import type { Express, Request, Response } from 'express';
import { z } from 'zod';
import { and, desc, eq, gte, inArray, sql } from 'drizzle-orm';
import { decode } from 'bolt11';
import * as schema from '../schema';
import { db } from '../db';
import { nostrAuth, moneyAuth, NostrAuthRequest } from '../middleware/auth';
import { checkLnbitsInvoicePaid, checkValidLnurl, createLnbitsInvoice } from '../lnbits';
import { paymentHashFromBolt11 } from '../nwc';
import { bolt11AmountMsat } from '../lib/lnurl';
import { custodialBountiesEnabled } from '../security';
import { claimStatusApproving, claimStatusPending } from '../types/claim.types';
import { CreateBountySchema, FilterBountiesSchema, ClaimBountySchema } from '../schemas';
import {
    UUID_RE,
    REPO_SLUG_RE,
    isUniqueViolation,
    PUBLIC_BOUNTY_COLUMNS,
    PUBLIC_CLAIM_COLUMNS,
    sendZodValidationError,
    devErrorMessage,
} from '../lib/http';
import { lnbitsLimiter } from '../lib/rate-limit';
import { config } from '../config';

/**
 * Non-payout bounty routes: create, public listing/filter, custodial paid-status
 * checks, LNURL limits, claim filing, and pending-claim lookup. The payout state
 * machines live in `routes/approve.ts` and `routes/deactivate.ts`.
 */
export function registerBountyRoutes(app: Express) {
    app.post('/bounties', moneyAuth, async (req: NostrAuthRequest, res: Response) => {
        try {
            const input = CreateBountySchema.parse(req.body);

            // Use the authenticated pubkey as creatorId — prevents impersonation
            const creatorId = req.nostrPubkey!;

            // NWC (non-custodial) is the default and, unless an operator flips
            // ALLOW_CUSTODIAL_BOUNTIES on, the only allowed funding mode. The
            // custodial path holds creator funds in our LNbits wallets, which we
            // aren't deploying right now.
            const allowCustodial = custodialBountiesEnabled();
            const fundingMode = input.fundingMode ?? (allowCustodial ? 'custodial' : 'nwc');
            if (fundingMode === 'custodial' && !allowCustodial) {
                return res.status(400).json({
                    error: 'Custodial bounties are currently disabled. Connect a Lightning wallet (NWC) to create a bounty.',
                });
            }
            let invoiceForDb: string | null = (input.frontEndInvoice as string | undefined) ?? null;
            let paymentHashForDb: string | null = (input.frontEndPaymentHash as string | undefined) ?? null;
            const memo = input.memo || `Bounty for test ${input.testId}`;

            if (fundingMode === 'nwc') {
                // Non-custodial path: the creator's own wallet will fund the
                // payout on approval. Require them to have connected an NWC URI
                // first — otherwise the /approve handler would fail later with
                // nothing useful to tell them.
                const user = await db.query.users.findFirst({
                    where: eq(schema.users.nostrPubkey, creatorId),
                    columns: { encryptedNwcUri: true },
                });
                if (!user?.encryptedNwcUri) {
                    return res.status(400).json({
                        error: 'Connect a Lightning wallet (NWC) before creating a non-custodial bounty',
                    });
                }
                // Skip LNbits entirely: no invoice, no payment hash. The bounty is
                // considered "funded" from the system's POV — there's nothing for
                // the creator to pay up front.
                invoiceForDb = null;
                paymentHashForDb = null;
            } else {
                const lnbitsUrl = config.lnbits.url;
                const apiKey = config.lnbits.invoiceKey;

                if (!lnbitsUrl || !apiKey) {
                    return res.status(500).json({ error: 'An unknown error occured.' });
                }

                if (!input.frontEndInvoice && !input.frontEndPaymentHash) {
                    const { payment_request: invoice, payment_hash } = await createLnbitsInvoice(
                        lnbitsUrl,
                        apiKey,
                        input.amountSats,
                        memo
                    );
                    invoiceForDb = invoice;
                    paymentHashForDb = payment_hash;
                } else {
                    // A client-supplied invoice/hash pair was previously stored
                    // verbatim: the schema checked that the invoice decoded and the
                    // hash was 64 hex, but never that they described each other or
                    // that the invoice asked for `amountSats`. That left the
                    // funded-vs-claimable accounting resting on the unique
                    // constraint on `payment_hash` rather than on validation.
                    //
                    // Verify both properties before persisting. (The stronger fix
                    // is to stop accepting these fields at all and always mint
                    // server-side — the client has no legitimate need to choose the
                    // invoice — but that's a client-contract change.)
                    if (input.frontEndInvoice) {
                        const decoded = decode(input.frontEndInvoice);
                        const invoiceMsat = bolt11AmountMsat(decoded);
                        if (!Number.isFinite(invoiceMsat) || invoiceMsat !== input.amountSats * 1000) {
                            return res.status(400).json({
                                error: 'frontEndInvoice amount does not match amountSats',
                            });
                        }
                        const derivedHash = paymentHashFromBolt11(input.frontEndInvoice);
                        if (!derivedHash) {
                            return res.status(400).json({
                                error: 'frontEndInvoice has no decodable payment hash',
                            });
                        }
                        if (
                            input.frontEndPaymentHash &&
                            derivedHash.toLowerCase() !== input.frontEndPaymentHash.toLowerCase()
                        ) {
                            return res.status(400).json({
                                error: 'frontEndPaymentHash does not match frontEndInvoice',
                            });
                        }
                        // Pin the hash to the one the invoice actually carries.
                        paymentHashForDb = derivedHash;
                    } else {
                        // A hash with no invoice can never be funded or displayed —
                        // and `update-paid` would poll a hash we can't tie to any
                        // invoice we issued. Reject rather than store a dead row.
                        return res.status(400).json({
                            error: 'frontEndPaymentHash requires the matching frontEndInvoice',
                        });
                    }
                }
            }

            // Deactivate any existing unpaid active bounties for the same test+creator.
            // Paid bounties are left alone — sats are committed and must be claimed.
            const existing = await db.query.bounties.findMany({
                where: and(
                    eq(schema.bounties.testId, input.testId),
                    eq(schema.bounties.creatorId, creatorId),
                    eq(schema.bounties.active, true),
                    eq(schema.bounties.invoicePaid, false),
                ),
            });

            if (existing.length > 0) {
                await db.update(schema.bounties)
                    .set({ active: false, updatedAt: new Date() })
                    .where(and(
                        eq(schema.bounties.testId, input.testId),
                        eq(schema.bounties.creatorId, creatorId),
                        eq(schema.bounties.active, true),
                        eq(schema.bounties.invoicePaid, false),
                    ));
            }

            const [newBounty] = await db
                .insert(schema.bounties)
                .values({
                    testId: input.testId,
                    creatorId,
                    amountSats: input.amountSats,
                    fundingMode,
                    // NWC bounties have no invoice to fund up-front. Marking
                    // invoicePaid=true lets the rest of the system treat them as
                    // "funded and ready to claim" without a payment-status poll.
                    invoicePaid: fundingMode === 'nwc',
                    invoice: invoiceForDb,
                    paymentHash: paymentHashForDb,
                    memo: memo,
                    repo: input.repo ?? null,
                    active: true,
                })
                .returning();

            res.status(201).json(newBounty);
        } catch (error) {
            if (error instanceof z.ZodError) {
                return sendZodValidationError(res, error);
            }

            console.error('Error creating bounty:', error);
            res.status(500).json({
                error: 'Failed to create bounty',
                message: devErrorMessage(error, 'Internal server error', 'Unknown error'),
            });
        }
    });

    // Body schema for PATCH /bounties/:id/deactivate. `refundLnurl` is optional:
    // omit it to preserve the original "just deactivate" behavior; supply it to
    // refund the funded amount back to the creator before deactivating.

    // PATCH /bounties/:id/deactivate

    app.get('/bounties', async (req: Request, res: Response) => {
        try {
            const { testId, includeInactive, repo, limit = '20', offset = '0' } = req.query;

            const parsedLimit = Number(limit);
            const parsedOffset = Number(offset);

            if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 100) {
                return res.status(400).json({ error: 'Invalid limit' });
            }
            if (isNaN(parsedOffset) || parsedOffset < 0) {
                return res.status(400).json({ error: 'Invalid offset' });
            }

            // `repo` is REQUIRED, not optional. This endpoint is unauthenticated,
            // and without a scope it served the entire table to anyone — which is
            // both far more data than any client needs and the reconnaissance feed
            // for targeting claims. Requiring a scope doesn't authenticate the
            // caller (repo slugs are guessable), but it bounds a single response to
            // one repository the caller already had to name.
            if (typeof repo !== 'string' || !REPO_SLUG_RE.test(repo)) {
                return res.status(400).json({
                    error: 'A repo scope is required (expected owner/repo)',
                    code: 'REPO_REQUIRED',
                });
            }

            const bounties = await db.query.bounties.findMany({
                where: and(
                    // Only active bounties by default
                    includeInactive !== 'true' ? eq(schema.bounties.active, true) : undefined,
                    // Filter by testId if provided
                    testId && typeof testId === 'string' ? eq(schema.bounties.testId, testId) : undefined,
                    // Mandatory scope — see the check above.
                    eq(schema.bounties.repo, repo)
                ),
                columns: PUBLIC_BOUNTY_COLUMNS,
                orderBy: [desc(schema.bounties.createdAt)],
                limit: parsedLimit,
                offset: parsedOffset,
                with: {
                    claims: {
                        columns: PUBLIC_CLAIM_COLUMNS,
                        orderBy: [desc(schema.claims.claimedAt)],
                    },
                },
            });

            res.json({
                bounties
            });
        } catch (error) {
            console.error('Error fetching bounties:', error);
            res.status(500).json({ error: 'Failed to fetch bounties' });
        }
    });

    // POST /bounties/filter — precise per-workspace listing keyed by a batch of
    // local test IDs. Used by the extension after test discovery runs so it can
    // pull only bounties that match tests actually present in the current
    // workspace. Unauthenticated by design (runs before the user signs in with
    // Nostr) — the generalLimiter + bounded body keep this cheap to serve.
    //
    // Query: ?repo=<owner/repo> (REQUIRED) &includeInactive=true (optional)
    // Body:  { "testIds": ["foo/bar.test.ts::test name", ...] }

    app.post('/bounties/filter', async (req: Request, res: Response) => {
        try {
            const { includeInactive, repo } = req.query;

            // Required, same as GET /bounties — an unauthenticated listing must
            // never be able to run unscoped. A batch of 500 arbitrary testIds with
            // no repo scope was a cross-repository probe.
            if (typeof repo !== 'string' || !REPO_SLUG_RE.test(repo)) {
                return res.status(400).json({
                    error: 'A repo scope is required (expected owner/repo)',
                    code: 'REPO_REQUIRED',
                });
            }

            const { testIds } = FilterBountiesSchema.parse(req.body);

            // De-duplicate client-side for a tighter IN clause. Order is preserved
            // by insertion, which doesn't matter for the IN lookup anyway.
            const uniqueTestIds = Array.from(new Set(testIds));

            const bounties = await db.query.bounties.findMany({
                where: and(
                    includeInactive !== 'true' ? eq(schema.bounties.active, true) : undefined,
                    eq(schema.bounties.repo, repo),
                    inArray(schema.bounties.testId, uniqueTestIds),
                ),
                columns: PUBLIC_BOUNTY_COLUMNS,
                orderBy: [desc(schema.bounties.createdAt)],
                // Bounded by |uniqueTestIds| × history; cap it anyway to keep
                // response sizes sane when the same test has lots of paid bounties.
                limit: 500,
                with: {
                    claims: {
                        columns: PUBLIC_CLAIM_COLUMNS,
                        orderBy: [desc(schema.claims.claimedAt)],
                    },
                },
            });

            res.json({ bounties });
        } catch (error) {
            if (error instanceof z.ZodError) {
                return sendZodValidationError(res, error);
            }
            console.error('Error filtering bounties:', error);
            res.status(500).json({ error: 'Failed to filter bounties' });
        }
    });

    app.get('/bounties/:paymentHash/check-paid', nostrAuth, async (req: NostrAuthRequest, res) => {
        const paymentHash = req.params.paymentHash as string;

        // Validate paymentHash is a 64-char hex string before forwarding to LNbits
        const paymentHashStr = paymentHash as string;
        if (!/^[0-9a-f]{64}$/i.test(paymentHashStr)) {
            return res.status(400).json({ error: 'Invalid payment hash format' });
        }

        try {
            // This endpoint exists for the creator's own paid-status sync. Without
            // an ownership check it was a paid/unpaid oracle over every invoice the
            // Treasury wallet ever issued, for any authenticated keypair that
            // learned a hash. 404 for unknown AND unowned alike, so it doesn't
            // become an existence oracle instead.
            const bounty = await db.query.bounties.findFirst({
                where: eq(schema.bounties.paymentHash, paymentHashStr),
                columns: { creatorId: true },
            });
            if (!bounty || bounty.creatorId !== req.nostrPubkey) {
                return res.status(404).json({ error: 'Bounty not found' });
            }

            const lnbitsPaidData = await checkLnbitsInvoicePaid(paymentHashStr);
            res.status(200).json({ success: true, paid: lnbitsPaidData.paid });
        } catch (err) {
            res.status(500).json({ error: 'Failed to check invoice paid' });
        }
    });

    // POST /lnurl/limits — resolve an LNURL/LN-address and return its sendable
    // bounds (millisats) so the extension can pre-check, while the user is still in
    // the claim input box, that the bounty amount fits the destination wallet.
    // Side-effect-free (unlike /bounties/:id/claim, which creates a claim). Gated by
    // nostrAuth + lnbitsLimiter since it makes an outbound network call.
    app.post('/lnurl/limits', lnbitsLimiter, nostrAuth, async (req: NostrAuthRequest, res: Response) => {
        const { lnurl } = req.body;
        if (!lnurl || typeof lnurl !== 'string' || !lnurl.trim()) {
            return res.status(400).json({ error: 'Valid lnurl is required' });
        }
        try {
            const result = await checkValidLnurl(lnurl);
            return res.json({
                minSendable: result.minSendable,
                maxSendable: result.maxSendable,
            });
        } catch (err) {
            console.error('[lnurl/limits] resolve failed:', err);
            return res.status(400).json({ error: 'Invalid or unreachable LNURL' });
        }
    });

    // Body schema for POST /bounties/:id/claim. `lnurl` is capped like every other
    // free-text field on this API (`refundLnurl` 2048, `memo` 500, `testId` 500) —
    // it was previously validated by hand with no maximum, which let a ~1 MB value
    // through the 1024kb body limit straight into a `text` column.

    // POST /bounties/:id/claim
    app.post('/bounties/:id/claim', lnbitsLimiter, moneyAuth, async (req: NostrAuthRequest, res: Response) => {
        const { id } = req.params;

        if (!UUID_RE.test(id as string)) {
            return res.status(400).json({ error: 'Invalid bounty ID' });
        }

        // Use the authenticated Nostr pubkey as the user identifier. This is
        // persisted on the claim below — it is the only thing that lets a creator
        // (and an auditor, after the fact) tell one claimant from another.
        const userId = req.nostrPubkey;
        if (!userId) {
            return res.status(401).json({ error: 'User not authenticated' });
        }

        let input: z.infer<typeof ClaimBountySchema>;
        try {
            input = ClaimBountySchema.parse(req.body ?? {});
        } catch (error) {
            if (error instanceof z.ZodError) {
                return sendZodValidationError(res, error);
            }
            throw error;
        }
        const lnurl = input.lnurl;
        const lnurlPrivate = input.hideLnurl === true;

        try {
            const strId = id as string;

            let lnurlResult;
            try {
                lnurlResult = await checkValidLnurl(lnurl);
            } catch (err) {
                console.error('[claim] checkValidLnurl failed:', err);
                return res.status(400).json({
                    error: 'Invalid or unreachable LNURL',
                    message: devErrorMessage(err, 'Invalid or unreachable LNURL'),
                });
            }

            const bounty = await db.query.bounties.findFirst({
                where: eq(schema.bounties.id, strId),
            });

            if (!bounty || !bounty.invoicePaid) {
                return res.status(400).json({ error: 'Bounty not claimable' });
            }

            // A removed bounty must not accept new claims. `active=false` was
            // display-only until now — the lens hides those bounties, but the API
            // happily took a claim on one, which is how a refunded (or already
            // paid out) bounty could acquire a fresh claim to approve against.
            // Distinct message from the one above: "not claimable" reads as
            // "unfunded", which isn't what happened here.
            if (!bounty.active) {
                return res.status(400).json({
                    error: 'This bounty is no longer available — it was removed by its creator.',
                });
            }

            // LNURL min/max are in millisats (LUD-06); the bounty amount is in
            // sats. Compare in the same unit — the previous sats-vs-msat check let
            // out-of-range claims through and mislabeled msat values as "sats".
            const amountMsat = bounty.amountSats * 1000;
            if (amountMsat < lnurlResult.minSendable || amountMsat > lnurlResult.maxSendable) {
                const minSats = Math.ceil(lnurlResult.minSendable / 1000);
                const maxSats = Math.floor(lnurlResult.maxSendable / 1000);
                return res.status(400).json({
                    error: `Bounty amount (${bounty.amountSats} sats) is outside this LNURL's range (${minSats}–${maxSats} sats).`,
                });
            }

            // One claim per identity per bounty. Stacking claims is what let a
            // later claimant displace an earlier one as "newest" and become the
            // payout destination, so a repeat claim from the same key returns the
            // existing row instead of minting a fresher one. The partial unique
            // index on (bounty_id, claimant_pubkey) enforces this even if two
            // requests race past this read.
            //
            // This runs BEFORE the anti-stuffing bounds below: someone who already
            // holds a claim isn't adding load, and answering them with a rate-limit
            // error instead of their own claimId would be both wrong and confusing.
            const existingClaim = await db.query.claims.findFirst({
                where: and(
                    eq(schema.claims.bountyId, strId),
                    eq(schema.claims.claimantPubkey, userId),
                ),
            });
            if (existingClaim) {
                return res.status(409).json({
                    error: 'You have already claimed this bounty',
                    code: 'CLAIM_ALREADY_FILED',
                    claimId: existingClaim.id,
                });
            }

            // --- Anti-stuffing bounds -------------------------------------------
            // Nostr keypairs are free, so any per-bounty quota can be filled by a
            // Sybil. That makes the *shape* of the bound the security decision, not
            // its size: a low hard ceiling let an attacker spend 25 requests once
            // and permanently lock the genuine contributor out of claiming — which
            // denies the bounty its whole purpose. These two bounds are chosen so
            // the degraded state is "noisy picker" rather than "unclaimable":
            //
            //   • A rolling window is the real control. It makes stuffing slow and
            //     conspicuous instead of a single burst, and it drains, so any lull
            //     lets a legitimate claimant straight in.
            //   • The absolute ceiling is only a storage backstop, set far above
            //     anything a real bounty sees.
            //
            // Noise is survivable now that hijacking isn't: the approve picker
            // sorts by git evidence, so junk claims with no trailer commit sort
            // last and read as "no commit found in this repo".
            const CLAIM_WINDOW_MS = 60 * 60 * 1000;
            const MAX_CLAIMS_PER_WINDOW = 10;
            const MAX_OPEN_CLAIMS_PER_BOUNTY = 200;

            const [recentRows, openRows] = await Promise.all([
                db.select({ n: sql<number>`count(*)::int` })
                    .from(schema.claims)
                    .where(and(
                        eq(schema.claims.bountyId, strId),
                        gte(schema.claims.claimedAt, new Date(Date.now() - CLAIM_WINDOW_MS)),
                    )),
                db.select({ n: sql<number>`count(*)::int` })
                    .from(schema.claims)
                    .where(and(
                        eq(schema.claims.bountyId, strId),
                        inArray(schema.claims.status, [claimStatusPending, claimStatusApproving]),
                    )),
            ]);

            if (Number(recentRows?.[0]?.n ?? 0) >= MAX_CLAIMS_PER_WINDOW) {
                // Explicitly temporary — a claimant who reads this should know to
                // come back, not that the bounty is closed to them.
                return res.status(429).json({
                    error:
                        'This bounty has received a lot of claims in the last hour. ' +
                        'Please try again shortly.',
                    code: 'CLAIM_RATE_LIMITED',
                    retryAfterSeconds: Math.ceil(CLAIM_WINDOW_MS / 1000),
                });
            }

            if (Number(openRows?.[0]?.n ?? 0) >= MAX_OPEN_CLAIMS_PER_BOUNTY) {
                return res.status(429).json({
                    error: 'This bounty has too many open claims',
                    code: 'TOO_MANY_CLAIMS',
                });
            }

            // Insert the claim with status='pending' set explicitly. The frontend
            // reads `claims[0].status` to decide whether the bounty has been
            // claimed; that comes from the row we insert here.
            let newClaim;
            try {
                const inserted = await db.insert(schema.claims).values({
                    bountyId: strId,
                    claimantLnurl: lnurl,
                    claimantPubkey: userId,
                    lnurlPrivate,
                    status: claimStatusPending,
                }).returning();
                newClaim = inserted[0];
            } catch (insertErr) {
                // Lost the race to a concurrent claim from this same key — the
                // unique index rejected the duplicate. Same benign answer as the
                // fast-path check above rather than a 500.
                if (isUniqueViolation(insertErr)) {
                    return res.status(409).json({
                        error: 'You have already claimed this bounty',
                        code: 'CLAIM_ALREADY_FILED',
                    });
                }
                throw insertErr;
            }

            // Frontend expects a single claim object at the top level (it types
            // the response as ClaimInfo). Returning the array directly used to
            // mean `claim.status` was always undefined client-side, so the local
            // cache silently failed to flip to "Claim Pending".
            res.json(newClaim);
        } catch (err) {
            // Without this log, every claim 500 was a black box — the response
            // body just says "Claim failed" with no detail.
            console.error('[POST /bounties/:id/claim] Error:', err);
            res.status(500).json({ error: 'Claim failed' });
        }
    });

    app.get('/bounties/:id/pending-claim', nostrAuth, async (req: NostrAuthRequest, res: Response) => {
        const { id } = req.params;
        const strId = id as string;
        if (!UUID_RE.test(strId)) {
            return res.status(400).json({ error: 'Invalid bounty ID' });
        }
        try {
            const bounty = await db.query.bounties.findFirst({
                where: eq(schema.bounties.id, strId),
                columns: { creatorId: true, amountSats: true },
            });
            if (!bounty) return res.status(404).json({ error: 'Bounty not found' });
            if (bounty.creatorId !== req.nostrPubkey) {
                return res.status(403).json({ error: 'Forbidden: you do not own this bounty' });
            }
            // `approving` is included deliberately. A claim whose payout outcome
            // was never confirmed stays locked, and the only way the creator can
            // resolve it from the UI is to hit /approve again (which reconciles
            // against the wallet rather than paying blind). If this endpoint 404s
            // for those claims, the client bails before it can ever get there and
            // the claim is stuck until an operator intervenes. The `status` field
            // below tells the client which case it's looking at.
            // EVERY open claim is returned, not just the newest. Returning only the
            // most recent meant the server silently chose the payout recipient, and
            // "most recent" is attacker-controlled: anyone could file a later claim
            // and become the destination the creator approved. The creator vets a
            // contributor out-of-band, so only they can say which claim corresponds
            // to the work they reviewed — this endpoint gives them the whole set to
            // choose from, keyed by claimant identity.
            const claims = await db.query.claims.findMany({
                where: and(
                    eq(schema.claims.bountyId, strId),
                    inArray(schema.claims.status, [claimStatusPending, claimStatusApproving]),
                ),
                orderBy: [desc(schema.claims.claimedAt)],
                // Bounded: the per-bounty open-claim cap
                // (MAX_OPEN_CLAIMS_PER_BOUNTY, 200) makes this mostly moot, but
                // legacy rows predate it — never ship an unbounded list to the client.
                limit: 100,
                columns: {
                    id: true,
                    claimantLnurl: true,
                    lnurlPrivate: true,
                    claimedAt: true,
                    status: true,
                    claimantPubkey: true,
                },
            });
            if (claims.length === 0) return res.status(404).json({ error: 'No pending claim on this bounty' });

            // When the claimant opted into privacy, never disclose the actual
            // payout destination to the creator — redact it here (server-side) so
            // it doesn't even reach the creator's client. The payout still routes
            // to the pinned `claimantLnurl` in the approve handler.
            //
            // `claimantPubkey` is deliberately NOT redacted by that flag. Hiding a
            // payout *address* is a reasonable privacy choice; hiding *who is being
            // paid* from the person paying is not — and it was precisely what made
            // a substituted claim invisible at the confirmation dialog.
            const view = claims.map(({ lnurlPrivate, claimantLnurl, ...rest }) => ({
                ...rest,
                claimantLnurl: lnurlPrivate ? null : claimantLnurl,
                lnurlHidden: lnurlPrivate,
            }));

            // The newest claim is also spread at the top level so extensions built
            // against the previous single-claim shape keep parsing this response.
            // Those clients can't render a chooser, but they can't be tricked into
            // a silent payout either: /approve refuses to pay when more than one
            // claim is open unless the caller names the claimant it intends to pay,
            // which old clients never do. They fail closed with a clear message.
            return res.json({ ...view[0], claims: view });
        } catch (err) {
            console.error('[GET /pending-claim] Error:', err);
            return res.status(500).json({ error: 'Failed to retrieve pending claim' });
        }
    });

    // POST /bounties/:id/approve

    app.patch('/bounties/:id/update-paid', lnbitsLimiter, moneyAuth, async (req: NostrAuthRequest, res) => {
        const { id } = req.params;
        const strId = id as string;

        if (!UUID_RE.test(strId)) {
            return res.status(400).json({ error: 'Invalid bounty ID' });
        }

        try {
            const bounty = await db.query.bounties.findFirst({
                where: eq(schema.bounties.id, strId),
            });

            if (!bounty) {
                return res.status(404).json({ error: 'Bounty not found' });
            }

            // Every other bounty-scoped handler gates on ownership; this one did
            // not, which let any authenticated key force a paid-status refresh on a
            // stranger's bounty (and spend our LNbits rate budget doing it).
            if (bounty.creatorId !== req.nostrPubkey) {
                return res.status(403).json({ error: 'Forbidden: you do not own this bounty' });
            }

            // NWC bounties have no LNbits invoice to poll — they're funded on the
            // creator's side at approval time. There's nothing to update here.
            if (!bounty.paymentHash) {
                return res.status(400).json({ error: 'Bounty has no invoice to check (non-custodial)' });
            }

            const lnbitsPaidData = await checkLnbitsInvoicePaid(bounty.paymentHash);

            if (lnbitsPaidData.paid === bounty.invoicePaid) {
                // Paid status already matches LNbits — nothing to persist. The client
                // polls this route, so a benign "no change" must not read as a server
                // error. Return success with `updated: false` instead of a 500.
                return res.status(200).json({ success: true, updated: false });
            }

            const finalPaidStatus = !!lnbitsPaidData.paid;
            await db.update(schema.bounties)
                .set({ invoicePaid: finalPaidStatus, updatedAt: new Date() })
                .where(eq(schema.bounties.id, strId));

            res.status(200).json({ success: true });
        } catch (err) {
            console.error('update-paid error:', err);
            res.status(500).json({ error: 'Failed to update invoice paid fields' });
        }
    });

}
