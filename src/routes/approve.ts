import type { Express, Response } from 'express';
import { z } from 'zod';
import { and, eq, inArray } from 'drizzle-orm';
import * as schema from '../schema';
import { db } from '../db';
import { moneyAuth, NostrAuthRequest } from '../middleware/auth';
import { createLnbitsPayout, LnbitsPayoutError, lookupLnbitsPayment } from '../lnbits';
import {
    createNwcPayout,
    NwcPayoutError,
    lookupInvoiceFromLnurl,
    paymentHashFromBolt11,
    walletPubkeyFromNwcUri,
} from '../nwc';
import { decrypt } from '../crypto';
import { alertAnomaly, payoutsEnabled } from '../security';
import { runPayoutGuards } from '../services/payout-guards';
import { claimStatusApproved, claimStatusApproving, claimStatusPending } from '../types/claim.types';
import { ApproveClaimSchema } from '../schemas';
import { UUID_RE, sendZodValidationError, devErrorMessage } from '../lib/http';
import { lnbitsLimiter } from '../lib/rate-limit';
import { reconcileApprovingClaim } from '../services/reconcile';

/**
 * POST /bounties/:id/approve — release a bounty payout to a claimant. The core
 * payout state machine: claimant binding, the `approving` lock, reconciliation
 * of a prior unknown outcome, the payout guard stack, and the NWC-vs-custodial
 * payout. Extracted from index.ts; behavior is unchanged.
 */
export function registerApproveRoute(app: Express) {
    app.post('/bounties/:id/approve', lnbitsLimiter, moneyAuth, async (req: NostrAuthRequest, res: Response) => {
        const { id } = req.params;
        const strId = id as string;

        if (!UUID_RE.test(strId)) {
            return res.status(400).json({ error: 'Invalid bounty ID' });
        }

        // Use the authenticated pubkey as approvedBy — prevents spoofing
        const approvedBy = req.nostrPubkey!;

        // Require the caller to name the exact claim they intend to pay. This
        // prevents a front-running attack where an adversary submits a newer claim
        // between the creator's review and the approve click — if the IDs don't
        // match, the handler rejects rather than silently redirecting funds.
        let input: z.infer<typeof ApproveClaimSchema>;
        try {
            input = ApproveClaimSchema.parse(req.body ?? {});
        } catch (error) {
            if (error instanceof z.ZodError) {
                return sendZodValidationError(res, error);
            }
            throw error;
        }

        try {

            const bounty = await db.query.bounties.findFirst({
                where: eq(schema.bounties.id, strId),
            });

            // Verify requester owns the bounty before approving
            if (!bounty) {
                return res.status(404).json({ error: 'Bounty not found' });
            }

            if (bounty.creatorId !== approvedBy) {
                return res.status(403).json({ error: 'Forbidden: you do not own this bounty' });
            }

            const strMemo = bounty?.memo as string;

            // Fetch the specific claim the creator identified. Scoping by both
            // claimId AND bountyId ensures a claim from a different bounty can't
            // be supplied, even if the caller guesses a valid UUID.
            const claim = await db.query.claims.findFirst({
                where: and(
                    eq(schema.claims.id, input.claimId),
                    eq(schema.claims.bountyId, strId),
                ),
            });

            if (!claim) {
                return res.status(404).json({ error: 'Claim not found for this bounty' });
            }

            // --- Claimant binding (anti-hijack) ---------------------------------
            // `claimId` binds the payout to a specific row, which stops a claim
            // swapped in between the creator's review and their click. It does NOT
            // stop an attacker who simply files a claim and becomes the one the
            // creator's client fetched in the first place — the client reads that
            // id from /pending-claim, and the server used to hand back whichever
            // claim was newest.
            //
            // So: when more than one claim is open, the caller must say *who* it
            // means to pay. A creator identifies their contributor out-of-band, and
            // only they can make that call. A client that doesn't name a claimant
            // is refused rather than paid blind — including older extensions, which
            // never send the field and therefore fail closed here.
            const openClaims = await db.query.claims.findMany({
                where: and(
                    eq(schema.claims.bountyId, strId),
                    inArray(schema.claims.status, [claimStatusPending, claimStatusApproving]),
                ),
                columns: { id: true, claimantPubkey: true },
            });

            if (openClaims.length > 1 && !input.claimantPubkey) {
                return res.status(409).json({
                    error:
                        `This bounty has ${openClaims.length} open claims, so Sattest can't tell which ` +
                        'one you mean to pay. Update the Sattest extension to choose the claimant ' +
                        'explicitly before approving.',
                    code: 'MULTIPLE_OPEN_CLAIMS',
                    openClaimCount: openClaims.length,
                });
            }

            if (input.claimantPubkey) {
                if (!claim.claimantPubkey) {
                    // Legacy row with no recorded identity — we cannot prove it
                    // belongs to the person the creator named, so we don't pay it
                    // on the strength of a claim we can't verify.
                    return res.status(409).json({
                        error:
                            'This claim predates claimant identity recording and cannot be matched to ' +
                            'the claimant you selected. Ask the claimant to re-file their claim.',
                        code: 'CLAIMANT_UNVERIFIABLE',
                    });
                }
                if (claim.claimantPubkey !== input.claimantPubkey) {
                    // The row moved under the creator between review and approve.
                    return res.status(409).json({
                        error:
                            'The claimant on this claim is not the one you selected. Re-open the claim ' +
                            'list and confirm who you intend to pay.',
                        code: 'CLAIMANT_MISMATCH',
                    });
                }
            }

            // A duplicate/concurrent approve (double-click, second VS Code window,
            // replayed request) lands here after the first already moved the claim
            // out of `pending`. This isn't a real failure for the caller — the
            // payout already happened or is happening — so send a machine-readable
            // `code` the client can treat as benign instead of popping a scary
            // "Failed to approve" toast next to the success one.
            if (claim.status === claimStatusApproved) {
                return res.status(409).json({
                    error: 'Claim already approved',
                    code: 'CLAIM_ALREADY_APPROVED',
                    payoutTxid: claim.payoutTxid ?? undefined,
                });
            }

            let claimStatus = claim.status;

            if (claimStatus === claimStatusApproving) {
                // The claim is locked by an earlier attempt. That attempt may have
                // ended in a reply timeout, in which case nobody knows whether the
                // wallet paid — ask it before doing anything else. Without this the
                // creator is stuck: the lens shows "Payout Processing" forever and
                // only manual SQL clears it.
                const reconciled = await reconcileApprovingClaim(bounty, claim);

                if (reconciled.resolution === 'settled') {
                    return res.status(409).json({
                        error: 'Claim already approved',
                        code: 'CLAIM_ALREADY_APPROVED',
                        payoutTxid: reconciled.payoutTxid,
                    });
                }
                if (reconciled.resolution === 'still-locked') {
                    return res.status(409).json({
                        error: reconciled.detail,
                        code: 'CLAIM_IN_PROGRESS',
                    });
                }
                if (reconciled.resolution === 'needs-confirmation') {
                    // No wallet can answer for this attempt — retrying the
                    // lookup will never resolve it. Distinct code so the client
                    // offers the confirmation flow instead of looping.
                    return res.status(409).json({
                        error: reconciled.detail,
                        code: 'PAYOUT_NEEDS_CONFIRMATION',
                    });
                }
                // 'released' — the wallet confirmed the earlier attempt didn't pay,
                // so the claim is back to `pending` and this request continues as a
                // normal approve below.
                claimStatus = claimStatusPending;
            }

            if (claimStatus !== claimStatusPending) {
                return res.status(409).json({
                    error: 'Claim is already being approved',
                    code: 'CLAIM_IN_PROGRESS',
                });
            }

            // An inactive bounty can never originate a NEW payout. Removal, a
            // refund, and a successful approve all set `active=false`, and in every
            // one of those cases the money is either already spent or has gone back
            // to the creator — paying again would be a second spend of the same
            // bounty (a refunded custodial bounty paid out anyway; a bounty paid to
            // claimant A also paid to claimant B).
            //
            // Placement matters: this sits AFTER the already-approved and
            // mid-approval branches above, because a successful approve sets
            // `active=false` itself. Checking earlier would turn every benign
            // duplicate approve into a hard error, and would make a claim held
            // after an unconfirmed payout impossible to reconcile.
            if (!bounty.active) {
                return res.status(400).json({
                    error:
                        'This bounty is no longer active (removed, refunded, or already ' +
                        'paid out) and cannot be paid out.',
                });
            }

            // --- Kill switch (fast path) ----------------------------------------
            // Checked here, before we mint an invoice against the claimant's LNURL
            // server, so a paused service fails immediately and cheaply. The full
            // guard stack (including this again) runs below, after the lock.
            if (!payoutsEnabled()) {
                return res.status(503).json({
                    error: 'Payouts are temporarily disabled (kill switch)',
                });
            }

            // --- LNURL pinning (Layer 4) ---------------------------------------
            // The payout destination is read from the DB (`claim.claimantLnurl`) —
            // set by the claimant at /claim time and never overridable from the
            // approve request body. A stolen/forged approve event therefore cannot
            // redirect funds to an attacker-controlled LNURL.

            // Resolve everything that can fail *before* taking the lock so a
            // validation failure never leaves the claim in the `approving` state.
            // For NWC: confirm the creator's wallet is connected and mint the
            // claimant's invoice up front.
            let nwcBolt11: string | undefined;
            let nwcEncryptedUri: string | undefined;
            let nwcPaymentHash: string | undefined;
            let nwcWalletPubkey: string | undefined;
            if (bounty.fundingMode === 'nwc') {
                const creator = await db.query.users.findFirst({
                    where: eq(schema.users.nostrPubkey, bounty.creatorId),
                    columns: { encryptedNwcUri: true },
                });
                if (!creator?.encryptedNwcUri) {
                    return res.status(400).json({
                        error: 'NWC wallet not connected for this bounty\'s creator',
                    });
                }
                nwcEncryptedUri = creator.encryptedNwcUri;
                try {
                    nwcBolt11 = await lookupInvoiceFromLnurl(
                        claim.claimantLnurl,
                        bounty.amountSats * 1000,
                        `bounty:${strId}`,
                    );
                } catch (err) {
                    return res.status(400).json({
                        error: err instanceof Error ? err.message : 'LNURL lookup failed',
                    });
                }
                // Recorded with the lock below so a payout whose reply we never
                // receive can still be reconciled against the wallet — including
                // *which* wallet, since only that one can say what happened.
                nwcPaymentHash = paymentHashFromBolt11(nwcBolt11);
                try {
                    nwcWalletPubkey = walletPubkeyFromNwcUri(decrypt(nwcEncryptedUri));
                } catch {
                    // Leave undefined: reconciliation treats an unknown wallet
                    // identity as "ask the creator" rather than guessing.
                    nwcWalletPubkey = undefined;
                }
            }

            // --- Atomic payout lock (anti-double-spend) ------------------------
            // Flip this specific claim `pending → approving`. The WHERE clause
            // makes it a single-winner transition: a concurrent approve, a
            // double-click, or a replayed auth event will update zero rows and bail
            // here, so the payout below can only ever fire once.
            // The payout bookkeeping is written in this same conditional UPDATE, so
            // a locked claim always carries the reference needed to reconcile it —
            // there is no window where the lock exists without it.
            const locked = await db.update(schema.claims)
                .set({
                    status: claimStatusApproving,
                    approvingAt: new Date(),
                    payoutPaymentHash: nwcPaymentHash ?? null,
                    payoutBolt11: nwcBolt11 ?? null,
                    payoutWalletPubkey: nwcWalletPubkey ?? null,
                    // A fresh attempt supersedes any earlier manual assertion.
                    payoutResolution: null,
                })
                .where(and(
                    eq(schema.claims.id, claim.id),
                    eq(schema.claims.status, claimStatusPending),
                ))
                .returning({ id: schema.claims.id });

            if (locked.length === 0) {
                // Lost the race to a concurrent approve that grabbed the lock between
                // our status read above and here. Same benign, machine-readable
                // signal so the loser doesn't show a failure toast.
                return res.status(409).json({
                    error: 'This claim is already being approved',
                    code: 'CLAIM_IN_PROGRESS',
                });
            }

            // Revert the lock so the creator can retry after a payout failure.
            //
            // ONLY call this when the payout definitively did not happen. If the
            // outcome is unknown (see NwcPayoutError.outcome), the claim must stay
            // locked: a retry mints a fresh invoice with a new payment hash, so
            // unlocking a payment that actually settled pays the claimant twice.
            const releaseClaimLock = async () => {
                try {
                    await db.update(schema.claims)
                        .set({
                            status: claimStatusPending,
                            payoutPaymentHash: null,
                            payoutBolt11: null,
                            payoutWalletPubkey: null,
                            approvingAt: null,
                        })
                        .where(and(
                            eq(schema.claims.id, claim.id),
                            eq(schema.claims.status, claimStatusApproving),
                        ));
                } catch (releaseErr) {
                    console.error('[approve] failed to release claim lock:', releaseErr);
                }
            };

            // --- Refund race guard ------------------------------------------------
            // The claim lock serialises approve-vs-approve, but not approve-vs-refund:
            // the bounty row was read before the lock was taken, so a refund that
            // started in between would pay the creator back while this approve pays
            // the claimant — the same bounty spent twice. Now that we hold the lock,
            // re-read the refund markers: whichever operation took its lock second
            // sees the other's marker and bails (the refund side re-reads claim
            // state after taking its own lock, so both orderings are covered).
            const bountyNow = await db.query.bounties.findFirst({
                where: eq(schema.bounties.id, strId),
                columns: { refundAt: true, refundCheckingId: true },
            });
            if (bountyNow?.refundAt || bountyNow?.refundCheckingId) {
                await releaseClaimLock();
                return res.status(409).json({
                    error: 'This bounty is being refunded and cannot be paid out.',
                    code: 'REFUND_IN_PROGRESS',
                });
            }

            // --- Payout guards --------------------------------------------------
            // These run AFTER the lock, not before it. The cumulative caps are a
            // check-then-act: evaluating them before the lock meant N concurrent
            // approvals on N different bounties each read the same pre-payout total
            // and each concluded they fit, so the hourly ceiling could be overshot
            // by roughly the concurrency. Now every approval publishes its intent
            // (an `approving` row, which `sumApprovedWithin` counts) before any
            // total is read, so concurrent approvals see each other and serialise.
            // Two racers may now both back off where one would have sufficed —
            // fail-closed is the correct direction for a circuit breaker.
            //
            // Every failure path below releases the lock, so a tripped guard still
            // leaves the claim `pending` for an operator, exactly as before.

            const guard = await runPayoutGuards({
                amountSats: bounty.amountSats,
                kind: 'payout',
                // Only a custodial payout draws on our LNbits payout wallet; an
                // NWC payout comes straight from the creator's own.
                checkBalance: bounty.fundingMode !== 'nwc',
                context: { bountyId: strId, claimId: claim.id, approvedBy },
            });
            if (!guard.ok) {
                await releaseClaimLock();
                return res.status(guard.status).json({ error: guard.error });
            }

            // Flipped the instant a payout returns successfully. After that point
            // money has left the creator's wallet, so the lock must never be
            // released — a failure in the bookkeeping below is an operator problem,
            // not a reason to let someone pay again.
            let payoutSent = false;

            try {
                let payoutTxid: string;

                if (bounty.fundingMode === 'nwc') {
                    try {
                        const { preimage } = await createNwcPayout(
                            nwcEncryptedUri as string,
                            nwcBolt11 as string,
                            bounty.amountSats,
                        );
                        payoutTxid = preimage;
                    } catch (err) {
                        if (err instanceof NwcPayoutError) {
                            if (err.outcome === 'failed') {
                                // Proven not paid (never published, or the wallet
                                // declined) — unlock so the creator can retry.
                                await releaseClaimLock();
                                return res.status(502).json({ error: err.message });
                            }
                            // Unknown: the request went out but we never got a
                            // usable answer. The wallet may have paid. Keep the
                            // lock — the next approve (or the startup sweep) will
                            // ask the wallet what happened via lookup_invoice.
                            console.error(
                                `[approve] payout outcome unknown for claim ${claim.id} ` +
                                `(paymentHash=${nwcPaymentHash ?? 'none'}): ${err.message}`,
                            );
                            await alertAnomaly({
                                bountyId: strId,
                                claimId: claim.id,
                                amountSats: bounty.amountSats,
                                approvedBy,
                                reason: `Payout outcome unknown, claim left locked: ${err.message}`,
                            });
                            return res.status(502).json({
                                error:
                                    'Sattest could not confirm this payout with your wallet. ' +
                                    'It may have been sent. The claim is on hold and will be ' +
                                    'checked automatically — do not resend from your wallet.',
                                code: 'PAYOUT_OUTCOME_UNKNOWN',
                            });
                        }
                        throw err;
                    }
                } else {
                    try {
                        const payoutResult = await createLnbitsPayout(
                            claim.claimantLnurl,
                            bounty.amountSats,
                            strMemo,
                            '',
                        );
                        payoutTxid = payoutResult.checking_id;
                    } catch (err) {
                        if (err instanceof LnbitsPayoutError) {
                            // Same discipline as the NWC branch: a throw from the
                            // pay step means the outcome is unknown (timeout after
                            // commit, unreadable success body, …). Reconcile
                            // against the payout wallet by payment hash before
                            // deciding whether a retry is safe.
                            const state = err.paymentHash
                                ? await lookupLnbitsPayment(err.paymentHash)
                                : 'unknown';
                            if (state === 'not-found') {
                                // LNbits proves no payment exists — release so the
                                // creator can safely retry.
                                await releaseClaimLock();
                                return res.status(502).json({ error: err.message });
                            }
                            // 'paid' or 'unknown': money may have moved. Keep the
                            // lock — never retry blind and pay the claimant twice.
                            console.error(
                                `[approve] custodial payout outcome unknown for claim ${claim.id} ` +
                                `(paymentHash=${err.paymentHash ?? 'none'}): ${err.message}`,
                            );
                            await alertAnomaly({
                                bountyId: strId,
                                claimId: claim.id,
                                amountSats: bounty.amountSats,
                                approvedBy,
                                reason: `Custodial payout outcome unknown, claim left locked: ${err.message}`,
                            });
                            return res.status(502).json({
                                error:
                                    'Sattest could not confirm this payout with LNbits. ' +
                                    'It may have been sent. The claim is on hold so it ' +
                                    'cannot be paid twice — reconcile it against the payout ' +
                                    'wallet before retrying.',
                                code: 'PAYOUT_OUTCOME_UNKNOWN',
                            });
                        }
                        throw err;
                    }
                }

                payoutSent = true;

                // Money has moved — finalize. Mark the bounty inactive and advance
                // the locked claim `approving → approved`.
                await db.update(schema.bounties)
                    .set({ active: false })
                    .where(eq(schema.bounties.id, strId));

                await db.update(schema.claims)
                    .set({
                        status: claimStatusApproved,
                        payoutTxid,
                        approvedBy,
                        approvedAt: new Date(),
                    })
                    .where(eq(schema.claims.id, claim.id));

                // Audit trail for the money path. Both counterparties are named:
                // without the claimant, a payout to the wrong person leaves nothing
                // to investigate or ban. The LNURL is deliberately omitted — it's a
                // payout destination (and sometimes an email-shaped address), and
                // the pubkey is the field with actual audit value.
                console.log(
                    `[approve] paid bounty=${strId} claim=${claim.id} amount=${bounty.amountSats} ` +
                    `claimant=${claim.claimantPubkey ?? 'unknown-legacy'} approvedBy=${approvedBy}`,
                );

                res.json({ success: true, checking_id: payoutTxid });
            } catch (payoutErr) {
                if (payoutSent) {
                    // The sats already left; only the finalize step failed. Leave
                    // the claim locked so nobody can pay twice, and shout loudly —
                    // this row needs an operator, not a retry.
                    console.error(
                        `[approve] PAYOUT SENT BUT NOT RECORDED for claim ${claim.id} — ` +
                        'claim left locked, reconcile manually:',
                        payoutErr,
                    );
                    await alertAnomaly({
                        bountyId: strId,
                        claimId: claim.id,
                        amountSats: bounty.amountSats,
                        approvedBy,
                        reason: 'Payout sent but the claim could not be marked approved',
                    });
                } else {
                    // Payout threw before any money moved — release so it can be retried.
                    await releaseClaimLock();
                }
                throw payoutErr;
            }

        } catch (err) {
            console.error('Approve/payout failed:', err);
            res.status(500).json({
                error: 'Payout failed',
                message: devErrorMessage(err, 'Internal server error'),
            });
        }
    });

    registerResolveRoute(app);
}

/**
 * POST /bounties/:id/claims/:claimId/resolve — human tie-breaker for a claim
 * whose payout outcome no wallet can report.
 *
 * The automatic path (`reconcileApprovingClaim`) asks the wallet that made the
 * attempt. When that wallet is gone — revoked, replaced, permanently offline —
 * nothing can answer, and the claim would otherwise sit in `approving` forever.
 * This lets the creator, who can look at their own wallet history, assert what
 * happened.
 *
 * Deliberately narrow:
 *   - NWC only. A custodial payout leaves our LNbits wallet, so letting a
 *     creator assert its outcome would spend the house's money on their word;
 *     those are reconcilable server-side against LNbits instead.
 *   - The creator bears the consequence of asserting wrongly, which is the
 *     whole reason this is safe to expose: in NWC mode it is their wallet that
 *     pays twice if they say "not paid" about a payment that settled.
 *   - Every use is recorded (`payout_resolution`) and alerted, so a
 *     human-asserted outcome is never mistaken for a verified one.
 */
function registerResolveRoute(app: Express) {
    const ResolveSchema = z.object({
        outcome: z.enum(['paid', 'not-paid']),
    });

    app.post(
        '/bounties/:id/claims/:claimId/resolve',
        moneyAuth,
        async (req: NostrAuthRequest, res: Response) => {
            const strId = req.params.id as string;
            const strClaimId = req.params.claimId as string;

            if (!UUID_RE.test(strId) || !UUID_RE.test(strClaimId)) {
                return res.status(400).json({ error: 'Invalid bounty or claim ID' });
            }

            let input: z.infer<typeof ResolveSchema>;
            try {
                input = ResolveSchema.parse(req.body ?? {});
            } catch (error) {
                if (error instanceof z.ZodError) {
                    return sendZodValidationError(res, error);
                }
                throw error;
            }

            const callerPubkey = req.nostrPubkey!;

            try {
                const bounty = await db.query.bounties.findFirst({
                    where: eq(schema.bounties.id, strId),
                });
                if (!bounty) {
                    return res.status(404).json({ error: 'Bounty not found' });
                }
                if (bounty.creatorId !== callerPubkey) {
                    return res.status(403).json({ error: 'Forbidden: you do not own this bounty' });
                }
                if (bounty.fundingMode !== 'nwc') {
                    return res.status(400).json({
                        error:
                            'Only non-custodial (NWC) payouts can be resolved this way — a ' +
                            'custodial payout is reconciled against LNbits server-side.',
                    });
                }

                const claim = await db.query.claims.findFirst({
                    where: and(
                        eq(schema.claims.id, strClaimId),
                        eq(schema.claims.bountyId, strId),
                    ),
                });
                if (!claim) {
                    return res.status(404).json({ error: 'Claim not found for this bounty' });
                }
                if (claim.status === claimStatusApproved) {
                    return res.status(409).json({
                        error: 'Claim already approved',
                        code: 'CLAIM_ALREADY_APPROVED',
                        payoutTxid: claim.payoutTxid ?? undefined,
                    });
                }
                if (claim.status !== claimStatusApproving) {
                    // Nothing to resolve: only a held claim is ambiguous.
                    return res.status(409).json({
                        error: 'This claim is not awaiting confirmation',
                        code: 'CLAIM_NOT_HELD',
                    });
                }

                if (input.outcome === 'paid') {
                    // Finalize without inventing a preimage — `payout_txid` means
                    // "proof the payment settled", and we have no such proof.
                    // `payout_resolution` is what records how this was decided.
                    await db.update(schema.bounties)
                        .set({ active: false })
                        .where(eq(schema.bounties.id, strId));
                    const updated = await db.update(schema.claims)
                        .set({
                            status: claimStatusApproved,
                            approvedBy: callerPubkey,
                            approvedAt: new Date(),
                            payoutResolution: 'creator-confirmed-paid',
                        })
                        .where(and(
                            eq(schema.claims.id, claim.id),
                            eq(schema.claims.status, claimStatusApproving),
                        ))
                        .returning({ id: schema.claims.id });
                    if (updated.length === 0) {
                        // Something else resolved it first.
                        return res.status(409).json({
                            error: 'This claim was already resolved',
                            code: 'CLAIM_IN_PROGRESS',
                        });
                    }
                } else {
                    // Confirmed unpaid — unlock for a retry against whatever
                    // wallet is connected now, clearing the dead attempt's
                    // bookkeeping so it can't be mistaken for the live one.
                    const updated = await db.update(schema.claims)
                        .set({
                            status: claimStatusPending,
                            payoutPaymentHash: null,
                            payoutBolt11: null,
                            payoutWalletPubkey: null,
                            approvingAt: null,
                            payoutResolution: 'creator-confirmed-unpaid',
                        })
                        .where(and(
                            eq(schema.claims.id, claim.id),
                            eq(schema.claims.status, claimStatusApproving),
                        ))
                        .returning({ id: schema.claims.id });
                    if (updated.length === 0) {
                        return res.status(409).json({
                            error: 'This claim was already resolved',
                            code: 'CLAIM_IN_PROGRESS',
                        });
                    }
                }

                // A human asserting a payment outcome is exactly the kind of
                // event an operator should see, whichever way it went.
                await alertAnomaly({
                    bountyId: strId,
                    claimId: claim.id,
                    amountSats: bounty.amountSats,
                    approvedBy: callerPubkey,
                    reason: `Creator confirmed unverifiable payout as "${input.outcome}"`,
                });
                console.log(
                    `[resolve] claim ${claim.id} manually resolved as ${input.outcome} by creator`,
                );

                return res.status(200).json({ success: true, outcome: input.outcome });
            } catch (err) {
                console.error('[resolve] failed:', err);
                return res.status(500).json({
                    error: 'Failed to resolve claim',
                    message: devErrorMessage(err, 'Internal server error'),
                });
            }
        },
    );
}
