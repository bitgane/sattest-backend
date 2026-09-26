import type { Express } from 'express';
import { z } from 'zod';
import { and, eq, isNull } from 'drizzle-orm';
import * as schema from '../schema';
import { db } from '../db';
import { moneyAuth, NostrAuthRequest } from '../middleware/auth';
import {
    checkValidLnurl,
    createLnbitsPayout,
    LnbitsPayoutError,
    lookupLnbitsPayment,
    convertSatsToLnbitsParam,
} from '../lnbits';
import { alertAnomaly, payoutsEnabled } from '../security';
import { runPayoutGuards } from '../services/payout-guards';
import { claimStatusApproved, claimStatusApproving } from '../types/claim.types';
import { DeactivateBountySchema } from '../schemas';
import { UUID_RE, sendZodValidationError, devErrorMessage } from '../lib/http';

/**
 * PATCH /bounties/:id/deactivate — remove a bounty, optionally refunding the
 * creator via LNbits. A payout state machine: it takes an atomic refund lock,
 * runs the payout guard stack, and reconciles unknown outcomes. Extracted from
 * index.ts; behavior is unchanged.
 */
export function registerDeactivateRoute(app: Express) {
    app.patch('/bounties/:id/deactivate', moneyAuth, async (req: NostrAuthRequest, res) => {
        const { id } = req.params;
        const strId = id as string;

        if (!UUID_RE.test(strId)) {
            return res.status(400).json({ error: 'Invalid bounty ID' });
        }

        let input: z.infer<typeof DeactivateBountySchema>;
        try {
            // `req.body` may be undefined (no-body PATCH). Treat that as {} so the
            // unpaid/no-refund path still works with an empty-body request.
            input = DeactivateBountySchema.parse(req.body ?? {});
        } catch (error) {
            if (error instanceof z.ZodError) {
                return sendZodValidationError(res, error);
            }
            throw error;
        }

        try {
            // Verify the requester owns the bounty before deactivating.
            //
            // ALL claims are loaded, not just the most recent. Claims accumulate
            // per bounty and nothing stops a new one being filed while an older one
            // holds the payout lock (or after one was already paid), so "latest
            // claim" is not a safe proxy for "state of this bounty's money" — an
            // older `approving`/`approved` claim would hide behind a newer
            // `pending` one and slip past the guards below.
            const bounty = await db.query.bounties.findFirst({
                where: eq(schema.bounties.id, strId),
                with: {
                    claims: {
                        columns: { status: true },
                    },
                },
            });

            if (!bounty) {
                return res.status(404).json({ error: 'Bounty not found' });
            }

            if (bounty.creatorId !== req.nostrPubkey) {
                return res.status(403).json({ error: 'Forbidden: you do not own this bounty' });
            }

            const claimStatuses = (bounty.claims ?? []).map((c) => c.status);
            const hasApprovingClaim = claimStatuses.includes(claimStatusApproving);
            const hasApprovedClaim = claimStatuses.includes(claimStatusApproved);

            // -------------------------------------------------------------------
            // A payout is in flight (or its outcome was never confirmed) — the
            // bounty must not be removed by either path.
            //
            // For a custodial bounty this is a straight double-spend guard: the
            // refund path would send the custodied sats back to the creator while
            // the claimant payout is still settling, paying the same bounty twice.
            //
            // For NWC there are no custodied funds, but deactivating hides the
            // bounty from the code lens — which is the creator's only route to
            // reconcile a held claim — so the payout would be stranded with no way
            // to resolve it short of manual SQL.
            //
            // Either way the answer is the same: resolve the claim first. Approving
            // it again reconciles against the wallet, which will either finalize it
            // or release it, and then removal works normally.
            // -------------------------------------------------------------------
            if (hasApprovingClaim) {
                return res.status(409).json({
                    error:
                        'This bounty has a payout in progress. Approve the claim again to ' +
                        'confirm it with your wallet, then remove the bounty once it resolves.',
                    code: 'CLAIM_IN_PROGRESS',
                });
            }

            // -------------------------------------------------------------------
            // No-refund path: preserve original behavior exactly.
            // -------------------------------------------------------------------
            if (!input.refundLnurl) {
                const result = await db.update(schema.bounties)
                    .set({
                        active: false,
                        updatedAt: new Date(),
                    })
                    .where(eq(schema.bounties.id, strId))
                    .returning({ id: schema.bounties.id, active: schema.bounties.active });

                return res.status(200).json({
                    success: true,
                    message: 'Bounty deactivated (soft delete)',
                    bountyId: result[0].id,
                    active: result[0].active,
                });
            }

            // -------------------------------------------------------------------
            // Refund path: eligibility + guards + payout + atomic persist.
            // -------------------------------------------------------------------

            // Non-custodial (NWC) bounties never held funds on our side — they're
            // marked invoicePaid=true at creation but no sats were ever custodied
            // in the LNbits wallet. Issuing an LNbits payout here would pay real
            // sats out of the shared payout wallet for a bounty that never funded
            // it. Reject before any guard/payout. The extension already blocks this
            // client-side, but the backend is the authoritative boundary.
            if (bounty.fundingMode === 'nwc') {
                return res.status(400).json({
                    error: 'Non-custodial (NWC) bounties hold no custodied funds to refund; deactivate without a refund LNURL',
                });
            }

            // Idempotency: if this bounty has already been refunded, stop. The
            // presence of `refundCheckingId` is the single source of truth.
            if (bounty.refundCheckingId) {
                return res.status(400).json({ error: 'Bounty has already been refunded' });
            }

            // Can't refund a bounty whose invoice was never paid — there's nothing
            // to send back.
            if (!bounty.invoicePaid) {
                return res.status(400).json({
                    error: 'Nothing to refund; invoice was never paid',
                });
            }

            // Can't refund if the sats have already been paid out to a claimant.
            // Checked across every claim, not just the newest: a claimant can file
            // a fresh claim after an earlier one was approved, and reading only the
            // latest would let that newer `pending` row mask the payout and refund
            // an already-spent bounty.
            if (hasApprovedClaim) {
                return res.status(400).json({
                    error: 'Bounty already paid out to a claimant; cannot refund',
                });
            }

            // Kill switch, checked before the lock so a paused service bails
            // cheaply. The full guard stack runs after the lock, below.
            if (!payoutsEnabled()) {
                return res.status(503).json({
                    error: 'Payouts are temporarily disabled (kill switch)',
                });
            }

            // --- Atomic refund lock (anti-double-spend) ------------------------
            // Stamp `refundAt` to claim the refund slot, but only while no refund
            // has started or completed (both `refundCheckingId` and `refundAt` are
            // still null). This is a single-winner transition: a concurrent refund
            // request updates zero rows and bails here, so the payout below can
            // only ever fire once even though the `refundCheckingId` fast-path
            // check above is not atomic on its own.
            //
            // The lock is taken BEFORE the LNURL validation network call: the
            // claim-state checks above are a snapshot, and an approve landing while
            // we're off fetching the refund LNURL would pay the claimant and then
            // let this refund pay the same bounty a second time (refund-vs-approve
            // TOCTOU). The mirror-image guard lives in /approve, which re-reads
            // these refund markers after taking its claim lock — whichever
            // operation takes its lock second sees the other's marker and bails.
            const refundLocked = await db.update(schema.bounties)
                .set({ refundAt: new Date() })
                .where(and(
                    eq(schema.bounties.id, strId),
                    isNull(schema.bounties.refundCheckingId),
                    isNull(schema.bounties.refundAt),
                ))
                .returning({ id: schema.bounties.id });

            if (refundLocked.length === 0) {
                return res.status(409).json({
                    error: 'A refund for this bounty is already in progress or completed',
                });
            }

            // Release the lock (clear `refundAt`) so the creator can retry after a
            // payout failure. Guarded on `refundCheckingId IS NULL` so we never
            // wipe the timestamp of a refund that actually succeeded.
            const releaseRefundLock = async () => {
                try {
                    await db.update(schema.bounties)
                        .set({ refundAt: null })
                        .where(and(
                            eq(schema.bounties.id, strId),
                            isNull(schema.bounties.refundCheckingId),
                        ));
                } catch (releaseErr) {
                    console.error('[deactivate] failed to release refund lock:', releaseErr);
                }
            };

            // Re-read claim state AFTER taking the lock: an approve that locked a
            // claim while we were taking the refund lock is visible now. Paying the
            // refund on top of an in-flight or completed claimant payout would
            // spend the same bounty twice.
            const claimsNow = await db.query.claims.findMany({
                where: eq(schema.claims.bountyId, strId),
                columns: { status: true },
            });
            if (claimsNow.some(
                (c) => c.status === claimStatusApproving || c.status === claimStatusApproved,
            )) {
                await releaseRefundLock();
                return res.status(409).json({
                    error:
                        'This bounty has a payout in progress or already paid. ' +
                        'Resolve the claim before refunding.',
                    code: 'CLAIM_IN_PROGRESS',
                });
            }

            // Validate the refund LNURL and make sure the amount fits its range.
            // Surface the underlying error message instead of swallowing it — the
            // previous bare `catch {}` made every LNURL failure look identical
            // and cost us hours of debugging. The dev-mode `message` field lets
            // local devs see what specifically failed (timeout, missing field,
            // 5xx from LNbits, etc.) without leaking detail to prod users.
            let lnurlResult;
            try {
                lnurlResult = await checkValidLnurl(input.refundLnurl);
            } catch (err) {
                await releaseRefundLock();
                console.error('[deactivate] checkValidLnurl failed:', err);
                return res.status(400).json({
                    error: 'Invalid or unreachable LNURL',
                    message: devErrorMessage(err, 'Invalid or unreachable LNURL'),
                });
            }
            const amountMsat = convertSatsToLnbitsParam(bounty.amountSats);
            if (amountMsat < lnurlResult.minSendable || amountMsat > lnurlResult.maxSendable) {
                await releaseRefundLock();
                return res.status(400).json({
                    error: 'Bounty amount is outside the sendable range of the refund LNURL',
                });
            }

            // Payout guards (same stack as /approve), run AFTER the lock for the
            // same reason: `refundAt` is now stamped, so `sumApprovedWithin` counts
            // this refund and a concurrent payout elsewhere can see it. Every
            // failure path releases the lock so the creator can retry.
            const guard = await runPayoutGuards({
                amountSats: bounty.amountSats,
                kind: 'refund',
                // A refund always leaves our LNbits payout wallet, so the
                // balance sanity check always applies here.
                checkBalance: true,
                context: { bountyId: strId, approvedBy: bounty.creatorId },
            });
            if (!guard.ok) {
                await releaseRefundLock();
                return res.status(guard.status).json({ error: guard.error });
            }

            // Fire the payout. A PLAIN error means the request never reached the
            // pay step (LNURL resolution, bounds, amount cross-check) — provably
            // unpaid, release the lock so the creator can retry. An
            // `LnbitsPayoutError` means the pay request may have committed before
            // we learned the outcome — reconcile against the wallet by payment
            // hash, and only release when LNbits proves no payment exists. This is
            // the same unknown-outcome discipline the NWC approve path follows:
            // a stuck refund is recoverable, a double refund is not.
            const refundComment = 'Refund';
            let payoutResult;
            try {
                payoutResult = await createLnbitsPayout(
                    input.refundLnurl,
                    bounty.amountSats,
                    refundComment,
                    `refund:${strId}`,
                );
            } catch (payoutErr) {
                if (payoutErr instanceof LnbitsPayoutError) {
                    const state = payoutErr.paymentHash
                        ? await lookupLnbitsPayment(payoutErr.paymentHash)
                        : 'unknown';
                    if (state !== 'not-found') {
                        // 'paid' or 'unknown': the sats may be gone. Keep the lock
                        // (`refundAt` stays stamped) so a retry can't pay twice;
                        // an operator reconciles against the payout wallet.
                        console.error(
                            `[deactivate] refund outcome unknown for bounty ${strId} ` +
                            `(paymentHash=${payoutErr.paymentHash ?? 'none'}): ${payoutErr.message}`,
                        );
                        await alertAnomaly({
                            bountyId: strId,
                            amountSats: bounty.amountSats,
                            approvedBy: bounty.creatorId,
                            reason: `Refund outcome unknown, refund left locked: ${payoutErr.message}`,
                        });
                        return res.status(502).json({
                            error:
                                'Sattest could not confirm this refund with LNbits. It may have ' +
                                'been sent. The refund is on hold so it cannot be paid twice — ' +
                                'check the payout wallet before retrying.',
                            code: 'PAYOUT_OUTCOME_UNKNOWN',
                        });
                    }
                    // LNbits proves no payment exists — fall through and release.
                }
                await releaseRefundLock();
                // LNbits requires a small fee-reserve buffer above the payout
                // amount. If the wallet only holds exactly `amountSats` (common
                // when refunding the same invoice that funded it), the payout
                // returns a 520 with a "must reserve at least N sat" message.
                // Translate that into a 400 with a clear, actionable error so
                // the user knows to either top up the wallet or refund slightly
                // less than the full amount.
                const msg = payoutErr instanceof Error ? payoutErr.message : String(payoutErr);
                if (/reserve.*sat.*routing fees/i.test(msg)) {
                    return res.status(400).json({
                        error:
                            'Refund failed: the payout wallet needs a small fee reserve. ' +
                            'Top up the LNbits payout wallet by ~100 sats and retry, or ' +
                            'deactivate without a refund.',
                    });
                }
                throw payoutErr;
            }

            // Atomically record the refund + deactivate.
            const result = await db.update(schema.bounties)
                .set({
                    active: false,
                    refundLnurl: input.refundLnurl,
                    refundCheckingId: payoutResult.checking_id,
                    refundAt: new Date(),
                    updatedAt: new Date(),
                })
                .where(eq(schema.bounties.id, strId))
                .returning({ id: schema.bounties.id, active: schema.bounties.active });

            return res.status(200).json({
                success: true,
                message: 'Bounty refunded and deactivated',
                bountyId: result[0].id,
                active: result[0].active,
                refund: {
                    checkingId: payoutResult.checking_id,
                    amountSats: bounty.amountSats,
                },
            });
        } catch (err) {
            console.error('[PATCH /deactivate] Error:', err);
            res.status(500).json({
                error: 'Failed to deactivate bounty',
                message: devErrorMessage(err, 'Internal server error'),
            });
        }
    });
}
