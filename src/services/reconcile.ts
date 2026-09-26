import { and, eq } from 'drizzle-orm';
import * as schema from '../schema';
import { db } from '../db';
import { decrypt } from '../crypto';
import { lookupNwcPayment, walletPubkeyFromNwcUri } from '../nwc';
import { claimStatusApproved, claimStatusApproving, claimStatusPending } from '../types/claim.types';

/**
 * Outcome of reconciling a claim that is sitting in the `approving` lock.
 *
 *   'settled'     — the wallet confirms it paid; the claim has been finalized
 *                   here and the caller should report it as already approved.
 *   'released'    — the wallet confirms it did NOT pay; the lock is back to
 *                   `pending` and the caller may retry the payout normally.
 *   'still-locked'— we still don't know (or it's genuinely mid-flight). The
 *                   lock stays; the caller must not pay.
 *   'needs-confirmation'
 *                 — no wallet can ever answer for this attempt (the creator is
 *                   now connected to a different wallet than the one that made
 *                   it). Automatic reconciliation is impossible; only a human
 *                   who can look at their wallet history can resolve it.
 */
export type ReconcileResult =
    | { resolution: 'settled'; payoutTxid: string }
    | { resolution: 'released' }
    | { resolution: 'still-locked'; detail: string }
    | { resolution: 'needs-confirmation'; detail: string };

export async function reconcileApprovingClaim(
    bounty: typeof schema.bounties.$inferSelect,
    claim: typeof schema.claims.$inferSelect,
): Promise<ReconcileResult> {
    // Custodial payouts run through LNbits, which has its own reconciliation
    // story — nothing to look up over NWC.
    if (bounty.fundingMode !== 'nwc') {
        return { resolution: 'still-locked', detail: 'Payout is still being processed' };
    }
    // Rows locked before this bookkeeping existed (or whose invoice wouldn't
    // decode) have nothing to look up. Safe side: stay locked.
    if (!claim.payoutPaymentHash && !claim.payoutBolt11) {
        return {
            resolution: 'still-locked',
            detail: 'Payout is still being processed (no payment reference recorded)',
        };
    }

    const creator = await db.query.users.findFirst({
        where: eq(schema.users.nostrPubkey, bounty.creatorId),
        columns: { encryptedNwcUri: true },
    });
    if (!creator?.encryptedNwcUri) {
        return {
            resolution: 'still-locked',
            detail: 'Reconnect your Lightning wallet so Sattest can confirm the previous payout',
        };
    }

    // Only the wallet that made the attempt can say what happened to it.
    //
    // A creator whose wallet went dark can (and should be able to) connect a
    // different one — but that new wallet has never seen this payment hash. Its
    // "not found" is not evidence the payment failed, and if it reports
    // `failed` outright, believing it would release the lock and let a retry
    // pay a second time for an invoice the OLD wallet may well have settled.
    // So when the identity doesn't match, don't ask: hand it to the human who
    // can actually look at both wallets.
    //
    // Note: if a wallet mints a fresh service pubkey per connection, then
    // reconnecting the *same* node reads as a different wallet here and we fall
    // back to confirmation even though a lookup would have worked. That's a
    // deliberate false negative — asking the creator is always safe, trusting an
    // answer we can't attribute is not.
    const attemptWallet = claim.payoutWalletPubkey;
    const currentWallet = (() => {
        try {
            return walletPubkeyFromNwcUri(decrypt(creator.encryptedNwcUri));
        } catch {
            return undefined;
        }
    })();

    if (!attemptWallet || !currentWallet || attemptWallet !== currentWallet) {
        return {
            resolution: 'needs-confirmation',
            detail:
                'The wallet now connected is not the one this payout was sent from, ' +
                'so Sattest cannot confirm what happened to it. Check the wallet you ' +
                'used at the time, then confirm the outcome.',
        };
    }

    const lookup = await lookupNwcPayment(creator.encryptedNwcUri, {
        paymentHash: claim.payoutPaymentHash ?? undefined,
        bolt11: claim.payoutBolt11 ?? undefined,
    });

    if (lookup.state === 'settled') {
        // The earlier attempt DID pay — the reply just never reached us.
        // Finalize now so the claim reflects reality and can never be paid
        // a second time.
        await db.update(schema.bounties)
            .set({ active: false })
            .where(eq(schema.bounties.id, bounty.id));
        await db.update(schema.claims)
            .set({
                status: claimStatusApproved,
                payoutTxid: lookup.preimage,
                approvedBy: bounty.creatorId,
                approvedAt: new Date(),
            })
            .where(and(
                eq(schema.claims.id, claim.id),
                eq(schema.claims.status, claimStatusApproving),
            ));
        console.log(
            `[approve] reconciled claim ${claim.id}: wallet confirms payment settled, finalized`,
        );
        return { resolution: 'settled', payoutTxid: lookup.preimage };
    }

    if (lookup.state === 'failed') {
        // Confirmed not paid — safe to unlock and let the creator retry.
        // Clear the bookkeeping so the columns only ever describe the attempt
        // currently holding the lock.
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
        console.log(`[approve] reconciled claim ${claim.id}: wallet confirms payment failed, unlocked`);
        return { resolution: 'released' };
    }

    if (lookup.state === 'pending') {
        return { resolution: 'still-locked', detail: 'The Lightning payment is still settling' };
    }

    console.warn(`[approve] could not reconcile claim ${claim.id}: ${lookup.reason}`);
    return {
        resolution: 'still-locked',
        detail: 'Sattest could not confirm the previous payout with your wallet yet',
    };
}
