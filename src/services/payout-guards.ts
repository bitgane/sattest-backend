import {
    evaluatePayoutGuards,
    payoutBalanceLooksSane,
    isLargePayout,
    alertAnomaly,
} from '../security';

/**
 * The full pre-payout guard stack, run once.
 *
 * `/approve` and `/deactivate` both had to clear the same three gates before
 * money moves — cumulative caps (which include the kill switch), hot-wallet
 * balance sanity, and the large-payout alert — and each had its own verbatim
 * copy of the sequence, differing only in which lock it released and how it
 * worded the alert. Two hand-maintained copies of a circuit breaker is exactly
 * the thing that drifts.
 *
 * Lock release deliberately stays at the call site: only the caller knows which
 * lock it holds, and the release must happen on the bail path and never on the
 * success path. This returns the verdict; the caller decides what to unwind.
 *
 * Alerting happens in here (every tripped gate is alerted, as before), so a
 * caller that forgets to alert can't silently swallow a breaker trip.
 *
 * Lives outside `security.ts` on purpose: it *composes* the primitives rather
 * than being one, and importing them means a test that mocks `./security` still
 * intercepts each gate individually. Defining it alongside them would bind the
 * calls intra-module, past any mock, and make the guard stack untestable.
 */
export interface PayoutGuardOptions {
    amountSats: number;
    /** Distinguishes a claimant payout from a creator refund in alert text. */
    kind: 'payout' | 'refund';
    /**
     * Whether the hot-wallet balance check applies. Only custodial payouts draw
     * on our LNbits payout wallet — an NWC payout comes straight from the
     * creator's own wallet, so the check is N/A there.
     */
    checkBalance: boolean;
    /** Alert context for whichever gate trips. */
    context: { bountyId: string; claimId?: string; approvedBy?: string };
}

export type PayoutGuardResult =
    | { ok: true }
    | { ok: false; status: number; error: string };

/**
 * Alert wording, kept byte-identical to the two inline copies this replaces so
 * operators' log greps and the existing tests keep matching.
 */
const GUARD_ALERT_TEXT = {
    payout: {
        tripped: (reason: string) => `Payout guard tripped: ${reason}`,
        balance: 'Payout wallet balance exceeds configured multiplier of payout amount',
        large: 'Large payout exceeds PAYOUT_ALERT_SATS',
    },
    refund: {
        tripped: (reason: string) => `Refund guard tripped: ${reason}`,
        balance: 'Refund halted: payout wallet balance looks anomalous',
        large: 'Large refund exceeds PAYOUT_ALERT_SATS',
    },
} as const;

export async function runPayoutGuards(
    opts: PayoutGuardOptions,
): Promise<PayoutGuardResult> {
    const { amountSats, kind, checkBalance, context } = opts;
    const text = GUARD_ALERT_TEXT[kind];

    // 1. Kill switch + cumulative outflow caps (hourly / daily).
    const verdict = await evaluatePayoutGuards(amountSats);
    if (!verdict.ok) {
        await alertAnomaly({
            ...context,
            amountSats,
            reason: text.tripped(verdict.reason as string),
        });
        return {
            ok: false,
            status: verdict.status ?? 429,
            error: verdict.reason as string,
        };
    }

    // 2. Hot-wallet balance sanity (custodial only).
    if (checkBalance && !(await payoutBalanceLooksSane(amountSats))) {
        await alertAnomaly({ ...context, amountSats, reason: text.balance });
        return {
            ok: false,
            status: 503,
            error: 'Payout halted: wallet balance looks anomalous',
        };
    }

    // 3. Pre-payout alert for unusually large outflows (informational — this
    //    does NOT block, it only tells an operator to look).
    if (isLargePayout(amountSats)) {
        await alertAnomaly({ ...context, amountSats, reason: text.large });
    }

    return { ok: true };
}
