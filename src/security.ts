/**
 * Payout circuit breakers, kill switch, anomaly alerts, and balance sanity
 * checks. These run in front of `createLnbitsPayout()` so that a compromise
 * of the backend or a bug in the auth path can only drain limited funds
 * before tripping a guard.
 *
 * Philosophy: each guard is cheap and local; failure of any guard returns an
 * error up to the `/approve` handler, which surfaces a 5xx to the caller and
 * leaves the claim in `pending` so an operator can reconcile.
 */
import fetch from 'node-fetch';
import { and, gte, inArray, sql } from 'drizzle-orm';
import { db } from './db';
import { config } from './config';
import * as schema from './schema';
import { claimStatusApproved, claimStatusApproving } from './types/claim.types';

/** Read a non-negative integer from an env var, falling back to a default. */
function intEnv(name: string, fallback: number): number {
    const raw = process.env[name];
    if (!raw) return fallback;
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) return fallback;
    return Math.floor(n);
}

/** True if payouts are enabled (kill switch is off). */
export function payoutsEnabled(): boolean {
    // Default to enabled so a missing env var doesn't silently block payouts
    // in existing environments. Ops flips to `false` to pause.
    return config.payout.enabled;
}

/**
 * True if the custodial (LNbits invoice/QR) bounty path is allowed.
 *
 * Defaults to OFF — the inverse of `payoutsEnabled()`. Custodial bounties
 * require us to hold creator funds in the LNbits Treasury/Payout wallets,
 * which we're not deploying right now; NWC (non-custodial) is the only path.
 * Ops flips this to `true` (and configures LNBITS_*) to bring custodial back.
 */
export function custodialBountiesEnabled(): boolean {
    return config.payout.custodialBountiesEnabled;
}

/**
 * Sums of payouts that have left — or may have left — in the last hour and the
 * last 24 hours, in sats. Both windows come from one pass over the same rows.
 *
 * Two things this deliberately counts that a naive "sum approved claims" does
 * not, because both are real outflow and excluding them meant the caps bounded
 * less than they advertised:
 *
 *   1. Claims in `approving`. An unconfirmed NIP-47 outcome may already have
 *      paid — that is exactly why the approve handler keeps the lock instead of
 *      releasing it (see `NwcPayoutError.outcome`). Money that might be gone has
 *      to count against the cap; the alternative is a burst of unconfirmed
 *      payouts slipping past it entirely. Windowed on `approvingAt` when there
 *      is no `approvedAt` yet.
 *   2. Refunds. A completed refund pays out of the same wallet but writes
 *      `refundCheckingId`/`refundAt` on `bounties` and never produces an
 *      approved claim — so refunds were limited *by* the cap while contributing
 *      nothing *to* it.
 */
async function sumOutflowWindows(): Promise<{ hourly: number; daily: number }> {
    const now = Date.now();
    const dayCutoff = new Date(now - 24 * 60 * 60 * 1000);
    const hourCutoff = new Date(now - 60 * 60 * 1000);

    // One scan per table instead of four. The hourly window is a strict subset
    // of the daily one, so both totals come from the same rows via a FILTER'd
    // aggregate — previously each window ran its own pair of queries, so every
    // payout cost four round-trips to compute two numbers over the same data.
    const [claimRows, refundRows] = await Promise.all([
        db
            .select({
                daily: sql<number>`coalesce(sum(${schema.bounties.amountSats}), 0)::int`,
                hourly: sql<number>`coalesce(sum(${schema.bounties.amountSats}) filter (
                    where coalesce(${schema.claims.approvedAt}, ${schema.claims.approvingAt}) >= ${hourCutoff}
                ), 0)::int`,
            })
            .from(schema.claims)
            .innerJoin(schema.bounties, sql`${schema.claims.bountyId} = ${schema.bounties.id}`)
            .where(and(
                inArray(schema.claims.status, [claimStatusApproved, claimStatusApproving]),
                gte(
                    sql`coalesce(${schema.claims.approvedAt}, ${schema.claims.approvingAt})`,
                    dayCutoff,
                ),
            )),
        db
            .select({
                daily: sql<number>`coalesce(sum(${schema.bounties.amountSats}), 0)::int`,
                hourly: sql<number>`coalesce(sum(${schema.bounties.amountSats}) filter (
                    where ${schema.bounties.refundAt} >= ${hourCutoff}
                ), 0)::int`,
            })
            .from(schema.bounties)
            // `refundAt` alone is the right predicate, not `refundCheckingId`:
            // the refund lock stamps `refundAt` *before* the payout fires and
            // clears it again if the payout provably failed, so this counts
            // in-flight refunds (money that may be moving right now) and
            // completed ones, while excluding released locks. Gating on
            // `refundCheckingId` instead would leave an in-flight refund
            // invisible — the same gap that `approving` claims had.
            .where(gte(schema.bounties.refundAt, dayCutoff)),
    ]);

    return {
        hourly: Number(claimRows?.[0]?.hourly ?? 0) + Number(refundRows?.[0]?.hourly ?? 0),
        daily: Number(claimRows?.[0]?.daily ?? 0) + Number(refundRows?.[0]?.daily ?? 0),
    };
}

export interface CircuitBreakerVerdict {
    ok: boolean;
    reason?: string;
    /** HTTP status to surface to the client (429 for rate-type, 503 for kill-switch/balance). */
    status?: number;
}

/**
 * Evaluate whether a payout of `amountSats` should proceed. Checks:
 *   1. Kill switch (PAYOUTS_ENABLED)
 *   2. Hourly cap (PAYOUT_CAP_HOURLY_SATS, default 1_000_000)
 *   3. Daily cap  (PAYOUT_CAP_DAILY_SATS,  default 10_000_000)
 *
 * Returns `{ ok: true }` when the payout is cleared. A verdict with `ok: false`
 * carries a reason suitable for logging and a `status` to return to the client.
 */
export async function evaluatePayoutGuards(amountSats: number): Promise<CircuitBreakerVerdict> {
    if (!payoutsEnabled()) {
        return { ok: false, reason: 'Payouts are temporarily disabled (kill switch)', status: 503 };
    }

    const hourlyCap = intEnv('PAYOUT_CAP_HOURLY_SATS', 1_000_000);
    const dailyCap = intEnv('PAYOUT_CAP_DAILY_SATS', 10_000_000);

    const { hourly, daily } = await sumOutflowWindows();

    if (hourly + amountSats > hourlyCap) {
        return {
            ok: false,
            reason: `Hourly payout cap exceeded (${hourly}+${amountSats} > ${hourlyCap})`,
            status: 429,
        };
    }

    if (daily + amountSats > dailyCap) {
        return {
            ok: false,
            reason: `Daily payout cap exceeded (${daily}+${amountSats} > ${dailyCap})`,
            status: 429,
        };
    }

    return { ok: true };
}

/**
 * Sanity-check the hot (payout) wallet balance immediately before a payout.
 * The payout wallet is intentionally kept near-empty in steady state, so a
 * balance dramatically larger than the payout being made is a red flag
 * (missed sweep, wrong wallet wired in, etc.) — we bail rather than drain it.
 *
 * Returns `true` if the wallet looks sane for this payout, `false` if suspect.
 * A missing/errored LNbits response returns `true` (fail-open) so that LNbits
 * availability blips don't block legitimate payouts; the actual payout call
 * will fail loudly if something is really wrong.
 */
export async function payoutBalanceLooksSane(amountSats: number): Promise<boolean> {
    const url = config.lnbits.url;
    const key = config.lnbits.adminKey;
    if (!url || !key) return true;

    // Multiplier: allow the hot wallet to hold up to Nx the payout being made,
    // to accommodate concurrent approvals and small buffer liquidity.
    const multiplier = intEnv('PAYOUT_BALANCE_MULTIPLIER', 10);

    try {
        const response = await fetch(`${url}/api/v1/wallet`, {
            method: 'GET',
            signal: AbortSignal.timeout(5_000),
            headers: { 'X-Api-Key': key },
        });
        if (!response.ok) return true; // fail-open on transient errors
        const data = await response.json() as { balance?: number };
        const balanceMsat = data?.balance;
        if (typeof balanceMsat !== 'number') return true;
        const balanceSats = Math.floor(balanceMsat / 1000);
        return balanceSats <= amountSats * multiplier;
    } catch {
        return true; // fail-open
    }
}

export interface AnomalyContext {
    bountyId: string;
    claimId?: string;
    amountSats: number;
    reason: string;
    approvedBy?: string;
}

/**
 * Log + (optionally) POST to an alert webhook when something unusual happens
 * around a payout. Never throws — alerting must not block the main flow.
 * Triggers:
 *   - single payout > PAYOUT_ALERT_SATS
 *   - guard verdict tripped
 *   - cumulative hourly outflow > 50% of cap
 */
export async function alertAnomaly(ctx: AnomalyContext): Promise<void> {
    const payload = {
        service: 'sattest-backend',
        event: 'payout-anomaly',
        at: new Date().toISOString(),
        ...ctx,
    };

    console.warn('[security] payout anomaly:', JSON.stringify(payload));

    const webhook = config.alertWebhookUrl;
    if (!webhook) return;

    try {
        await fetch(webhook, {
            method: 'POST',
            signal: AbortSignal.timeout(5_000),
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
    } catch (err) {
        // Swallow — an alerting failure must never propagate to the caller.
        console.error('[security] alert webhook failed:', err);
    }
}

/** True if this payout amount should fire an anomaly alert based on size. */
export function isLargePayout(amountSats: number): boolean {
    const threshold = intEnv('PAYOUT_ALERT_SATS', 500_000);
    return amountSats >= threshold;
}
