export type ClaimStatus = 'pending' | 'approving' | 'approved';

export const claimStatusPending: ClaimStatus = 'pending';

/**
 * Transient lock state held only while a payout is in flight. The /approve
 * handler atomically flips the claim `pending → approving` (a conditional
 * UPDATE that just one concurrent request can win) before any money moves, so
 * a double-click / replay / concurrent approve can't trigger a second payout.
 * On success it advances to `approved`.
 *
 * It reverts to `pending` ONLY when the payout provably didn't happen —
 * `NwcPayoutError.outcome === 'failed'`, meaning the request never reached the
 * wallet or the wallet explicitly declined. An *unknown* outcome (classically
 * a NIP-47 reply timeout, which a relay also produces for a payment that
 * settled fine) keeps the lock, because every retry mints a fresh invoice with
 * a new payment hash: unlocking a payment that actually went through pays the
 * claimant twice.
 *
 * A row stuck in `approving` is therefore the deliberate safe state, not a
 * dead end. `reconcileApprovingClaim` resolves it by asking the wallet
 * directly (NIP-47 `lookup_invoice`, keyed on the `payout_payment_hash` stored
 * alongside the lock) on the next approve, and `sweepStaleApprovingClaims`
 * does the same at boot for claims orphaned by a mid-payout restart.
 */
export const claimStatusApproving: ClaimStatus = 'approving';

export const claimStatusApproved: ClaimStatus = 'approved';
