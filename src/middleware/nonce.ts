import * as crypto from 'crypto';

/**
 * Server-issued, single-use nonce store for the write-path auth challenge.
 * A client fetches a nonce via `POST /auth/nonce` (gated by the cheap,
 * reusable read credential) and must embed it in a freshly signed
 * write-scope event for the actual money-moving call. Each nonce is bound to
 * the pubkey it was issued to and can be consumed exactly once, which turns
 * a captured write credential from a replayable bearer token into a
 * single-shot one — replaying it fails because the nonce is already gone.
 *
 * In-memory is sufficient: nonces are short-lived (NONCE_TTL_SECONDS) and
 * losing them on a process restart just means a client re-requests one,
 * which is cheap and doesn't need to survive a redeploy.
 */

const NONCE_TTL_SECONDS = 120;

/** Hard cap on outstanding nonces so an issuance flood can't grow this unbounded. */
const MAX_OUTSTANDING_NONCES = 10_000;

interface NonceEntry {
    pubkey: string;
    expiresAt: number;
}

const nonceStore = new Map<string, NonceEntry>();

function sweepExpired(now: number): void {
    for (const [nonce, entry] of nonceStore) {
        if (entry.expiresAt <= now) {
            nonceStore.delete(nonce);
        }
    }
}

/**
 * Issues a fresh single-use nonce bound to `pubkey`. Sweeps expired entries
 * first; if the store is still at capacity, evicts the oldest entry (Map
 * iteration order is insertion order) rather than refusing to issue.
 */
export function issueNonce(pubkey: string): { nonce: string; expiresAt: number } {
    const now = Date.now();
    sweepExpired(now);

    if (nonceStore.size >= MAX_OUTSTANDING_NONCES) {
        const oldestKey = nonceStore.keys().next().value;
        if (oldestKey !== undefined) {
            nonceStore.delete(oldestKey);
        }
    }

    const nonce = crypto.randomBytes(24).toString('base64url');
    const expiresAt = now + NONCE_TTL_SECONDS * 1000;
    nonceStore.set(nonce, { pubkey, expiresAt });
    return { nonce, expiresAt };
}

/**
 * Consumes `nonce` if it exists, is unexpired, and was issued to `pubkey`.
 * Always deletes the entry on a matching lookup — even an expired or
 * wrong-pubkey nonce is burned so it can't be probed repeatedly — so this is
 * inherently single-use regardless of outcome.
 */
export function consumeNonce(nonce: string, pubkey: string): boolean {
    const entry = nonceStore.get(nonce);
    if (!entry) {
        return false;
    }
    nonceStore.delete(nonce);
    if (entry.expiresAt < Date.now()) {
        return false;
    }
    return entry.pubkey === pubkey;
}

/** Test-only helper to reset state between test cases. */
export function _resetNonceStoreForTests(): void {
    nonceStore.clear();
}
