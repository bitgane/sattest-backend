import type { Response } from 'express';
import { z } from 'zod';

// Shared HTTP-layer constants + helpers, extracted from index.ts so route and
// schema modules can reuse them without importing the whole app.

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const NOSTR_PUBKEY_RE = /^[0-9a-f]{64}$/i;

/**
 * True when `err` is a Postgres unique-constraint violation (SQLSTATE 23505).
 *
 * Drizzle wraps driver errors, so the `code` can sit on the error itself or on
 * anything down its `cause` chain — walk it rather than assuming a depth. Used
 * to turn a lost insert race into the same benign answer as the non-atomic
 * fast-path check that precedes it, instead of a 500.
 */
export function isUniqueViolation(err: unknown): boolean {
    let current: unknown = err;
    for (let depth = 0; current && depth < 5; depth++) {
        if (typeof current === 'object' && (current as { code?: unknown }).code === '23505') {
            return true;
        }
        current = (current as { cause?: unknown }).cause;
    }
    return false;
}

// Git repo slug like "owner/repo". Matches what the extension parses out of
// `git remote get-url origin`. Intentionally permissive (GitHub, GitLab,
// Bitbucket all fit) but disallows whitespace, multiple slashes, and overlong
// inputs to prevent abuse as a cheap scope key.
export const REPO_SLUG_RE = /^[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._-]{1,100}$/;

// Column allowlist for the UNAUTHENTICATED listing endpoints (GET /bounties and
// POST /bounties/filter). Only fields the extension's board/code-lens actually
// need are returned. Deliberately omitted: `invoice` (a payable bolt11),
// `paymentHash`, `refundLnurl` (a creator's payout destination),
// `refundCheckingId` (internal LNbits id), and `memo` (free-form text) — none
// of which anonymous callers should see. `creatorId` stays because the client
// uses it to decide whether to render creator-only actions.
//
// Accepted residual: exposing `creatorId` lets an anonymous caller
// enumerate which Nostr pubkeys created bounties on a given repo/test — a
// correlation/privacy leak. This is accepted for now because the client
// depends on `creatorId` to render creator-only actions without a second
// authenticated round-trip. To close it, drop `creatorId` here and gate
// creator-only UI on an authenticated "is-mine" signal instead.
export const PUBLIC_BOUNTY_COLUMNS = {
    id: true,
    testId: true,
    creatorId: true,
    amountSats: true,
    invoicePaid: true,
    fundingMode: true,
    repo: true,
    active: true,
    createdAt: true,
} as const;

// Column allowlist for claims nested under the UNAUTHENTICATED listing
// endpoints. The code lens only needs to know that an open claim exists and
// what state it's in.
//
// Deliberately omitted: `claimedAt` — publishing the exact filing time of every
// claim, unauthenticated, told an attacker precisely when a legitimate claim
// landed so they could file one straight after it. `claimantPubkey` and
// `claimantLnurl` are omitted for the obvious reason: neither belongs in an
// anonymous response.
export const PUBLIC_CLAIM_COLUMNS = {
    id: true,
    status: true,
} as const;

/**
 * Render a Zod validation failure as the standard 400 response. Use as
 * `return sendZodValidationError(res, error);` from a `catch` after `.parse()`.
 * Kept byte-identical to the inline blocks it replaces.
 */
export function sendZodValidationError(res: Response, error: z.ZodError) {
    return res.status(400).json({
        error: 'Validation failed',
        issues: error.issues.map(issue => ({
            field: issue.path.join('.'),
            message: issue.message,
        })),
    });
}

/**
 * The `message` field for a JSON error response: the real error text in
 * development, a safe generic string in production. `nonErrorDev` is the dev
 * value when `err` isn't an Error (defaults to `String(err)`). Preserves the
 * exact prod/dev split of the inline expressions it replaces.
 */
export function devErrorMessage(err: unknown, prodMessage: string, nonErrorDev?: string): string {
    if (process.env.NODE_ENV === 'development') {
        return err instanceof Error ? err.message : (nonErrorDev ?? String(err));
    }
    return prodMessage;
}
