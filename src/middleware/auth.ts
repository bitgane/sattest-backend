import { Request, Response, NextFunction } from 'express';
import { verifyEvent, type VerifiedEvent } from 'nostr-tools';
import { consumeNonce } from './nonce';
import { config } from '../config';

/**
 * Freshness window for **read-only** endpoints (GET /bounties, nwc-status, …).
 * Relaxed so the board doesn't blank out during a normal coding session — a
 * replayed read is harmless, and the auth event rides an HTTPS-only header that
 * is never broadcast over relays. Dev is loose for long sessions.
 */
const DEFAULT_MAX_EVENT_AGE_SECONDS = process.env.NODE_ENV === 'development'
    ? 60 * 60 * 24  // 24h in development
    : 1800;         // 30 minutes in production

/**
 * Tighter window for **state-mutating** endpoints (/approve, /claim, deactivate,
 * POST /bounties, PATCH /nwc, …). Keeping writes on a short window means relaxing
 * the read window above never widens payout/replay exposure. Set to 300s (today's
 * value) so an approve stays instant for ~5 min after connecting; the extension's
 * transparent re-auth-on-401 covers anything older. Drop to `60` for stricter
 * replay bounds at the cost of more frequent reconnect prompts.
 */
const MONEY_MAX_EVENT_AGE_SECONDS = process.env.NODE_ENV === 'development'
    ? 60 * 60 * 24
    : 300;

/** Allowed future skew, in seconds, to tolerate clock drift on the signer. */
const ALLOWED_FUTURE_SKEW_SECONDS = 300;

/**
 * Scope-separated auth content strings.
 *
 * The extension signs two distinct events at connect time:
 *   - READ:  content = 'sattest-auth'       — acceptable to `nostrAuth`
 *   - WRITE: content = 'sattest-auth:write' — required by `moneyAuth`
 *
 * This ensures a read credential captured in transit (e.g. from a GET
 * request log) cannot be replayed against state-mutating endpoints even
 * while it is still fresh. A stolen write credential is still bounded by
 * the 5-minute `MONEY_MAX_EVENT_AGE_SECONDS` window.
 */
export const READ_AUTH_CONTENT = 'sattest-auth';
export const WRITE_AUTH_CONTENT = 'sattest-auth:write';

/**
 * NIP-42 auth event kind accepted by both middlewares.
 *
 * Was an inline `22242` literal at the one comparison site. Naming it makes the
 * wire contract greppable from both sides — the extension's counterpart is
 * `NOSTR_AUTH_KIND` in `sattest/src/api/nostr-protocol.ts`, and
 * `auth.contract.test.ts` pins these values so a one-sided edit fails CI
 * instead of failing a payout.
 */
export const NOSTR_AUTH_KIND = 22242;

/**
 * Express request augmented with the authenticated Nostr pubkey.
 * After the middleware runs, `req.nostrPubkey` contains the hex pubkey
 * of the user who signed the Authorization event.
 */
export interface NostrAuthRequest extends Request {
    nostrPubkey?: string;
    /** The parsed, verified event — available to handlers for binding-tag checks. */
    nostrEvent?: VerifiedEvent;
}

/**
 * Express middleware that validates Nostr-signed authentication.
 *
 * Expects the header:
 *   Authorization: Nostr <base64-encoded JSON of a signed Nostr event>
 *
 * The event must:
 *   1. Be a valid Nostr event (correct id hash + valid schnorr signature)
 *   2. Be kind 22242 (NIP-42 AUTH)
 *   3. Have content "sattest-auth"
 *   4. Have a created_at within DEFAULT_MAX_EVENT_AGE_SECONDS of now
 *
 * On success, sets `req.nostrPubkey` to the event's pubkey and calls next().
 * On failure, returns 401 Unauthorized.
 *
 * `nostrAuth` is the read-path middleware (relaxed window); `moneyAuth` is the
 * same check on the tighter write window, plus a server-issued single-use
 * nonce (see `verifyAuthHeader`). Both are built from
 * `makeNostrAuth`.
 */
function makeNostrAuth(maxAgeSeconds: number, requiredContent: string, requireNonce: boolean = false) {
    return function nostrAuthMiddleware(
        req: NostrAuthRequest,
        res: Response,
        next: NextFunction,
    ): void {
        const verified = verifyAuthHeader(req, maxAgeSeconds, requiredContent, requireNonce);
        if (!verified.ok) {
            res.status(401).json({ error: verified.error });
            return;
        }
        req.nostrPubkey = verified.event.pubkey;
        req.nostrEvent = verified.event;
        next();
    };
}

/** Read-path auth — relaxed freshness window, read-scoped credential required. */
export const nostrAuth = makeNostrAuth(DEFAULT_MAX_EVENT_AGE_SECONDS, READ_AUTH_CONTENT);

/**
 * Write-path auth — tighter freshness window, write-scoped credential, AND a
 * server-issued single-use nonce required.
 *
 * Accepts only events with `content: 'sattest-auth:write'`, which the extension
 * signs fresh per money-moving call (see `signMoneyAuthEvent` in the
 * extension). A read credential (`content: 'sattest-auth'`) is explicitly
 * rejected here, so capturing a read-path auth event from logs cannot
 * authorize money-moving operations. The event must also carry a `['nonce',
 * <value>]` tag naming a nonce previously issued to this pubkey by `POST
 * /auth/nonce` — the nonce is consumed on first use, so even a captured write
 * credential cannot be replayed a second time.
 */
export const moneyAuth = makeNostrAuth(MONEY_MAX_EVENT_AGE_SECONDS, WRITE_AUTH_CONTENT, true);

type VerifyResult =
    | { ok: true; event: VerifiedEvent }
    | { ok: false; error: string };

/**
 * Shared validation of the Authorization header. Returns the verified event
 * on success or an error message to pass to the 401 response.
 *
 * Time source is the local system clock. NIP-42 does not require a network
 * time source — the signer's `created_at` is cross-checked against our clock
 * with `ALLOWED_FUTURE_SKEW_SECONDS` of tolerance. Making this sync also
 * keeps the auth path off any network dependency.
 *
 * Replay model & residual risk (resolved on the write path): the read
 * credential is still a *bearer* token with a static `content` challenge,
 * reused for the lifetime of `DEFAULT_MAX_EVENT_AGE_SECONDS` — a captured
 * read event is replayable until it ages out. That's an accepted residual
 * (reads are non-destructive) so the client can avoid a signer round-trip on
 * every read. The write path closes the gap: `moneyAuth` additionally
 * requires a server-issued, single-use nonce (see `./nonce.ts`) minted by
 * `POST /auth/nonce` and consumed here on first use, so a captured write
 * credential is a single-shot token, not a bearer one — replaying it fails
 * because the nonce is already gone. Defense-in-depth layers remain on top:
 *   1. HTTPS-only transport (the event never rides a relay) — see config.ts /
 *      state.ts, which refuse non-TLS backend/relay URLs.
 *   2. `AUTH_AUDIENCE` origin binding (below) — a credential harvested by a
 *      different server can't be replayed here. Mandatory in production
 *      (enforced at boot in warnOnInsecureConfig).
 *   3. Read/write scope separation — a read credential can't move money.
 *   4. A tight write freshness window (MONEY_MAX_EVENT_AGE_SECONDS, 300s prod)
 *      bounding how long an unused nonce (and the event carrying it) is valid.
 *   5. Per-object ownership + claimId binding in the handlers, so even a
 *      forged/stolen write still can't redirect funds to an attacker.
 */
function verifyAuthHeader(
    req: Request,
    maxAgeSeconds: number,
    requiredContent: string,
    requireNonce: boolean = false,
): VerifyResult {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Nostr ')) {
        return { ok: false, error: 'Missing or invalid Authorization header. Expected: Nostr <base64-event>' };
    }

    const base64Event = authHeader.slice('Nostr '.length);

    let event: VerifiedEvent;
    try {
        const json = Buffer.from(base64Event, 'base64').toString('utf-8');
        event = JSON.parse(json);
    } catch {
        return { ok: false, error: 'Invalid base64 or JSON in Authorization header' };
    }

    if (!event.id || !event.sig || !event.pubkey || !event.kind || event.created_at == null) {
        return { ok: false, error: 'Malformed Nostr event: missing required fields' };
    }
    if (event.kind !== NOSTR_AUTH_KIND) {
        return {
            ok: false,
            error: `Invalid event kind: expected ${NOSTR_AUTH_KIND}, got ${event.kind}`,
        };
    }
    if (event.content !== requiredContent) {
        return { ok: false, error: `Invalid event content: expected "${requiredContent}"` };
    }

    // Audience binding (defense-in-depth). When `AUTH_AUDIENCE` is configured,
    // the signed event must carry a `['relay', <url>]` tag whose origin matches
    // this backend's. The extension stamps the tag with the backend URL it is
    // actually sending to, so an auth event harvested by a *different* server
    // (e.g. a leak, or a client tricked into a wrong backendUrl) cannot be
    // replayed against us — its tag points at that other origin. Left off when
    // the env var is unset so existing deployments/tests are unaffected.
    const expectedAudience = config.authAudience;
    if (expectedAudience) {
        const expectedOrigin = toOrigin(expectedAudience);
        const relayTag = (event.tags || []).find(
            (t) => Array.isArray(t) && t[0] === 'relay' && typeof t[1] === 'string',
        );
        const actualOrigin = relayTag ? toOrigin(relayTag[1] as string) : undefined;
        if (!expectedOrigin || !actualOrigin || actualOrigin !== expectedOrigin) {
            return {
                ok: false,
                error: 'Auth event audience mismatch (event is not bound to this server)',
            };
        }
    }

    // Freshness. In development we skip this entirely so cached extension
    // tokens work across a long coding session.
    if (process.env.NODE_ENV !== 'development') {
        const now = Math.floor(Date.now() / 1000);
        const age = now - event.created_at;
        if (age > maxAgeSeconds || age < -ALLOWED_FUTURE_SKEW_SECONDS) {
            return { ok: false, error: `Auth event expired or has invalid timestamp (age: ${age}s)` };
        }
    }

    if (!verifyEvent(event)) {
        return { ok: false, error: 'Invalid Nostr event signature' };
    }

    // Single-use nonce. Checked only after the signature is verified —
    // `event.pubkey` isn't trustworthy until then, and we don't want an
    // unauthenticated request able to burn someone else's nonce as a cheap
    // DoS. `consumeNonce` deletes on any matching lookup, so a replay of this
    // exact event (same nonce) fails here on the second attempt.
    if (requireNonce) {
        const nonceTag = (event.tags || []).find(
            (t) => Array.isArray(t) && t[0] === 'nonce' && typeof t[1] === 'string',
        );
        const nonceValue = nonceTag ? (nonceTag[1] as string) : undefined;
        if (!nonceValue || !consumeNonce(nonceValue, event.pubkey)) {
            return {
                ok: false,
                error: 'Missing, invalid, expired, or already-used nonce (request a fresh one via POST /auth/nonce)',
            };
        }
    }

    return { ok: true, event };
}

/** Normalize a URL to its origin (scheme://host:port), lowercased. */
function toOrigin(url: string): string | undefined {
    try {
        return new URL(url).origin.toLowerCase();
    } catch {
        return undefined;
    }
}
