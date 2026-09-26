import {
    NWCClient,
    Nip47NetworkError,
    Nip47PublishError,
    Nip47PublishTimeoutError,
    Nip47WalletError,
} from '@getalby/sdk';
import { decode as decodeBolt11 } from 'bolt11';
import { decrypt } from './crypto';
import { bolt11AmountMsat } from './lib/lnurl';
import { fetchInvoiceForAmount } from './lib/lnurl-pay';

/**
 * NIP-47 Nostr Wallet Connect adapter.
 *
 * When a bounty is created with `fundingMode: 'nwc'`, the creator has already
 * granted us a budgeted `pay_invoice` permission against their own Lightning
 * wallet. On claim approval we fetch a bolt11 invoice from the claimant's
 * LNURL, then ask the creator's wallet — over Nostr, end-to-end encrypted —
 * to pay it. Sats move creator → claimant; our backend never holds the funds.
 *
 * The functions here are intentionally narrow: each one does one step of that
 * handoff, so the /approve handler can compose them with its existing guard
 * rails (evaluatePayoutGuards, isLargePayout, alertAnomaly).
 */

/**
 * Call a NIP-47 method with an explicit reply budget.
 *
 * `executeNip47Request` is internal to @getalby/sdk — it is absent from the
 * .d.ts surface but present on the client at runtime (verified in
 * node_modules/@getalby/sdk/dist/esm/index.js). The public wrappers
 * (`payInvoice`, …) hard-code a 60s reply timeout, which is too short for cold
 * Lightning routing and too long for a read, so both call sites need to pass
 * their own. The structural cast lived twice, verbatim; it lives here now.
 */
async function executeNip47<T>(
    client: NWCClient,
    method: string,
    request: unknown,
    replyTimeoutMs: number,
): Promise<T | undefined> {
    return (await (client as unknown as {
        executeNip47Request: (
            method: string,
            request: unknown,
            predicate: (r: unknown) => boolean,
            timeouts: { replyTimeout?: number; publishTimeout?: number },
        ) => Promise<unknown>;
    }).executeNip47Request(
        method,
        request,
        (r) => !!r,
        { replyTimeout: replyTimeoutMs },
    )) as T | undefined;
}

/**
 * Validates the shape of a NIP-47 connection URI.
 *
 * A well-formed NWC URI is:
 *   nostr+walletconnect://<wallet-pubkey>?relay=<wss-url>&secret=<hex-secret>[&...]
 *
 * We intentionally don't try to *use* the URI here — that would require a live
 * relay connection. This is just a cheap syntactic guard so we never persist
 * obvious garbage and never call @getalby/sdk with something it can't parse.
 */
export function validateNwcUri(uri: string): void {
    if (typeof uri !== 'string' || uri.trim().length === 0) {
        throw new Error('NWC URI is empty');
    }
    const trimmed = uri.trim();
    if (!trimmed.startsWith('nostr+walletconnect://') && !trimmed.startsWith('nostrwalletconnect://')) {
        throw new Error('NWC URI must use the nostr+walletconnect:// scheme');
    }

    // The hostname after the scheme is the wallet service pubkey (64-hex).
    // URL parsing is the simplest way to pull it + the query params out.
    let parsed: URL;
    try {
        // The URL class normalises the double-slash + hostname the same way it
        // would for http://, which is what we want.
        parsed = new URL(trimmed);
    } catch {
        throw new Error('NWC URI is not a valid URL');
    }

    const walletPubkey = parsed.hostname || parsed.pathname.replace(/^\/+/, '');
    if (!/^[0-9a-f]{64}$/i.test(walletPubkey)) {
        throw new Error('NWC URI is missing a valid wallet pubkey');
    }
    if (!parsed.searchParams.get('relay')) {
        throw new Error('NWC URI is missing the relay parameter');
    }
    const secret = parsed.searchParams.get('secret');
    if (!secret || !/^[0-9a-f]{64}$/i.test(secret)) {
        throw new Error('NWC URI is missing a valid secret parameter');
    }
}

/**
 * The wallet-service pubkey an NWC URI points at — i.e. *which wallet* this
 * connection talks to. Non-secret (it's the URI hostname; the spending
 * credential is the `secret` param, which this never reads).
 *
 * Recorded against a claim when a payout is attempted so we can later tell
 * whether the wallet currently connected is the same one that made the
 * attempt. Asking a *different* wallet whether it paid an invoice it has never
 * seen produces an answer that means nothing — see `reconcileApprovingClaim`.
 *
 * Returns undefined on any parse failure; callers treat that as "unknown
 * wallet" and fall back to human confirmation rather than guessing.
 */
export function walletPubkeyFromNwcUri(uri: string): string | undefined {
    try {
        const parsed = new URL(uri.trim());
        // Same extraction as validateNwcUri: hostname, with the pathname
        // fallback for parsers that don't treat the pubkey as a host.
        const pubkey = parsed.hostname || parsed.pathname.replace(/^\/+/, '');
        return /^[0-9a-f]{64}$/i.test(pubkey) ? pubkey.toLowerCase() : undefined;
    } catch {
        return undefined;
    }
}

/**
 * Non-secret, display-only summary of an NWC URI — for showing the creator
 * *which* wallet a bounty will draw from at creation time.
 *
 * Returns ONLY public fields: the relay hostname and the `lud16` lightning
 * address. It NEVER returns the `secret` (the spending credential). Params are
 * read by name, never by string position, so a reordered URI can't leak the
 * secret. Returns `{}` on any parse failure — callers degrade to a generic
 * label rather than erroring.
 */
export function summarizeNwcUri(uri: string): { relay?: string; lud16?: string } {
    try {
        const parsed = new URL(uri.trim());
        const relayRaw = parsed.searchParams.get('relay') ?? undefined; // first relay only
        const lud16 = parsed.searchParams.get('lud16') ?? undefined;
        let relay = relayRaw;
        // Prefer just the hostname (e.g. "relay.getalby.com") over the full
        // wss:// URL; fall back to the raw value if it doesn't parse.
        try {
            if (relayRaw) relay = new URL(relayRaw).hostname;
        } catch {
            /* keep relayRaw */
        }
        return { relay, lud16 };
    } catch {
        return {};
    }
}

/**
 * Resolves an LNURL / Lightning address → bolt11 invoice for `amountMsat`.
 *
 * Thin wrapper over the shared LNURL-pay implementation — see
 * `lib/lnurl-pay.ts` for the two-hop protocol and the amount cross-check that
 * stops a malicious LNURL server handing back a higher-value invoice.
 */
export async function lookupInvoiceFromLnurl(
    lnurl: string,
    amountMsat: number,
    comment?: string,
): Promise<string> {
    return fetchInvoiceForAmount(lnurl, amountMsat, comment);
}

/**
 * Pays `bolt11` from the creator's wallet via NIP-47.
 *
 * `encryptedUri` is the value stored in users.encrypted_nwc_uri — we only ever
 * decrypt it inside this function, and only long enough to hand it to the SDK.
 * If anything goes wrong (relay timeout, budget exceeded, wallet offline), we
 * throw with a normalized `NwcPayoutError` so the approve handler can map it
 * to a 502 + user-facing message without having to know about the SDK's error
 * taxonomy.
 *
 * `expectedAmountSats` is a defence-in-depth check — the bolt11 has already
 * been amount-validated by lookupInvoiceFromLnurl, but re-decoding here means
 * a caller that supplied a hand-built bolt11 can't sneak a mismatch past us.
 */
/**
 * Whether a failed payout attempt definitely moved no money.
 *
 *   'failed'  — the wallet never got the request, or explicitly declined it.
 *               No payment exists, so the claim lock can be released and the
 *               creator can safely retry.
 *   'unknown' — the request was published but we never got a usable answer
 *               (classically `Nip47ReplyTimeoutError`, which the relay also
 *               produces when it drops our reply subscription on a payment
 *               that settled fine). The wallet MAY have paid. Releasing the
 *               lock here would let a retry mint a second invoice and pay
 *               twice, so an 'unknown' keeps the claim locked until
 *               `lookupNwcPayment` can say what really happened.
 */
export type NwcPayoutOutcome = 'failed' | 'unknown';

export class NwcPayoutError extends Error {
    constructor(
        message: string,
        public readonly cause?: unknown,
        /** Defaults to the safe answer: assume money may have moved. */
        public readonly outcome: NwcPayoutOutcome = 'unknown',
    ) {
        super(message);
        this.name = 'NwcPayoutError';
    }
}

/**
 * Map an SDK error onto a payout outcome.
 *
 * Only the cases where we can *prove* the wallet never paid are 'failed'.
 * Everything else — including anything unrecognised — is 'unknown', because
 * the cost of guessing wrong is a double payment from the creator's wallet.
 */
export function classifyNwcError(err: unknown): NwcPayoutOutcome {
    // Never reached a relay: connection refused, or the publish itself failed
    // / timed out. The wallet cannot have seen the request.
    if (
        err instanceof Nip47NetworkError ||
        err instanceof Nip47PublishError ||
        err instanceof Nip47PublishTimeoutError
    ) {
        return 'failed';
    }
    // The wallet answered with a NIP-47 error code (insufficient balance,
    // budget exceeded, unauthorized, …) — an explicit decline, so nothing was
    // paid.
    if (err instanceof Nip47WalletError) {
        return 'failed';
    }
    // Nip47ReplyTimeoutError lands here, as does anything we don't recognise.
    return 'unknown';
}

/**
 * Best-effort payment hash for a bolt11, used to reconcile an attempt whose
 * outcome we never learned. Returns undefined if the invoice can't be decoded —
 * callers treat a missing hash as "not reconcilable", never as an error.
 */
export function paymentHashFromBolt11(bolt11: string): string | undefined {
    try {
        // `decode()` returns PaymentRequestObject & { tagsObject }, but the
        // package's own type declares only the former on the base type — and
        // the test suite mocks `decode` with a partial object. Read it
        // defensively rather than asserting a shape we can't rely on.
        const decoded = decodeBolt11(bolt11) as {
            tagsObject?: { payment_hash?: string };
            tags?: Array<{ tagName: string; data: unknown }>;
        };
        const fromObject = decoded.tagsObject?.payment_hash;
        if (typeof fromObject === 'string' && fromObject.length > 0) {
            return fromObject;
        }
        const fromTags = decoded.tags?.find((t) => t.tagName === 'payment_hash')?.data;
        return typeof fromTags === 'string' && fromTags.length > 0 ? fromTags : undefined;
    } catch {
        return undefined;
    }
}

/**
 * What the creator's wallet says about a payment we attempted.
 *
 * 'unknown' covers every case where the wallet couldn't tell us — the method
 * isn't implemented, the relay is down, the response was malformed. It is NOT
 * a synonym for "not paid": callers must keep the claim locked on 'unknown'.
 */
export type NwcPaymentLookup =
    | { state: 'settled'; preimage: string }
    | { state: 'failed' }
    | { state: 'pending' }
    | { state: 'unknown'; reason: string };

/** Reply budget for a lookup. Short — this is a read, not a settlement. */
const LOOKUP_INVOICE_REPLY_TIMEOUT_MS = 30_000;

/**
 * Ask the creator's wallet whether `paymentHash` was actually paid.
 *
 * This is the reconciliation half of the 'unknown' outcome above: after a
 * reply timeout we don't know if the sats left, and this is the only way to
 * find out without asking the creator to check their wallet by hand.
 *
 * Never throws — every failure path degrades to `{ state: 'unknown' }` so a
 * reconcile attempt can't itself break the approve flow.
 */
export async function lookupNwcPayment(
    encryptedUri: string,
    ref: { paymentHash?: string; bolt11?: string },
): Promise<NwcPaymentLookup> {
    // NIP-47 lookup_invoice accepts either identifier. Prefer the hash (a
    // wallet may normalise or re-encode the invoice string), fall back to the
    // bolt11 so an invoice we couldn't decode is still reconcilable.
    const request = ref.paymentHash
        ? { payment_hash: ref.paymentHash }
        : ref.bolt11
            ? { invoice: ref.bolt11 }
            : undefined;
    if (!request) {
        return { state: 'unknown', reason: 'No payment hash or invoice to look up' };
    }

    let uri: string;
    try {
        uri = decrypt(encryptedUri);
    } catch {
        return { state: 'unknown', reason: 'Failed to decrypt NWC URI' };
    }

    const client = new NWCClient({ nostrWalletConnectUrl: uri });
    try {
        const response = await executeNip47<{
            state?: string;
            preimage?: string;
            settled_at?: number;
        }>(client, 'lookup_invoice', request, LOOKUP_INVOICE_REPLY_TIMEOUT_MS);

        if (!response) {
            return { state: 'unknown', reason: 'Empty lookup_invoice response' };
        }

        // Newer wallets report an explicit `state`; older ones only set
        // `settled_at`. Accept either rather than assuming the modern shape.
        const state = response.state
            ?? (response.settled_at ? 'settled' : undefined);

        if (state === 'settled') {
            // A settled payment without a preimage shouldn't happen, but if it
            // does we still know money moved — surfacing 'unknown' would risk a
            // second payment, so treat the missing preimage as a marker.
            return { state: 'settled', preimage: response.preimage || 'unknown-preimage' };
        }
        if (state === 'failed') {
            return { state: 'failed' };
        }
        if (state === 'pending' || state === 'accepted') {
            return { state: 'pending' };
        }
        return { state: 'unknown', reason: `Unrecognised lookup_invoice state: ${state ?? 'none'}` };
    } catch (err) {
        // NOT_IMPLEMENTED (wallet doesn't support lookup_invoice), relay down,
        // reply timeout — all indistinguishable from "we still don't know".
        const message = err instanceof Error ? err.message : 'lookup_invoice failed';
        return { state: 'unknown', reason: message };
    } finally {
        try { client.close(); } catch { /* best-effort */ }
    }
}

export async function createNwcPayout(
    encryptedUri: string,
    bolt11: string,
    expectedAmountSats: number,
): Promise<{ preimage: string; feesPaidSats: number }> {
    // Re-check amount before we let the wallet anywhere near the invoice.
    const invoiceMsat = bolt11AmountMsat(decodeBolt11(bolt11));
    const invoiceSats = Number.isFinite(invoiceMsat) ? Math.round(invoiceMsat / 1000) : NaN;
    if (!Number.isFinite(invoiceSats) || invoiceSats !== expectedAmountSats) {
        // Rejected before the wallet is contacted — definitively no payment.
        throw new NwcPayoutError(
            `bolt11 amount ${invoiceSats} sats does not match expected ${expectedAmountSats} sats`,
            undefined,
            'failed',
        );
    }

    let uri: string;
    try {
        uri = decrypt(encryptedUri);
    } catch (err) {
        // Same — we never got as far as building a client.
        throw new NwcPayoutError('Failed to decrypt NWC URI', err, 'failed');
    }

    const client = new NWCClient({ nostrWalletConnectUrl: uri });
    try {
        // Alby SDK's `client.payInvoice()` hard-codes a 60s reply timeout
        // internally. Lightning routing on cold paths (private channels, MPP,
        // hops via Phoenix/Mutiny-style mobile wallets that need to wake up)
        // can easily exceed that, in which case the relay drops our reply
        // listener and the SDK throws Nip47ReplyTimeoutError — even though
        // the wallet ultimately settled. Bypass the wrapper and call the
        // underlying primitive directly with a generous budget. 180s is the
        // longest timeout we use anywhere; longer than that and the user is
        // better off seeing an error and retrying.
        const PAY_INVOICE_REPLY_TIMEOUT_MS = 180_000;
        const response = await executeNip47<{ preimage?: string; fees_paid?: number }>(
            client,
            'pay_invoice',
            { invoice: bolt11 },
            PAY_INVOICE_REPLY_TIMEOUT_MS,
        );

        if (!response || typeof response.preimage !== 'string') {
            // The wallet replied, but not with something we can record as proof
            // of payment. It may still have paid — leave this 'unknown' (the
            // default) so the caller reconciles instead of retrying blind.
            throw new NwcPayoutError('NWC wallet returned no preimage');
        }
        const feesPaidMsat = typeof response.fees_paid === 'number' ? response.fees_paid : 0;
        return {
            preimage: response.preimage,
            feesPaidSats: Math.round(feesPaidMsat / 1000),
        };
    } catch (err) {
        if (err instanceof NwcPayoutError) throw err;
        const message = err instanceof Error ? err.message : 'NWC payout failed';
        throw new NwcPayoutError(message, err, classifyNwcError(err));
    } finally {
        // `close()` tears down the relay subscription so we don't leak sockets.
        try { client.close(); } catch { /* best-effort */ }
    }
}

