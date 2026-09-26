import fetch from 'node-fetch';
import { assertPublicHttpUrl, readJsonCapped, readTextCapped } from './ssrf';
import { paymentHashFromBolt11 } from './nwc';
import { resolveLnurlEndpoint } from './lib/lnurl';
import { config } from './config';
import {
    fetchInvoiceFromPayRequest,
    LNURL_HTTP_TIMEOUT_MS,
    type LnurlFetch,
} from './lib/lnurl-pay';

/**
 * Thrown when a payout request may have reached LNbits but the outcome never
 * came back (timeout/abort after send, non-2xx, unreadable success body).
 *
 * This is the custodial counterpart of NWC's `NwcPayoutError.outcome`:
 * anything thrown from the pay step means "we don't know whether money moved"
 * and MUST be reconciled by payment hash (`lookupLnbitsPayment`) before the
 * caller releases any lock. A blind retry mints a second payment.
 *
 * Errors thrown BEFORE the pay step (LNURL resolution, bounds checks, amount
 * cross-check) stay plain Errors — those provably moved no money.
 */
export class LnbitsPayoutError extends Error {
    constructor(
        message: string,
        /** Payment hash of the bolt11 we attempted — the reconciliation key. */
        public readonly paymentHash?: string,
    ) {
        super(message);
        this.name = 'LnbitsPayoutError';
    }
}

/**
 * Ask the LNbits payout wallet whether `paymentHash` exists.
 *
 *   'paid'      — a payment record exists; money moved (or is moving). Never
 *                 retry; finalize or hold.
 *   'not-found' — LNbits (404) proves no payment exists: safe to release the
 *                 caller's lock and retry.
 *   'unknown'   — LNbits unreachable/misconfigured: the safe side is "locked".
 *
 * Uses the ADMIN (payout wallet) key, not the invoice key: the outgoing
 * payment lives in the payout wallet.
 */
export async function lookupLnbitsPayment(
    paymentHash: string
): Promise<'paid' | 'not-found' | 'unknown'> {
    const lnbitsUrl = config.lnbits.url;
    const lnbitsApiKey = config.lnbits.adminKey;
    if (!lnbitsUrl || !lnbitsApiKey) return 'unknown';

    try {
        const response = await fetch(`${lnbitsUrl}/api/v1/payments/${paymentHash}`, {
            method: 'GET',
            signal: AbortSignal.timeout(10_000),
            headers: { 'X-Api-Key': lnbitsApiKey },
        });
        if (response.status === 404) return 'not-found';
        if (!response.ok) return 'unknown';
        // A record exists for this hash — treat as paid regardless of the
        // body's status field; the safe direction is "don't pay again".
        return 'paid';
    } catch {
        return 'unknown';
    }
}

interface CreateInvoiceResponse {
    payment_request: string;
    payment_hash: string;
}
interface CreatePayoutResponse {
    amount: number;
    checking_id: string;
    created_at: string;
    expiry: string;
    fee: number;
    labels: string[];
    memo: string;
    payment_hash: string;
    payment_request: string;
    status: string;
    time: string;
    updated_at: string;
}
interface CheckLnurlResponse {
    tag: string;
    callback: string;
    minSendable: number;
    maxSendable: number;
    metadata: string;
    // LUD-12 — optional, default 0 (no comments allowed)
    commentAllowed: number;
    // NIP-57 zap fields — only present when the endpoint supports Nostr zaps.
    // Plenty of LN-pay endpoints (Strike, Wallet of Satoshi, many self-hosted
    // setups) don't include these, so they have to be optional or our
    // validator rejects perfectly-valid LNURLs.
    allowsNostr: boolean;
    nostrPubkey?: string;
}

interface CheckLnbitsInvoiceResponse {
    paid: boolean;
}

export async function createLnbitsInvoice(
    lnbitsUrl: string,
    apiKey: string,
    amountSats: number,
    memo: string
): Promise<CreateInvoiceResponse> {
    const response = await fetch(`${lnbitsUrl}/api/v1/payments`, {
        method: 'POST',
        signal: AbortSignal.timeout(10_000),
        headers: {
            'Content-Type': 'application/json',
            'X-Api-Key': apiKey,
        },
        body: JSON.stringify({
            out: false,
            amount: amountSats,
            memo: memo,
        }),
    });

    if (!response.ok) {
        const errorText = await readTextCapped(response);
        throw new Error(`LNbits error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();

    return {
        payment_request: (data as CreateInvoiceResponse).payment_request,
        payment_hash: (data as CreateInvoiceResponse).payment_hash,
    };
}

export async function createLnbitsPayout(
    lnurl: string,
    amountSats: number,
    comment: string,
    internalMemo: string,
): Promise<CreatePayoutResponse> {
    const lnbitsUrl = config.lnbits.url;
    const lnbitsApiKey = config.lnbits.adminKey;

    // LNbits's `/api/v1/payments/lnurl` is not a "pay any LNURL" endpoint —
    // it requires pre-resolved `callback` + `description_hash` fields and
    // returns 400 without them. We run the LNURL-pay protocol ourselves and
    // hand LNbits a plain bolt11 via its standard /api/v1/payments endpoint.
    //
    // Steps 1-2 (resolve → bounds check → callback → amount cross-check) are the
    // shared implementation in lib/lnurl-pay.ts, which the NWC path also uses.
    // `checkValidLnurl` still does the resolution here because it returns the
    // richer LUD-06/NIP-57 shape this module's callers expect.
    const info = await checkValidLnurl(lnurl);

    const amountMsat = convertSatsToLnbitsParam(amountSats);
    const bolt11 = await fetchInvoiceFromPayRequest(
        {
            tag: info.tag,
            callback: info.callback,
            minSendable: info.minSendable,
            maxSendable: info.maxSendable,
            commentAllowed: info.commentAllowed,
        },
        amountMsat,
        comment,
        // Keep this path on node-fetch, the client the rest of this module (and
        // its test mocks) use.
        { fetchImpl: fetch as unknown as LnurlFetch },
    );

    // Step 3: pay the bolt11 via LNbits's standard payments endpoint.
    // Lightning routing can take 30+ seconds on cold paths — 60s budget
    // matches the NWC path. Anything past that surfaces as an explicit
    // LNbits error rather than silently aborting a payment that may still
    // settle (which would leave the claim stuck on our side).
    //
    // Every failure from here on is an LnbitsPayoutError carrying the bolt11's
    // payment hash: the request may have reached LNbits and committed before
    // we learned the outcome, so callers must reconcile before releasing any
    // lock. (Errors above — LNURL resolution, bounds, amount cross-check —
    // provably moved no money and stay plain Errors.)
    const payoutHash = paymentHashFromBolt11(bolt11);
    let payResp;
    try {
        payResp = await fetch(`${lnbitsUrl}/api/v1/payments`, {
            method: 'POST',
            signal: AbortSignal.timeout(60_000),
            headers: {
                'Content-Type': 'application/json',
                'X-Api-Key': lnbitsApiKey as string,
            },
            body: JSON.stringify({ out: true, bolt11, memo: internalMemo }),
        });
    } catch (err) {
        // Timeout/abort/network failure after the request may have been sent.
        throw new LnbitsPayoutError(
            `LNbits payout request failed: ${err instanceof Error ? err.message : String(err)}`,
            payoutHash,
        );
    }
    if (!payResp.ok) {
        const errorText = await readTextCapped(payResp);
        throw new LnbitsPayoutError(`LNbits payout error: ${payResp.status} - ${errorText}`, payoutHash);
    }
    let payData: Record<string, unknown>;
    try {
        payData = (await payResp.json()) as Record<string, unknown>;
    } catch {
        // The success body never arrived intact (abort mid-read, invalid JSON).
        // The payment may already be committed — this is an unknown outcome.
        throw new LnbitsPayoutError('Unreadable payment response from LNbits', payoutHash);
    }
    if (typeof payData !== 'object' || payData === null || !('payment_hash' in payData)) {
        throw new LnbitsPayoutError('Invalid payment response from LNbits', payoutHash);
    }

    // LNbits's POST /api/v1/payments returns a leaner shape than the legacy
    // /payments/lnurl endpoint did. Map what we get; fall back to safe
    // defaults for fields LNbits no longer surfaces here. Only `checking_id`
    // is actually consumed downstream (stored as refundCheckingId / payoutTxid)
    // but we keep the legacy fields so callers and tests don't break.
    return {
        checking_id: (payData.checking_id as string | undefined) ?? (payData.payment_hash as string),
        payment_hash: payData.payment_hash as string,
        payment_request: (payData.payment_request as string | undefined) ?? bolt11,
        amount: typeof payData.amount === 'number' ? payData.amount : amountMsat,
        fee: typeof payData.fee === 'number' ? payData.fee : 0,
        status: typeof payData.status === 'string' ? payData.status : 'pending',
        created_at: typeof payData.created_at === 'string' ? payData.created_at : new Date().toISOString(),
        updated_at: typeof payData.updated_at === 'string' ? payData.updated_at : new Date().toISOString(),
        expiry: typeof payData.expiry === 'string' ? payData.expiry : '',
        time: typeof payData.time === 'string' ? payData.time : '',
        memo: typeof payData.memo === 'string' ? payData.memo : internalMemo,
        labels: Array.isArray(payData.labels) ? (payData.labels as string[]) : [],
    };
}

export async function checkLnbitsInvoicePaid(
    paymentHash: string | undefined
): Promise<CheckLnbitsInvoiceResponse> {
    const lnbitsUrl = config.lnbits.url;
    const lnbitsApiKey = config.lnbits.invoiceKey;

    const lnbitsResponse = await fetch(`${lnbitsUrl}/api/v1/payments/${paymentHash}`, {
        method: 'GET',
        signal: AbortSignal.timeout(10_000),
        headers: {
            'X-Api-Key': lnbitsApiKey as string,
        },
    });

    if (!lnbitsResponse.ok) {
        const errorText = await readTextCapped(lnbitsResponse);
        throw new Error(`LNbits scan lnurl error: ${lnbitsResponse.status} - ${errorText}`);
    }

    const lnbitsData = await lnbitsResponse.json();

    if (typeof lnbitsData === 'object' && lnbitsData !== null && 'paid' in lnbitsData
    ) {
        return {
            paid: lnbitsData.paid as boolean,
        };
    }

    throw new Error('Invalid check invoice paid response from LNbits');
}


export async function checkValidLnurl(
    lnurl: string
): Promise<CheckLnurlResponse> {
    // LNURL-pay is a public protocol. We used to proxy this through LNbits's
    // `/api/v1/lnurlscan/<code>`, but that endpoint isn't available on every
    // LNbits deployment (Railway's instance returns 404, and several hosted
    // services have removed it). Hitting the LN-pay endpoint directly works
    // for any LNURL/LN-address and removes one moving part.
    const endpoint = await resolveLnurlEndpoint(lnurl);
    await assertPublicHttpUrl(endpoint);
    const response = await fetch(endpoint, {
        method: 'GET',
        signal: AbortSignal.timeout(LNURL_HTTP_TIMEOUT_MS),
        redirect: 'manual',
        headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
        const errorText = await readTextCapped(response);
        throw new Error(`LNURL endpoint error: ${response.status} - ${errorText}`);
    }

    const data = await readJsonCapped(response);

    // Some LN-pay servers (esp. those that don't fully follow LUD-06) return
    // `{ "status": "ERROR", "reason": "..." }` instead of the payRequest shape.
    // Surface the reason verbatim so the caller gets something actionable.
    if (typeof data === 'object' && data !== null && (data as Record<string, unknown>).status === 'ERROR') {
        const reason = (data as { reason?: string }).reason ?? 'unknown';
        throw new Error(`LNURL endpoint returned ERROR: ${reason}`);
    }

    // Required fields per LUD-06. Anything beyond this is optional and may be
    // absent for perfectly-valid LN-pay endpoints, so we don't gate on it.
    if (
        typeof data === 'object' && data !== null &&
        'tag' in data &&
        'callback' in data &&
        'minSendable' in data &&
        'maxSendable' in data &&
        'metadata' in data
    ) {
        const obj = data as Record<string, unknown>;
        return {
            tag: obj.tag as string,
            callback: obj.callback as string,
            minSendable: obj.minSendable as number,
            maxSendable: obj.maxSendable as number,
            metadata: obj.metadata as string,
            // LUD-12: missing means no comments allowed.
            commentAllowed: typeof obj.commentAllowed === 'number' ? obj.commentAllowed : 0,
            // NIP-57: missing means the endpoint doesn't support Nostr zaps.
            allowsNostr: obj.allowsNostr === true,
            nostrPubkey: typeof obj.nostrPubkey === 'string' ? obj.nostrPubkey : undefined,
        };
    }

    throw new Error(
        `LNURL endpoint response missing required LUD-06 fields. Got keys: ${
            typeof data === 'object' && data !== null ? Object.keys(data).join(',') : typeof data
        }`,
    );
}

export const convertSatsToLnbitsParam = (amountSats: number) => {
    return (amountSats * 1000);
}

