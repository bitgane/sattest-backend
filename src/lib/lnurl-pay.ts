import { decode as decodeBolt11 } from 'bolt11';
import { assertPublicHttpUrl, readJsonCapped } from '../ssrf';
import { resolveLnurlEndpoint, bolt11AmountMsat } from './lnurl';

/**
 * The LNURL-pay protocol, in one place.
 *
 * Both payout paths need the same two-hop handshake before any money moves:
 *
 *   1. GET the LNURL (or `.well-known/lnurlp/<user>` for an LN address) →
 *      a JSON `payRequest` carrying a `callback` URL and min/max send bounds.
 *   2. GET `<callback>?amount=<msat>[&comment=…]` → `{ pr: <bolt11> }`.
 *
 * …followed by the check that actually matters: decode the returned invoice and
 * assert it asks for exactly the amount we requested. The LNURL server is
 * attacker-controllable and a wallet will pay whatever a bolt11 demands, so
 * without this cross-check a malicious server could hand back a higher-value
 * invoice and overspend the payer.
 *
 * This lived twice — `nwc.ts:lookupInvoiceFromLnurl` and inline inside
 * `lnbits.ts:createLnbitsPayout` — and the two copies had drifted (different
 * timeouts, different `Accept` headers, different error types) despite guarding
 * the same invariant. One implementation, one set of guarantees.
 */

/**
 * Network budget for each LNURL hop.
 *
 * Standardized on the custodial path's 20s rather than the NWC path's 10s. Both
 * hops happen *before* any claim lock is taken or any wallet is contacted, so a
 * slow lookup costs latency on a path that is going to fail anyway — whereas a
 * 10s cut-off rejects slow-but-valid LNURL servers that the custodial path has
 * always tolerated. Failing a legitimate payout is the worse error here.
 */
export const LNURL_HTTP_TIMEOUT_MS = 20_000;

/**
 * The HTTP surface these hops need.
 *
 * The two callers genuinely use different clients — `lnbits.ts` (and
 * `security.ts`) are on `node-fetch@2` while `nwc.ts` uses Node's built-in
 * `fetch`. Rather than silently migrating one of them as a side effect of this
 * dedup, the client is injected: each path keeps the exact HTTP behavior (and
 * test mocking surface) it already had. Typed structurally so both satisfy it.
 */
export type LnurlFetch = (
    url: string,
    init?: {
        method?: string;
        signal?: AbortSignal;
        redirect?: 'manual';
        headers?: Record<string, string>;
    },
) => Promise<{ ok: boolean; status: number; body: unknown }>;

export interface LnurlFetchOptions {
    /** Defaults to the global `fetch` (what the NWC path has always used). */
    fetchImpl?: LnurlFetch;
}

const defaultFetch: LnurlFetch = (url, init) =>
    fetch(url, init as RequestInit) as unknown as ReturnType<LnurlFetch>;

/** Shape of the LUD-06 `payRequest` document, as much of it as we rely on. */
export interface LnurlPayRequest {
    tag?: string;
    callback?: string;
    minSendable?: number;
    maxSendable?: number;
    commentAllowed?: number;
    status?: string;
    reason?: string;
}

/**
 * Hop 1 — resolve the LNURL and return its `payRequest` document.
 *
 * SSRF-guarded before the fetch, and `redirect: 'manual'` so a redirect can't
 * walk us to an address the guard already rejected.
 */
export async function fetchLnurlPayRequest(
    lnurl: string,
    opts: LnurlFetchOptions = {},
): Promise<LnurlPayRequest> {
    const doFetch = opts.fetchImpl ?? defaultFetch;
    const endpoint = await resolveLnurlEndpoint(lnurl.trim());
    await assertPublicHttpUrl(endpoint);

    const response = await doFetch(endpoint, {
        method: 'GET',
        signal: AbortSignal.timeout(LNURL_HTTP_TIMEOUT_MS),
        redirect: 'manual',
        headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
        throw new Error(`LNURL lookup failed: ${response.status}`);
    }

    const data = (await readJsonCapped(response)) as LnurlPayRequest;
    if (data.status === 'ERROR') {
        throw new Error(`LNURL error: ${data.reason || 'unknown'}`);
    }
    if (data.tag !== 'payRequest' || !data.callback) {
        throw new Error('LNURL did not return a payRequest');
    }
    return data;
}

/**
 * Hop 2 + the amount cross-check — mint a bolt11 for exactly `amountMsat`.
 *
 * `payRequest` is the document from hop 1; passing it in lets a caller that has
 * already resolved the endpoint (the custodial path validates bounds against its
 * own resolver first) avoid a second round-trip.
 */
export async function fetchInvoiceFromPayRequest(
    payRequest: LnurlPayRequest,
    amountMsat: number,
    comment?: string,
    opts: LnurlFetchOptions = {},
): Promise<string> {
    const doFetch = opts.fetchImpl ?? defaultFetch;
    if (
        typeof payRequest.minSendable !== 'number' ||
        typeof payRequest.maxSendable !== 'number' ||
        amountMsat < payRequest.minSendable ||
        amountMsat > payRequest.maxSendable
    ) {
        throw new Error(
            `Amount ${amountMsat} msat outside LNURL bounds [${payRequest.minSendable}, ${payRequest.maxSendable}]`,
        );
    }

    const callbackUrl = new URL(payRequest.callback as string);
    callbackUrl.searchParams.set('amount', String(amountMsat));
    if (comment && payRequest.commentAllowed && comment.length <= payRequest.commentAllowed) {
        callbackUrl.searchParams.set('comment', comment);
    }

    // The callback URL is supplied by the (attacker-controllable) LNURL server,
    // so it gets the same SSRF guard as the initial endpoint.
    await assertPublicHttpUrl(callbackUrl.toString());
    const response = await doFetch(callbackUrl.toString(), {
        method: 'GET',
        signal: AbortSignal.timeout(LNURL_HTTP_TIMEOUT_MS),
        redirect: 'manual',
        headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
        throw new Error(`LNURL callback failed: ${response.status}`);
    }

    const callbackData = (await readJsonCapped(response)) as {
        pr?: string;
        status?: string;
        reason?: string;
    };
    if (callbackData.status === 'ERROR') {
        throw new Error(`LNURL callback error: ${callbackData.reason || 'unknown'}`);
    }
    if (!callbackData.pr || typeof callbackData.pr !== 'string') {
        throw new Error('LNURL callback did not return a bolt11 invoice');
    }

    assertInvoiceAmount(callbackData.pr, amountMsat);
    return callbackData.pr;
}

/**
 * The integrity guard: the invoice must ask for exactly what we requested.
 *
 * Exported so a caller holding an invoice from elsewhere can apply the identical
 * check rather than re-deriving it.
 */
export function assertInvoiceAmount(bolt11: string, expectedMsat: number): void {
    const invoiceMsat = bolt11AmountMsat(decodeBolt11(bolt11));
    if (!Number.isFinite(invoiceMsat) || invoiceMsat !== expectedMsat) {
        throw new Error(
            `LNURL invoice amount ${invoiceMsat} msat does not match requested ${expectedMsat} msat`,
        );
    }
}

/**
 * Both hops end-to-end: LNURL → bolt11 for `amountMsat`, amount cross-checked.
 */
export async function fetchInvoiceForAmount(
    lnurl: string,
    amountMsat: number,
    comment?: string,
    opts: LnurlFetchOptions = {},
): Promise<string> {
    const payRequest = await fetchLnurlPayRequest(lnurl, opts);
    return fetchInvoiceFromPayRequest(payRequest, amountMsat, comment, opts);
}
