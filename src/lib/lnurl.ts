/**
 * Shared Lightning helpers for the LNURL-pay payout flow, factored out of
 * lnbits.ts and nwc.ts so the custodial and NWC paths resolve LNURL endpoints
 * and cross-check invoice amounts through one implementation.
 */

/**
 * Resolve an LN address ("alice@domain.tld") or bech32 LNURL to the https
 * LNURL-pay endpoint. Input is trimmed, so both the custodial and NWC callers
 * accept the same formats identically.
 */
export async function resolveLnurlEndpoint(input: string): Promise<string> {
    const trimmed = input.trim();
    // LN address: alice@domain.tld → https://domain.tld/.well-known/lnurlp/alice
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(trimmed)) {
        const [name, domain] = trimmed.split('@');
        return `https://${domain}/.well-known/lnurlp/${encodeURIComponent(name)}`;
    }
    // Raw https URL — use as-is.
    if (/^https?:\/\//i.test(trimmed)) {
        return trimmed;
    }
    // bech32-encoded LNURL: decode to the embedded https URL. bolt11 pulls in
    // bech32@1.x, which exposes `decode`/`fromWords` as top-level named exports.
    if (/^lnurl1/i.test(trimmed)) {
        const bech32 = await import('bech32');
        const decoded = bech32.decode(trimmed.toLowerCase(), 2000);
        const bytes = bech32.fromWords(decoded.words);
        return Buffer.from(bytes).toString('utf8');
    }
    throw new Error(
        `Unrecognised LNURL format: expected LN address (alice@domain.tld), lnurl1... bech32, or https:// URL`,
    );
}

/**
 * Amount in millisatoshis from a decoded bolt11 invoice. bolt11 returns
 * `millisatoshis` as a string or `satoshis` as a number; prefer the msat form.
 * Returns NaN when neither is present — callers guard with `Number.isFinite`.
 */
export function bolt11AmountMsat(
    decoded: { millisatoshis?: string | null; satoshis?: number | null }
): number {
    return decoded.millisatoshis
        ? Number(decoded.millisatoshis)
        : typeof decoded.satoshis === 'number'
            ? decoded.satoshis * 1000
            : NaN;
}
