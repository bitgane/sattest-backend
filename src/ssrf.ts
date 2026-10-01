/**
 * SSRF guard for outbound fetches whose target is derived from user input
 * (LNURLs / Lightning addresses and the `callback` URL an LNURL server hands
 * back). Without this, a caller can point the backend at internal hosts —
 * cloud metadata (169.254.169.254), loopback, RFC-1918 ranges — and use it as
 * a request proxy.
 *
 * Usage: call `await assertPublicHttpUrl(url)` immediately before fetching a
 * user-derived URL, and set `redirect: 'manual'` on that fetch so a 3xx can't
 * bounce past the check (defeating it via an open redirect to an internal IP).
 *
 * Residual risk: a pre-fetch DNS check can't fully stop DNS rebinding (the name
 * resolving to a public IP here and a private IP at fetch time). That requires
 * attacker-controlled authoritative DNS with a low TTL and winning a race —
 * a far higher bar than the trivial `http://10.0.0.1` / metadata cases this
 * blocks. Pinning the resolved IP through the socket would close it fully but
 * breaks TLS SNI/cert validation, so we accept the residual for now.
 *
 * Development is intentionally permissive (local LNbits / test LNURL servers
 * live on localhost), matching the rest of the backend's dev posture.
 */
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

function isDevelopment(): boolean {
    return process.env.NODE_ENV === 'development';
}

/**
 * True for any address we refuse to fetch: loopback, RFC-1918 private,
 * link-local (incl. cloud metadata), CGNAT, multicast/reserved, and the
 * unspecified address. IPv6 forms that embed an IPv4 address (mapped,
 * compatible, NAT64, 6to4) are judged by that IPv4 address. Anything we can't
 * parse as an IP is treated as blocked (fail closed).
 */
export function isBlockedAddress(addr: string): boolean {
    const family = isIP(addr);
    if (family === 4) return isBlockedIPv4(addr);
    if (family === 6) return isBlockedIPv6(addr);
    return true;
}

function isBlockedIPv4(addr: string): boolean {
    const parts = addr.split('.').map((p) => Number(p));
    if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
        return true;
    }
    const [a, b] = parts;
    if (a === 0) return true; // 0.0.0.0/8 "this host"
    if (a === 10) return true; // 10.0.0.0/8 private
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local (cloud metadata)
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
    if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a >= 224) return true; // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved
    return false;
}

/**
 * Classifies on the parsed 16-bit groups, never on the string. Text matching
 * missed the forms that matter: Node's URL parser rewrites
 * `[::ffff:169.254.169.254]` to `::ffff:a9fe:a9fe`, so a dotted-quad-only
 * check let the metadata address through, and `startsWith('fe80')` covered
 * only a sliver of the fe80::/10 link-local range.
 */
function isBlockedIPv6(raw: string): boolean {
    const h = parseIPv6(raw);
    if (!h) return true; // fail closed

    if (h.every((g) => g === 0)) return true; // :: unspecified
    if (h.slice(0, 7).every((g) => g === 0) && h[7] === 1) return true; // ::1 loopback

    // Forms that carry an IPv4 address the packet can actually reach: judge
    // them by that address, with the IPv4 rules.
    const embedded = embeddedIPv4(h);
    if (embedded) return isBlockedIPv4(embedded);
    // NAT64 local-use 64:ff9b:1::/48 (RFC 8215): the embedded IPv4 position
    // depends on the operator's prefix length, so it can't be decoded reliably.
    if (h[0] === 0x64 && h[1] === 0xff9b && h[2] === 1) return true;

    if ((h[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
    if ((h[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
    if ((h[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 site-local (deprecated)
    if ((h[0] & 0xff00) === 0xff00) return true; // ff00::/8 multicast
    return false;
}

/** The dotted-quad IPv4 address carried by an IPv6 address, if any. */
function embeddedIPv4(h: number[]): string | undefined {
    const zero = (from: number, to: number) => h.slice(from, to).every((g) => g === 0);
    const v4 = (hi: number, lo: number) => `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;

    if (zero(0, 5) && h[5] === 0xffff) return v4(h[6], h[7]); // ::ffff:0:0/96 IPv4-mapped
    if (zero(0, 4) && h[4] === 0xffff && h[5] === 0) return v4(h[6], h[7]); // ::ffff:0:0:0/96 IPv4-translated
    if (zero(0, 6)) return v4(h[6], h[7]); // ::/96 IPv4-compatible (deprecated)
    if (h[0] === 0x64 && h[1] === 0xff9b && zero(2, 6)) return v4(h[6], h[7]); // 64:ff9b::/96 NAT64
    if (h[0] === 0x2002) return v4(h[1], h[2]); // 2002::/16 6to4
    return undefined;
}

/**
 * Expands an IPv6 literal to its eight 16-bit groups, or undefined if it isn't
 * one. Handles `::` compression, a trailing dotted quad, upper case, and a
 * `%zone` suffix.
 */
function parseIPv6(raw: string): number[] | undefined {
    let addr = raw.toLowerCase();
    const zone = addr.indexOf('%');
    if (zone !== -1) addr = addr.slice(0, zone);

    // A trailing dotted quad (::ffff:1.2.3.4) becomes two hex groups.
    const dotted = addr.match(/^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (dotted) {
        const [a, b, c, d] = dotted.slice(2).map(Number);
        if ([a, b, c, d].some((n) => n > 255)) return undefined;
        addr = `${dotted[1]}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
    }

    const halves = addr.split('::');
    if (halves.length > 2) return undefined;
    const head = halves[0] ? halves[0].split(':') : [];
    const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    const gap = 8 - head.length - tail.length;
    if (halves.length === 2 ? gap < 1 : gap !== 0) return undefined;

    const groups = [...head, ...Array<string>(halves.length === 2 ? gap : 0).fill('0'), ...tail];
    if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return undefined;
    return groups.map((g) => parseInt(g, 16));
}

/**
 * Throws unless `rawUrl` is safe to fetch:
 *   - parses as a URL,
 *   - uses https (http is allowed only for localhost in development),
 *   - and (in production) does not resolve to a private/loopback/link-local IP.
 *
 * In development the IP check is skipped so a local LNbits/LNURL server works.
 */
export async function assertPublicHttpUrl(rawUrl: string): Promise<void> {
    let url: URL;
    try {
        url = new URL(rawUrl);
    } catch {
        throw new Error('Refusing to fetch an invalid URL');
    }

    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        throw new Error(`Refusing to fetch a non-http(s) URL (${url.protocol})`);
    }
    if (url.protocol === 'http:' && !isDevelopment()) {
        throw new Error('Refusing to fetch a plaintext http:// URL');
    }

    // Dev is permissive: local LNbits/test LNURL servers run on loopback.
    if (isDevelopment()) {
        return;
    }

    // Strip IPv6 brackets ("[::1]" → "::1") before classifying.
    const hostname = url.hostname.replace(/^\[/, '').replace(/\]$/, '');

    let addresses: string[];
    if (isIP(hostname)) {
        addresses = [hostname];
    } else {
        try {
            const records = await lookup(hostname, { all: true });
            addresses = records.map((r) => r.address);
        } catch {
            throw new Error('Refusing to fetch: could not resolve URL host');
        }
    }

    if (addresses.length === 0 || addresses.some(isBlockedAddress)) {
        throw new Error('Refusing to fetch a URL that resolves to a non-public address');
    }
}

/**
 * Reads a JSON response body with a hard byte cap.
 *
 * Every user-derived fetch in this codebase used to parse with `resp.json()`,
 * which buffers the ENTIRE body before parsing. The LNURL servers those fetches
 * hit are attacker-controlled (a claimant/refund caller picks the URL, and the
 * LNURL server picks the callback), so an uncapped parse let any Nostr key make
 * the backend allocate gigabytes and OOM the process. LUD-06/LUD-16 payloads
 * are a few hundred bytes; anything over the cap is an attack or a bug, not a
 * wallet.
 *
 * Works on both response body types used here: node-fetch's Node Readable and
 * undici's web ReadableStream (both are async-iterable on Node 22). Throws
 * rather than falling back to an uncapped parse when no bounded stream exists.
 */
export async function readJsonCapped(resp: { body: unknown }, maxBytes = 65_536): Promise<unknown> {
    const body = bodyStream(resp);
    if (!body) {
        throw new Error('Refusing to read a response body without a bounded stream');
    }
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const chunk of body) {
        total += chunk.length;
        if (total > maxBytes) {
            // Tear the stream down rather than just abandoning it — an
            // unconsumed body holds its socket open, so throwing alone would
            // let the same attacker exhaust connections instead of memory.
            releaseBody(body);
            throw new Error(`Response body exceeds ${maxBytes} bytes — refusing to parse`);
        }
        chunks.push(Buffer.from(chunk));
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

/**
 * Reads a response body as text with a hard byte cap, for ERROR paths.
 *
 * `readJsonCapped` only covers the success path — every `!resp.ok` branch was
 * still calling `.text()`, which buffers without limit. That left the cap
 * trivially bypassable: an attacker-controlled LNURL server answers with a
 * non-2xx status and an enormous body, and we buffer all of it while building
 * the error message. Same DoS, one status code away.
 *
 * Unlike the JSON reader this TRUNCATES instead of throwing, and returns ''
 * when there's no readable stream. An error path must still surface the status
 * code it was reporting; replacing one failure with a different, noisier one
 * would hide the actual problem. The default cap is small because this text
 * only ever lands in an error message or a log line.
 */
export async function readTextCapped(resp: { body: unknown }, maxBytes = 2048): Promise<string> {
    const body = bodyStream(resp);
    if (!body) {
        return '';
    }
    const chunks: Buffer[] = [];
    let total = 0;
    try {
        for await (const chunk of body) {
            const remaining = maxBytes - total;
            if (chunk.length >= remaining) {
                chunks.push(Buffer.from(chunk.subarray(0, remaining)));
                releaseBody(body);
                return `${Buffer.concat(chunks).toString('utf8')}… (truncated)`;
            }
            chunks.push(Buffer.from(chunk));
            total += chunk.length;
        }
    } catch {
        // Mid-read failure on an already-failing request — return whatever we
        // got rather than masking the original error with a read error.
    }
    return Buffer.concat(chunks).toString('utf8');
}

/**
 * The response body as an async-iterable byte stream, or undefined when it
 * isn't one. Covers both types in use here: node-fetch's Node Readable and
 * undici's web ReadableStream (both async-iterable on Node 22).
 */
function bodyStream(resp: { body: unknown }): AsyncIterable<Uint8Array> | undefined {
    const body = resp?.body as AsyncIterable<Uint8Array> | null | undefined;
    if (!body || typeof (body as never)[Symbol.asyncIterator] !== 'function') {
        return undefined;
    }
    return body;
}

/** Best-effort teardown so an abandoned body doesn't hold its socket open. */
function releaseBody(body: unknown): void {
    try {
        const b = body as { destroy?: () => void; cancel?: () => Promise<void> };
        if (typeof b.destroy === 'function') {
            b.destroy();
        } else if (typeof b.cancel === 'function') {
            void b.cancel();
        }
    } catch {
        /* best effort — teardown must never mask the caller's error */
    }
}
