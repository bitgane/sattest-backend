import fetch from 'node-fetch';
import {
    createLnbitsInvoice,
    createLnbitsPayout,
    checkLnbitsInvoicePaid,
    checkValidLnurl,
    convertSatsToLnbitsParam,
    lookupLnbitsPayment,
    LnbitsPayoutError,
} from './lnbits';

jest.mock('node-fetch');
const mockFetch = fetch as jest.MockedFunction<typeof fetch>;

// bolt11 decode is used by createLnbitsPayout to cross-check that the invoice
// returned by the LNURL callback asks for exactly the amount we requested.
// Mock it so tests don't need real invoice strings (same approach as nwc.test.ts).
jest.mock('bolt11', () => ({
    decode: jest.fn(),
}));
import { decode as decodeBolt11 } from 'bolt11';
const mockDecode = decodeBolt11 as jest.MockedFunction<typeof decodeBolt11>;

function mockOkJson(data: unknown) {
    const text = JSON.stringify(data);
    return {
        ok: true,
        status: 200,
        // readJsonCapped consumes the body as an async-iterable byte stream —
        // provide one so the real capped parse path is exercised.
        body: (async function* () {
            yield Buffer.from(text);
        })(),
        json: jest.fn().mockResolvedValue(data),
        text: jest.fn().mockResolvedValue(text),
    } as any;
}

function mockErrorResponse(status: number, body = 'error') {
    return {
        ok: false,
        status,
        body: (async function* () {
            yield Buffer.from(body);
        })(),
        json: jest.fn().mockResolvedValue({}),
        text: jest.fn().mockResolvedValue(body),
    } as any;
}

beforeEach(() => {
    jest.clearAllMocks();
    // The SSRF guard (assertPublicHttpUrl) is permissive in development and only
    // does DNS/IP checks in production. Keep these suites in dev so they exercise
    // the real LNURL flow against public test domains without hitting the network.
    // The guard's production behavior is covered directly in ssrf.test.ts, plus
    // the prod-rejection cases below.
    process.env.NODE_ENV = 'development';
    process.env.LNBITS_URL = 'http://lnbits.test';
    process.env.LNBITS_API_KEY = 'test-api-key';
    process.env.LNBITS_INVOICE_KEY = 'test-invoice-key';
});

// ---------------------------------------------------------------------------
describe('convertSatsToLnbitsParam', () => {
    it('converts sats to millisats (×1000)', () => {
        expect(convertSatsToLnbitsParam(1)).toBe(1000);
        expect(convertSatsToLnbitsParam(100)).toBe(100000);
        expect(convertSatsToLnbitsParam(21000000)).toBe(21000000000);
    });
});

// ---------------------------------------------------------------------------
describe('createLnbitsInvoice', () => {
    it('POSTs to /api/v1/payments with correct headers and body', async () => {
        mockFetch.mockResolvedValue(mockOkJson({ payment_request: 'lnbc1', payment_hash: 'hash1' }));

        await createLnbitsInvoice('http://lnbits.test', 'mykey', 500, 'test memo');

        expect(mockFetch).toHaveBeenCalledWith(
            'http://lnbits.test/api/v1/payments',
            expect.objectContaining({
                method: 'POST',
                headers: expect.objectContaining({ 'X-Api-Key': 'mykey' }),
            })
        );
        const body = JSON.parse((mockFetch.mock.calls[0][1] as any).body);
        expect(body.out).toBe(false);
        expect(body.amount).toBe(500);
        expect(body.memo).toBe('test memo');
    });

    it('returns payment_request and payment_hash', async () => {
        mockFetch.mockResolvedValue(mockOkJson({ payment_request: 'lnbc_pay', payment_hash: 'abc123' }));

        const result = await createLnbitsInvoice('http://lnbits.test', 'key', 1000, 'memo');

        expect(result.payment_request).toBe('lnbc_pay');
        expect(result.payment_hash).toBe('abc123');
    });

    it('throws with status code when LNbits returns a non-ok response', async () => {
        mockFetch.mockResolvedValue(mockErrorResponse(403, 'forbidden'));

        await expect(createLnbitsInvoice('http://lnbits.test', 'key', 1000, 'memo'))
            .rejects.toThrow('LNbits error: 403');
    });
});

// ---------------------------------------------------------------------------
describe('checkLnbitsInvoicePaid', () => {
    it('GETs /api/v1/payments/:hash with invoice key', async () => {
        mockFetch.mockResolvedValue(mockOkJson({ paid: true }));
        const hash = 'a'.repeat(64);

        await checkLnbitsInvoicePaid(hash);

        expect(mockFetch).toHaveBeenCalledWith(
            `http://lnbits.test/api/v1/payments/${hash}`,
            expect.objectContaining({
                method: 'GET',
                headers: expect.objectContaining({ 'X-Api-Key': 'test-invoice-key' }),
            })
        );
    });

    it('returns paid: true when invoice is paid', async () => {
        mockFetch.mockResolvedValue(mockOkJson({ paid: true }));

        const result = await checkLnbitsInvoicePaid('hash');
        expect(result.paid).toBe(true);
    });

    it('returns paid: false when invoice is unpaid', async () => {
        mockFetch.mockResolvedValue(mockOkJson({ paid: false }));

        const result = await checkLnbitsInvoicePaid('hash');
        expect(result.paid).toBe(false);
    });

    it('throws with status code on non-ok response', async () => {
        mockFetch.mockResolvedValue(mockErrorResponse(404, 'not found'));

        await expect(checkLnbitsInvoicePaid('hash')).rejects.toThrow('404');
    });

    it('throws if response is missing the paid field', async () => {
        mockFetch.mockResolvedValue(mockOkJson({ something: 'else' }));

        await expect(checkLnbitsInvoicePaid('hash'))
            .rejects.toThrow('Invalid check invoice paid response from LNbits');
    });
});

// ---------------------------------------------------------------------------
describe('checkValidLnurl', () => {
    const validResponse = {
        tag: 'payRequest',
        callback: 'https://example.com/callback',
        minSendable: 1000,
        maxSendable: 10000000,
        metadata: '[]',
        commentAllowed: 0,
        allowsNostr: false,
        nostrPubkey: '',
    };

    it('GETs the .well-known/lnurlp endpoint directly for a Lightning address', async () => {
        // LNURL-pay is a public protocol; we no longer proxy this through
        // LNbits's /lnurlscan (which 404s on Railway's instance). LN address
        // alice@domain.tld resolves to https://domain.tld/.well-known/lnurlp/alice.
        mockFetch.mockResolvedValue(mockOkJson(validResponse));

        await checkValidLnurl('  bitgane@primal.net  ');

        const [url, init] = mockFetch.mock.calls[0];
        expect(String(url)).toBe('https://primal.net/.well-known/lnurlp/bitgane');
        expect((init as any).method).toBe('GET');
        expect((init as any).body).toBeUndefined();
        // No LNbits API key — we hit the user's LN-pay endpoint directly.
        expect((init as any).headers).not.toHaveProperty('X-Api-Key');
        expect((init as any).headers).toMatchObject({ Accept: 'application/json' });
    });

    it('passes a raw https URL through to fetch unchanged', async () => {
        mockFetch.mockResolvedValue(mockOkJson(validResponse));

        await checkValidLnurl('https://example.com/.well-known/lnurlp/x');

        const [url] = mockFetch.mock.calls[0];
        expect(String(url)).toBe('https://example.com/.well-known/lnurlp/x');
    });

    it('rejects an unrecognised LNURL format with a clear error', async () => {
        await expect(checkValidLnurl('not-an-lnurl'))
            .rejects.toThrow(/Unrecognised LNURL format/);
    });

    it('returns all lnurl response fields', async () => {
        mockFetch.mockResolvedValue(mockOkJson(validResponse));

        const result = await checkValidLnurl('bitgane@primal.net');

        expect(result.minSendable).toBe(1000);
        expect(result.maxSendable).toBe(10000000);
        expect(result.tag).toBe('payRequest');
        expect(result.callback).toBe('https://example.com/callback');
    });

    it('throws with status code on non-ok response from the LN-pay endpoint', async () => {
        mockFetch.mockResolvedValue(mockErrorResponse(404, 'not found'));

        await expect(checkValidLnurl('bitgane@primal.net'))
            .rejects.toThrow(/LNURL endpoint error: 404/);
    });

    it('caps an oversized ERROR body — a non-2xx must not bypass the read cap', async () => {
        // The bypass this closes: the success path was capped, but the
        // `!response.ok` branch called `.text()` unbounded. An attacker-chosen
        // LNURL host just answers 500 with a huge body and we buffer all of it.
        // Any Nostr key can reach here via /lnurl/limits or /bounties/:id/claim.
        mockFetch.mockResolvedValue(mockErrorResponse(500, 'A'.repeat(5_000_000)));

        const err = await checkValidLnurl('bitgane@primal.net').catch((e) => e);

        expect(String(err)).toMatch(/LNURL endpoint error: 500/);
        // The status still surfaces, but the attacker's body does not land in
        // the error message (and so never reaches the logs either).
        expect(String(err).length).toBeLessThan(4000);
        expect(String(err)).toMatch(/truncated/);
    });

    it('surfaces LUD-06 ERROR-status responses with the reason', async () => {
        // Some LN-pay servers respond 200 with { status: "ERROR", reason: "..." }
        // instead of the payRequest shape. Make sure the reason isn't lost.
        mockFetch.mockResolvedValue(mockOkJson({ status: 'ERROR', reason: 'user not found' }));

        await expect(checkValidLnurl('bitgane@primal.net'))
            .rejects.toThrow(/LNURL endpoint returned ERROR: user not found/);
    });

    it('throws if response is missing required LUD-06 fields', async () => {
        // Has `tag` but missing callback/minSendable/maxSendable/metadata.
        mockFetch.mockResolvedValue(mockOkJson({ tag: 'payRequest' }));

        await expect(checkValidLnurl('bitgane@primal.net'))
            .rejects.toThrow(/missing required LUD-06 fields/);
    });

    it('accepts a response without NIP-57 zap fields (allowsNostr / nostrPubkey)', async () => {
        // Many LN-pay endpoints (Strike, Wallet of Satoshi, plenty of
        // self-hosted setups) omit these. Refusing them broke refund/claim
        // flows for those users.
        const noZapResponse = {
            tag: 'payRequest',
            callback: 'https://example.com/cb',
            minSendable: 1000,
            maxSendable: 10000000,
            metadata: '[]',
            // commentAllowed, allowsNostr, nostrPubkey all absent.
        };
        mockFetch.mockResolvedValue(mockOkJson(noZapResponse));

        const result = await checkValidLnurl('bitgane@primal.net');
        expect(result.callback).toBe('https://example.com/cb');
        expect(result.allowsNostr).toBe(false);   // safe default
        expect(result.nostrPubkey).toBeUndefined();
        expect(result.commentAllowed).toBe(0);     // safe default
    });

    it('passes allowsNostr through when the endpoint sets it true', async () => {
        mockFetch.mockResolvedValue(mockOkJson({
            tag: 'payRequest',
            callback: 'https://example.com/cb',
            minSendable: 1000,
            maxSendable: 10000000,
            metadata: '[]',
            allowsNostr: true,
            nostrPubkey: 'a'.repeat(64),
        }));

        const result = await checkValidLnurl('bitgane@primal.net');
        expect(result.allowsNostr).toBe(true);
        expect(result.nostrPubkey).toBe('a'.repeat(64));
    });
});

// ---------------------------------------------------------------------------
describe('createLnbitsPayout', () => {
    // The new flow does three fetches in sequence:
    //   1. GET https://<domain>/.well-known/lnurlp/<user>  (resolve LNURL-pay)
    //   2. GET <callback>?amount=<msat>                    (mint bolt11)
    //   3. POST <lnbits>/api/v1/payments  { out: true, bolt11 }  (pay it)
    const lnurlInfo = {
        tag: 'payRequest',
        callback: 'https://example.com/cb',
        minSendable: 1000,
        maxSendable: 100_000_000,
        metadata: '[]',
        commentAllowed: 200,
    };
    const callbackResponse = { pr: 'lnbc1bolt11invoice' };
    const lnbitsPaymentResponse = {
        payment_hash: 'phash123',
        checking_id: 'check123',
        payment_request: 'lnbc1bolt11invoice',
    };

    /** Stub the three sequential fetches the new flow needs. */
    function mockHappyPath() {
        mockFetch
            .mockResolvedValueOnce(mockOkJson(lnurlInfo))           // resolve
            .mockResolvedValueOnce(mockOkJson(callbackResponse))    // callback → bolt11
            .mockResolvedValueOnce(mockOkJson(lnbitsPaymentResponse)); // pay
    }

    beforeEach(() => {
        // Default: the returned invoice asks for exactly the requested amount
        // (all happy-path cases below use 1000 sats = 1_000_000 msat). Tests
        // that need a mismatch override this.
        mockDecode.mockReturnValue({ millisatoshis: '1000000', satoshis: 1000 } as any);
    });

    it('runs the LNURL-pay flow and POSTs the bolt11 to LNbits /api/v1/payments', async () => {
        mockHappyPath();

        await createLnbitsPayout('bitgane@primal.net', 1000, 'memo', 'internal');

        // Three fetches: resolve, callback, pay.
        expect(mockFetch).toHaveBeenCalledTimes(3);

        // 1. Direct LNURL-pay resolution (no LNbits in the path).
        expect(String(mockFetch.mock.calls[0][0]))
            .toBe('https://primal.net/.well-known/lnurlp/bitgane');

        // 2. Callback with amount in millisats; memo went into the comment slot
        //    because the endpoint allowed it.
        const cbUrl = new URL(String(mockFetch.mock.calls[1][0]));
        expect(cbUrl.origin + cbUrl.pathname).toBe('https://example.com/cb');
        expect(cbUrl.searchParams.get('amount')).toBe('1000000'); // 1000 sats × 1000
        expect(cbUrl.searchParams.get('comment')).toBe('memo');

        // 3. POST to LNbits with { out: true, bolt11 } — the shape LNbits's
        //    standard payments endpoint actually accepts. Crucial regression:
        //    the old shape POSTed { amount, lnurl, unit } to /payments/lnurl
        //    and got 400 ("description_hash" / "callback" required).
        const [payUrl, payInit] = mockFetch.mock.calls[2];
        expect(String(payUrl)).toBe('http://lnbits.test/api/v1/payments');
        const body = JSON.parse((payInit as any).body);
        expect(body).toEqual({ out: true, bolt11: 'lnbc1bolt11invoice', memo: 'internal' });
        expect((payInit as any).headers).toMatchObject({ 'X-Api-Key': 'test-api-key' });
    });

    it('omits the comment when the endpoint disallows it', async () => {
        mockFetch
            .mockResolvedValueOnce(mockOkJson({ ...lnurlInfo, commentAllowed: 0 }))
            .mockResolvedValueOnce(mockOkJson(callbackResponse))
            .mockResolvedValueOnce(mockOkJson(lnbitsPaymentResponse));

        await createLnbitsPayout('bitgane@primal.net', 1000, 'memo', '');

        const cbUrl = new URL(String(mockFetch.mock.calls[1][0]));
        expect(cbUrl.searchParams.get('comment')).toBeNull();
    });

    it('rejects when the amount is outside the LNURL sendable range', async () => {
        mockFetch.mockResolvedValueOnce(mockOkJson({ ...lnurlInfo, minSendable: 5_000_000 }));

        await expect(createLnbitsPayout('bitgane@primal.net', 1000, 'memo', ''))
            .rejects.toThrow(/outside LNURL bounds/);
        // Only the resolve fetch fired — never reached the callback/pay steps.
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('surfaces a callback ERROR status with the reason', async () => {
        mockFetch
            .mockResolvedValueOnce(mockOkJson(lnurlInfo))
            .mockResolvedValueOnce(mockOkJson({ status: 'ERROR', reason: 'wallet offline' }));

        await expect(createLnbitsPayout('bitgane@primal.net', 1000, 'memo', ''))
            .rejects.toThrow(/LNURL callback error: wallet offline/);
    });

    it('rejects when the callback returns no bolt11 invoice', async () => {
        mockFetch
            .mockResolvedValueOnce(mockOkJson(lnurlInfo))
            .mockResolvedValueOnce(mockOkJson({})); // no `pr` field

        await expect(createLnbitsPayout('bitgane@primal.net', 1000, 'memo', ''))
            .rejects.toThrow(/did not return a bolt11 invoice/);
    });

    it('refuses to pay when the returned invoice amount exceeds the requested amount', async () => {
        // A malicious LNURL server declares wide send bounds, then returns a
        // bolt11 for far more than requested. Without the amount cross-check
        // LNbits would pay it in full and drain the payout wallet.
        mockFetch
            .mockResolvedValueOnce(mockOkJson(lnurlInfo))        // resolve
            .mockResolvedValueOnce(mockOkJson(callbackResponse)); // callback → bolt11
        // Requested 1000 sats (1_000_000 msat) but the invoice asks for 50_000 sats.
        mockDecode.mockReturnValue({ millisatoshis: '50000000', satoshis: 50000 } as any);

        await expect(createLnbitsPayout('bitgane@primal.net', 1000, 'memo', ''))
            .rejects.toThrow(/does not match requested/);

        // The LNbits pay POST must never fire — only resolve + callback ran.
        expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('throws with status code on LNbits payment failure', async () => {
        mockFetch
            .mockResolvedValueOnce(mockOkJson(lnurlInfo))
            .mockResolvedValueOnce(mockOkJson(callbackResponse))
            .mockResolvedValueOnce(mockErrorResponse(500, 'server error'));

        await expect(createLnbitsPayout('bitgane@primal.net', 1000, 'memo', ''))
            .rejects.toThrow(/LNbits payout error: 500/);
    });

    it('returns checking_id from LNbits and bolt11 as payment_request', async () => {
        mockHappyPath();

        const result = await createLnbitsPayout('bitgane@primal.net', 1000, 'memo', '');

        expect(result.checking_id).toBe('check123');
        expect(result.payment_hash).toBe('phash123');
        expect(result.payment_request).toBe('lnbc1bolt11invoice');
        // Status defaults to 'pending' when LNbits doesn't include it — the
        // value is informational only; downstream code reads checking_id.
        expect(result.status).toBeDefined();
    });

    it('falls back to payment_hash as checking_id when LNbits omits it', async () => {
        mockFetch
            .mockResolvedValueOnce(mockOkJson(lnurlInfo))
            .mockResolvedValueOnce(mockOkJson(callbackResponse))
            .mockResolvedValueOnce(mockOkJson({ payment_hash: 'phash-only' }));

        const result = await createLnbitsPayout('bitgane@primal.net', 1000, 'memo', '');
        expect(result.checking_id).toBe('phash-only');
    });

    it('throws when LNbits returns a payment without payment_hash', async () => {
        mockFetch
            .mockResolvedValueOnce(mockOkJson(lnurlInfo))
            .mockResolvedValueOnce(mockOkJson(callbackResponse))
            .mockResolvedValueOnce(mockOkJson({ status: 'pending' })); // no payment_hash

        await expect(createLnbitsPayout('bitgane@primal.net', 1000, 'memo', ''))
            .rejects.toThrow(/Invalid payment response from LNbits/);
    });
});

// ---------------------------------------------------------------------------
describe('createLnbitsPayout — payout outcome classification', () => {
    const lnurlInfo = {
        tag: 'payRequest',
        callback: 'https://example.com/cb',
        minSendable: 1000,
        maxSendable: 100_000_000,
        metadata: '[]',
        commentAllowed: 0,
    };
    const callbackResponse = { pr: 'lnbc1bolt11invoice' };

    beforeEach(() => {
        // Invoice matches the requested amount AND carries a decodable payment
        // hash, so the pay-step error can carry it for reconciliation.
        mockDecode.mockReturnValue({
            millisatoshis: '1000000',
            satoshis: 1000,
            tagsObject: { payment_hash: 'phash-abc' },
        } as any);
    });

    it('pay-step failures throw LnbitsPayoutError carrying the payment hash', async () => {
        mockFetch
            .mockResolvedValueOnce(mockOkJson(lnurlInfo))
            .mockResolvedValueOnce(mockOkJson(callbackResponse))
            .mockResolvedValueOnce(mockErrorResponse(500, 'server error'));

        const err = await createLnbitsPayout('bitgane@primal.net', 1000, 'memo', '')
            .catch((e) => e);
        expect(err).toBeInstanceOf(LnbitsPayoutError);
        expect((err as LnbitsPayoutError).paymentHash).toBe('phash-abc');
    });

    it('a pay-request network failure (abort/timeout) is an unknown outcome too', async () => {
        mockFetch
            .mockResolvedValueOnce(mockOkJson(lnurlInfo))
            .mockResolvedValueOnce(mockOkJson(callbackResponse))
            .mockRejectedValueOnce(new Error('The operation was aborted'));

        const err = await createLnbitsPayout('bitgane@primal.net', 1000, 'memo', '')
            .catch((e) => e);
        expect(err).toBeInstanceOf(LnbitsPayoutError);
        expect((err as LnbitsPayoutError).paymentHash).toBe('phash-abc');
    });

    it('pre-pay failures (LNURL resolution) stay plain Errors — provably unpaid', async () => {
        mockFetch.mockResolvedValueOnce(mockErrorResponse(500, 'server error'));

        const err = await createLnbitsPayout('bitgane@primal.net', 1000, 'memo', '')
            .catch((e) => e);
        expect(err).not.toBeInstanceOf(LnbitsPayoutError);
        expect(String(err)).toMatch(/LNURL endpoint error: 500/);
    });
});

// ---------------------------------------------------------------------------
describe('lookupLnbitsPayment', () => {
    it('returns paid when LNbits has a record for the hash', async () => {
        mockFetch.mockResolvedValueOnce(mockOkJson({ payment_hash: 'phash', paid: true }));
        await expect(lookupLnbitsPayment('phash')).resolves.toBe('paid');
        // Admin (payout wallet) key, not the invoice key.
        expect(mockFetch).toHaveBeenCalledWith(
            'http://lnbits.test/api/v1/payments/phash',
            expect.objectContaining({ headers: { 'X-Api-Key': 'test-api-key' } }),
        );
    });

    it('returns not-found on a 404', async () => {
        mockFetch.mockResolvedValueOnce(mockErrorResponse(404, 'not found'));
        await expect(lookupLnbitsPayment('phash')).resolves.toBe('not-found');
    });

    it('returns unknown on a non-404 error status', async () => {
        mockFetch.mockResolvedValueOnce(mockErrorResponse(500, 'boom'));
        await expect(lookupLnbitsPayment('phash')).resolves.toBe('unknown');
    });

    it('returns unknown on a network failure', async () => {
        mockFetch.mockRejectedValueOnce(new Error('connection refused'));
        await expect(lookupLnbitsPayment('phash')).resolves.toBe('unknown');
    });

    it('returns unknown when LNbits env is unset', async () => {
        delete process.env.LNBITS_API_KEY;
        await expect(lookupLnbitsPayment('phash')).resolves.toBe('unknown');
        expect(mockFetch).not.toHaveBeenCalled();
    });
});

// ---------------------------------------------------------------------------
describe('checkValidLnurl — response body cap', () => {
    it('rejects an oversized LNURL response body instead of buffering it', async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            body: (async function* () {
                yield Buffer.alloc(70_000, 65); // 70 KB > 64 KB cap
            })(),
            text: jest.fn(),
        } as any);

        await expect(checkValidLnurl('alice@example.com')).rejects.toThrow(/exceeds/);
    });
});

// ---------------------------------------------------------------------------
// SSRF guard wiring — in production, user-supplied LNURLs that point at private
// hosts or use plaintext http must be rejected *before* any fetch fires. Uses
// literal IPs so no DNS/network is involved.
describe('checkValidLnurl — SSRF guard (production)', () => {
    const realNodeEnv = process.env.NODE_ENV;
    beforeEach(() => {
        process.env.NODE_ENV = 'production';
    });
    afterEach(() => {
        process.env.NODE_ENV = realNodeEnv;
    });

    it('rejects a raw URL that resolves to a private/loopback IP without fetching', async () => {
        await expect(checkValidLnurl('https://10.0.0.1/.well-known/lnurlp/x'))
            .rejects.toThrow(/non-public address/);
        expect(mockFetch).not.toHaveBeenCalled();
    });

    it('rejects the link-local cloud-metadata address without fetching', async () => {
        await expect(checkValidLnurl('https://169.254.169.254/latest/meta-data/'))
            .rejects.toThrow(/non-public address/);
        expect(mockFetch).not.toHaveBeenCalled();
    });

    it('rejects plaintext http:// in production without fetching', async () => {
        await expect(checkValidLnurl('http://example.com/.well-known/lnurlp/x'))
            .rejects.toThrow(/plaintext http/);
        expect(mockFetch).not.toHaveBeenCalled();
    });
});

