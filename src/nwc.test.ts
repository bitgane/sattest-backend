import {
    validateNwcUri,
    summarizeNwcUri,
    lookupInvoiceFromLnurl,
    createNwcPayout,
    lookupNwcPayment,
    paymentHashFromBolt11,
    NwcPayoutError,
} from './nwc';

// ----- Mocks ----------------------------------------------------------------

// bolt11 decode is used by both lookupInvoiceFromLnurl (amount cross-check)
// and createNwcPayout (defence-in-depth). Mock so tests don't need real
// invoice strings.
jest.mock('bolt11', () => ({
    decode: jest.fn(),
}));
import { decode as decodeBolt11 } from 'bolt11';
const mockDecode = decodeBolt11 as jest.MockedFunction<typeof decodeBolt11>;

// crypto.decrypt is called from createNwcPayout. Stub it to return a URI.
jest.mock('./crypto', () => ({
    decrypt: jest.fn((s: string) => s.replace(/^enc:/, '')),
}));

// @getalby/sdk's NWCClient — mock the whole module so we can observe calls and
// simulate success / failure. We mock `executeNip47Request` (not `payInvoice`)
// because the production code bypasses payInvoice() to pass a longer reply
// timeout — see nwc.ts for the full rationale.
const mockExecuteNip47Request = jest.fn();
const mockClose = jest.fn();
// Spread the real module so the Nip47*Error classes stay intact — the payout
// error classifier does `instanceof` against them, and stubbing them out would
// make these tests pass for the wrong reason.
jest.mock('@getalby/sdk', () => ({
    ...jest.requireActual('@getalby/sdk'),
    NWCClient: jest.fn().mockImplementation(() => ({
        executeNip47Request: mockExecuteNip47Request,
        close: mockClose,
    })),
}));
import {
    NWCClient,
    Nip47NetworkError,
    Nip47PublishError,
    Nip47PublishTimeoutError,
    Nip47ReplyTimeoutError,
    Nip47WalletError,
} from '@getalby/sdk';
const mockNwcClientCtor = NWCClient as unknown as jest.Mock;

// global.fetch — nwc.ts uses the built-in fetch, not node-fetch.
const mockFetch = jest.fn();
(global as any).fetch = mockFetch;

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
    } as any;
}
function mockErrorResp(status: number) {
    return {
        ok: false,
        status,
        body: (async function* () {
            yield Buffer.from('err');
        })(),
        json: jest.fn().mockResolvedValue({}),
        text: jest.fn().mockResolvedValue('err'),
    } as any;
}

beforeEach(() => {
    jest.clearAllMocks();
    // Keep the SSRF guard permissive here (it only does DNS/IP checks in
    // production) so these suites run the real LNURL flow against public test
    // domains offline. Production behavior is covered in ssrf.test.ts.
    process.env.NODE_ENV = 'development';
});

// ---------------------------------------------------------------------------
describe('validateNwcUri', () => {
    const goodWallet = 'a'.repeat(64);
    const goodSecret = 'b'.repeat(64);
    const goodRelay = 'wss://relay.example.com';

    it('accepts a well-formed URI', () => {
        const uri = `nostr+walletconnect://${goodWallet}?relay=${encodeURIComponent(goodRelay)}&secret=${goodSecret}`;
        expect(() => validateNwcUri(uri)).not.toThrow();
    });

    it('rejects an empty string', () => {
        expect(() => validateNwcUri('')).toThrow(/empty/);
    });

    it('rejects the wrong scheme', () => {
        expect(() => validateNwcUri(`https://${goodWallet}?relay=${goodRelay}&secret=${goodSecret}`))
            .toThrow(/scheme/);
    });

    it('rejects a malformed wallet pubkey', () => {
        expect(() => validateNwcUri(`nostr+walletconnect://nothex?relay=${goodRelay}&secret=${goodSecret}`))
            .toThrow(/wallet pubkey/);
    });

    it('rejects when the relay param is missing', () => {
        expect(() => validateNwcUri(`nostr+walletconnect://${goodWallet}?secret=${goodSecret}`))
            .toThrow(/relay/);
    });

    it('rejects when the secret param is missing or malformed', () => {
        expect(() => validateNwcUri(`nostr+walletconnect://${goodWallet}?relay=${goodRelay}`))
            .toThrow(/secret/);
        expect(() => validateNwcUri(`nostr+walletconnect://${goodWallet}?relay=${goodRelay}&secret=short`))
            .toThrow(/secret/);
    });
});

// ---------------------------------------------------------------------------
describe('summarizeNwcUri', () => {
    const wallet = 'a'.repeat(64);
    const secret = 'b'.repeat(64);

    it('returns the relay hostname and lud16 for a full URI', () => {
        const uri = `nostr+walletconnect://${wallet}?relay=${encodeURIComponent('wss://relay.getalby.com/v1')}&secret=${secret}&lud16=${encodeURIComponent('alice@getalby.com')}`;
        expect(summarizeNwcUri(uri)).toEqual({
            relay: 'relay.getalby.com',
            lud16: 'alice@getalby.com',
        });
    });

    it('returns relay only when lud16 is absent', () => {
        const uri = `nostr+walletconnect://${wallet}?relay=${encodeURIComponent('wss://relay.example.com')}&secret=${secret}`;
        const summary = summarizeNwcUri(uri);
        expect(summary.relay).toBe('relay.example.com');
        expect(summary.lud16).toBeUndefined();
    });

    it('keeps the raw relay value if it is not a parseable URL', () => {
        const uri = `nostr+walletconnect://${wallet}?relay=not-a-url&secret=${secret}`;
        expect(summarizeNwcUri(uri).relay).toBe('not-a-url');
    });

    it('returns {} for malformed input', () => {
        expect(summarizeNwcUri('')).toEqual({});
        expect(summarizeNwcUri('not a uri at all')).toEqual({});
    });

    it('NEVER returns the secret — even when secret is the last query param', () => {
        const uri = `nostr+walletconnect://${wallet}?relay=${encodeURIComponent('wss://relay.example.com')}&lud16=${encodeURIComponent('bob@example.com')}&secret=${secret}`;
        const summary = summarizeNwcUri(uri);
        // Reading by param name (not "after the last =") means the trailing
        // secret can't leak into the relay/lud16 fields.
        expect(JSON.stringify(summary)).not.toContain(secret);
        expect(summary).toEqual({ relay: 'relay.example.com', lud16: 'bob@example.com' });
    });
});

// ---------------------------------------------------------------------------
describe('lookupInvoiceFromLnurl', () => {
    const callback = 'https://wallet.example.com/lnurl/callback/xyz';

    it('returns the bolt11 invoice when amounts match', async () => {
        mockFetch
            .mockResolvedValueOnce(mockOkJson({
                tag: 'payRequest',
                callback,
                minSendable: 1_000,
                maxSendable: 10_000_000,
                commentAllowed: 0,
            }))
            .mockResolvedValueOnce(mockOkJson({ pr: 'lnbc1fake' }));
        mockDecode.mockReturnValue({ millisatoshis: '1000000', satoshis: 1000 } as any);

        const bolt11 = await lookupInvoiceFromLnurl('alice@example.com', 1_000_000);

        expect(bolt11).toBe('lnbc1fake');
        expect(mockFetch).toHaveBeenCalledTimes(2);
        // Second call carries the msat amount.
        const secondUrl = mockFetch.mock.calls[1][0] as URL;
        expect(secondUrl.toString()).toContain('amount=1000000');
    });

    it('rejects when the amount falls outside min/max sendable bounds', async () => {
        mockFetch.mockResolvedValueOnce(mockOkJson({
            tag: 'payRequest',
            callback,
            minSendable: 1_000_000,
            maxSendable: 5_000_000,
            commentAllowed: 0,
        }));

        await expect(lookupInvoiceFromLnurl('alice@example.com', 500)).rejects.toThrow(/outside/);
        expect(mockFetch).toHaveBeenCalledTimes(1); // never reached callback
    });

    it('rejects when the callback returns no `pr`', async () => {
        mockFetch
            .mockResolvedValueOnce(mockOkJson({
                tag: 'payRequest',
                callback,
                minSendable: 1_000,
                maxSendable: 10_000_000,
                commentAllowed: 0,
            }))
            .mockResolvedValueOnce(mockOkJson({ status: 'ERROR', reason: 'wallet offline' }));

        await expect(lookupInvoiceFromLnurl('alice@example.com', 1_000_000)).rejects.toThrow(/wallet offline/);
    });

    it('rejects when the returned invoice amount does not match requested', async () => {
        mockFetch
            .mockResolvedValueOnce(mockOkJson({
                tag: 'payRequest',
                callback,
                minSendable: 1_000,
                maxSendable: 10_000_000,
                commentAllowed: 0,
            }))
            .mockResolvedValueOnce(mockOkJson({ pr: 'lnbc1fake' }));
        mockDecode.mockReturnValue({ millisatoshis: '2000000', satoshis: 2000 } as any);

        await expect(lookupInvoiceFromLnurl('alice@example.com', 1_000_000)).rejects.toThrow(/does not match/);
    });

    it('rejects when the first hop returns a non-payRequest response', async () => {
        mockFetch.mockResolvedValueOnce(mockOkJson({ tag: 'withdrawRequest' }));
        await expect(lookupInvoiceFromLnurl('alice@example.com', 1000)).rejects.toThrow(/payRequest/);
    });

    it('propagates upstream HTTP failures', async () => {
        mockFetch.mockResolvedValueOnce(mockErrorResp(500));
        await expect(lookupInvoiceFromLnurl('alice@example.com', 1000)).rejects.toThrow(/500/);
    });
});

// ---------------------------------------------------------------------------
describe('createNwcPayout', () => {
    const encryptedUri = 'enc:nostr+walletconnect://abc';
    const bolt11 = 'lnbc1fake';

    it('pays the invoice and returns the preimage', async () => {
        mockDecode.mockReturnValue({ millisatoshis: '1000000', satoshis: 1000 } as any);
        mockExecuteNip47Request.mockResolvedValue({ preimage: 'deadbeef', fees_paid: 2000 });

        const result = await createNwcPayout(encryptedUri, bolt11, 1000);

        expect(result).toEqual({ preimage: 'deadbeef', feesPaidSats: 2 });
        // Client constructed with the decrypted URI, not the ciphertext.
        expect(mockNwcClientCtor).toHaveBeenCalledWith({
            nostrWalletConnectUrl: 'nostr+walletconnect://abc',
        });
        // We bypass client.payInvoice() so we can pass a longer reply timeout.
        // Method name + request body should still match the standard pay_invoice contract.
        expect(mockExecuteNip47Request).toHaveBeenCalledWith(
            'pay_invoice',
            { invoice: bolt11 },
            expect.any(Function),
            expect.objectContaining({ replyTimeout: expect.any(Number) }),
        );
        expect(mockClose).toHaveBeenCalled();
    });

    it('passes a reply timeout >= 60s (the SDK default) so cold Lightning paths complete', async () => {
        // Regression: SDK's payInvoice() hard-codes 60s. We override to a longer
        // budget; pin it so a future refactor can't silently revert.
        mockDecode.mockReturnValue({ millisatoshis: '1000000', satoshis: 1000 } as any);
        mockExecuteNip47Request.mockResolvedValue({ preimage: 'deadbeef' });

        await createNwcPayout(encryptedUri, bolt11, 1000);

        const opts = mockExecuteNip47Request.mock.calls[0][3] as { replyTimeout: number };
        expect(opts.replyTimeout).toBeGreaterThanOrEqual(60_000);
    });

    it('rejects when the bolt11 amount does not match expected', async () => {
        mockDecode.mockReturnValue({ millisatoshis: '5000000', satoshis: 5000 } as any);

        await expect(createNwcPayout(encryptedUri, bolt11, 1000))
            .rejects.toBeInstanceOf(NwcPayoutError);
        expect(mockExecuteNip47Request).not.toHaveBeenCalled();
    });

    it('wraps wallet-side failures in NwcPayoutError', async () => {
        mockDecode.mockReturnValue({ millisatoshis: '1000000', satoshis: 1000 } as any);
        mockExecuteNip47Request.mockRejectedValue(new Error('budget exceeded'));

        await expect(createNwcPayout(encryptedUri, bolt11, 1000))
            .rejects.toThrow(/budget exceeded/);
        // Socket is still torn down on error.
        expect(mockClose).toHaveBeenCalled();
    });

    it('throws when the wallet returns no preimage', async () => {
        mockDecode.mockReturnValue({ millisatoshis: '1000000', satoshis: 1000 } as any);
        mockExecuteNip47Request.mockResolvedValue({});

        await expect(createNwcPayout(encryptedUri, bolt11, 1000))
            .rejects.toThrow(/preimage/);
    });

    // ── Outcome classification ────────────────────────────────────────────
    //
    // This is the double-spend guard. The approve handler releases the claim
    // lock only for 'failed'; a wrong 'failed' here lets a retry pay a second
    // invoice for a payment that actually settled.
    describe('outcome classification', () => {
        beforeEach(() => {
            mockDecode.mockReturnValue({ millisatoshis: '1000000', satoshis: 1000 } as any);
        });

        async function outcomeOf(thrown: unknown): Promise<string> {
            mockExecuteNip47Request.mockRejectedValue(thrown);
            try {
                await createNwcPayout(encryptedUri, bolt11, 1000);
                throw new Error('expected createNwcPayout to reject');
            } catch (err) {
                return (err as NwcPayoutError).outcome;
            }
        }

        it('marks a reply timeout as unknown — the wallet may have paid', async () => {
            // The exact error behind the "reply timeout: event <id>" report:
            // the request was published, the reply never arrived. A relay that
            // simply dropped our subscription looks identical to a payment that
            // never happened, so we must not claim it failed.
            expect(await outcomeOf(new Nip47ReplyTimeoutError('reply timeout: event abc', 'INTERNAL')))
                .toBe('unknown');
        });

        it('marks a publish failure as failed — the wallet never saw it', async () => {
            expect(await outcomeOf(new Nip47PublishError('failed to publish', 'INTERNAL')))
                .toBe('failed');
            expect(await outcomeOf(new Nip47PublishTimeoutError('publish timeout', 'INTERNAL')))
                .toBe('failed');
        });

        it('marks a relay connection failure as failed', async () => {
            expect(await outcomeOf(new Nip47NetworkError('Failed to connect to relay', 'OTHER')))
                .toBe('failed');
        });

        it('marks an explicit wallet rejection as failed', async () => {
            // e.g. INSUFFICIENT_BALANCE / QUOTA_EXCEEDED — the wallet answered
            // and declined, so no payment exists.
            expect(await outcomeOf(new Nip47WalletError('insufficient balance', 'INSUFFICIENT_BALANCE')))
                .toBe('failed');
        });

        it('treats an unrecognised error as unknown (fails safe)', async () => {
            expect(await outcomeOf(new Error('something we have never seen'))).toBe('unknown');
        });

        it('marks pre-flight rejections as failed (nothing was ever sent)', async () => {
            // Amount mismatch is caught before the wallet is contacted.
            mockDecode.mockReturnValue({ millisatoshis: '5000000', satoshis: 5000 } as any);
            try {
                await createNwcPayout(encryptedUri, bolt11, 1000);
                throw new Error('expected rejection');
            } catch (err) {
                expect((err as NwcPayoutError).outcome).toBe('failed');
            }
            expect(mockExecuteNip47Request).not.toHaveBeenCalled();
        });
    });
});

// ---------------------------------------------------------------------------
describe('paymentHashFromBolt11', () => {
    it('reads the hash from tagsObject', () => {
        mockDecode.mockReturnValue({ tagsObject: { payment_hash: 'hash-abc' } } as any);
        expect(paymentHashFromBolt11('lnbc1fake')).toBe('hash-abc');
    });

    it('falls back to the tags array', () => {
        mockDecode.mockReturnValue({
            tags: [{ tagName: 'payment_hash', data: 'hash-from-tags' }],
        } as any);
        expect(paymentHashFromBolt11('lnbc1fake')).toBe('hash-from-tags');
    });

    it('returns undefined for an undecodable invoice rather than throwing', () => {
        mockDecode.mockImplementation(() => { throw new Error('bad invoice'); });
        expect(paymentHashFromBolt11('garbage')).toBeUndefined();
    });

    it('returns undefined when no payment hash is present', () => {
        mockDecode.mockReturnValue({ millisatoshis: '1000' } as any);
        expect(paymentHashFromBolt11('lnbc1fake')).toBeUndefined();
    });
});

// ---------------------------------------------------------------------------
describe('lookupNwcPayment', () => {
    const encryptedUri = 'enc:nostr+walletconnect://abc';

    it('reports a settled payment with its preimage', async () => {
        mockExecuteNip47Request.mockResolvedValue({ state: 'settled', preimage: 'pre-abc' });

        const result = await lookupNwcPayment(encryptedUri, { paymentHash: 'hash-xyz' });

        expect(result).toEqual({ state: 'settled', preimage: 'pre-abc' });
        expect(mockExecuteNip47Request).toHaveBeenCalledWith(
            'lookup_invoice',
            { payment_hash: 'hash-xyz' },
            expect.any(Function),
            expect.objectContaining({ replyTimeout: expect.any(Number) }),
        );
        expect(mockClose).toHaveBeenCalled();
    });

    it('treats a legacy settled_at response as settled', async () => {
        // Wallets predating the `state` field only report settled_at.
        mockExecuteNip47Request.mockResolvedValue({ settled_at: 1700000000, preimage: 'pre-old' });

        expect(await lookupNwcPayment(encryptedUri, { paymentHash: 'h' }))
            .toEqual({ state: 'settled', preimage: 'pre-old' });
    });

    it('reports a failed payment', async () => {
        mockExecuteNip47Request.mockResolvedValue({ state: 'failed' });
        expect(await lookupNwcPayment(encryptedUri, { paymentHash: 'h' })).toEqual({ state: 'failed' });
    });

    it('reports an in-flight payment as pending', async () => {
        mockExecuteNip47Request.mockResolvedValue({ state: 'accepted' });
        expect(await lookupNwcPayment(encryptedUri, { paymentHash: 'h' })).toEqual({ state: 'pending' });
    });

    it('falls back to the invoice when no payment hash is known', async () => {
        mockExecuteNip47Request.mockResolvedValue({ state: 'failed' });

        await lookupNwcPayment(encryptedUri, { bolt11: 'lnbc1fake' });

        expect(mockExecuteNip47Request).toHaveBeenCalledWith(
            'lookup_invoice',
            { invoice: 'lnbc1fake' },
            expect.any(Function),
            expect.anything(),
        );
    });

    it('returns unknown (never throws) when the wallet cannot answer', async () => {
        // A wallet without lookup_invoice support, a dead relay, a second
        // timeout — all indistinguishable, and none of them mean "not paid".
        mockExecuteNip47Request.mockRejectedValue(new Error('NOT_IMPLEMENTED'));

        const result = await lookupNwcPayment(encryptedUri, { paymentHash: 'h' });

        expect(result.state).toBe('unknown');
        expect(mockClose).toHaveBeenCalled();
    });

    it('returns unknown when given nothing to look up', async () => {
        expect((await lookupNwcPayment(encryptedUri, {})).state).toBe('unknown');
        expect(mockExecuteNip47Request).not.toHaveBeenCalled();
    });
});
