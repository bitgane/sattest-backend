import request from 'supertest';

// ── Fixed test identifiers ──────────────────────────────────────────────────
const TEST_PUBKEY = 'a'.repeat(64);
const OTHER_PUBKEY = 'b'.repeat(64);
const BOUNTY_ID = '11111111-1111-4111-8111-111111111111';
const VALID_HASH = 'c'.repeat(64);
const CLAIM_ID = '22222222-2222-4222-8222-222222222222';
// Identity of the claimant on the default fixture claim. Distinct from
// TEST_PUBKEY (the authenticated caller / bounty creator) so a test that
// confuses payer with payee fails loudly.
const CLAIMANT_PUBKEY = 'd'.repeat(64);
// The NWC wallet-service pubkey a payout was sent from. Reconciliation only
// trusts a lookup when the currently connected wallet matches the one recorded
// against the claim, so tests distinguish this from a replacement wallet.
const WALLET_PUBKEY = 'e'.repeat(64);
const OTHER_WALLET_PUBKEY = 'f'.repeat(64);
// The unauthenticated listing endpoints now require a repo scope, so every
// listing call in this suite has to carry one.
const REPO_SLUG = 'acme/widgets';
const OTHER_CLAIM_ID = '33333333-3333-4333-8333-333333333333';

// ── Mock: express-rate-limit — no-op so the suite isn't throttled by its own
// repeated calls to lnbitsLimiter-protected routes.
jest.mock('express-rate-limit', () => ({
    __esModule: true,
    default: jest.fn(() => (_req: any, _res: any, next: any) => next()),
}));

// ── Mock: auth middleware — both variants always pass, inject TEST_PUBKEY ──
jest.mock('./middleware/auth', () => {
    const passThrough = (req: any, _res: any, next: any) => {
        req.nostrPubkey = 'a'.repeat(64);
        next();
    };
    return {
        nostrAuth: jest.fn(passThrough),
        // Write routes use moneyAuth (tighter window) — same pass-through here.
        moneyAuth: jest.fn(passThrough),
    };
});

// ── Mock: ./middleware/nonce — issuance stubbed; consumption is exercised in
// auth.test.ts against the real implementation, not through the app mock. ──
jest.mock('./middleware/nonce', () => ({
    issueNonce: jest.fn(() => ({ nonce: 'test-nonce-value', expiresAt: Date.now() + 120_000 })),
}));

// ── Mock: ./db ─────────────────────────────────────────────────────────────
jest.mock('./db', () => ({
    pool: { query: jest.fn().mockResolvedValue({}) },
    db: {
        query: {
            bounties: { findFirst: jest.fn(), findMany: jest.fn() },
            claims: { findFirst: jest.fn(), findMany: jest.fn() },
            users: { findFirst: jest.fn() },
        },
        insert: jest.fn(),
        update: jest.fn(),
        select: jest.fn(),
    },
}));

// ── Mock: ./lnbits ─────────────────────────────────────────────────────────
// LnbitsPayoutError mirrors the real class: thrown from the pay step with the
// bolt11's payment hash, so the handler can reconcile before releasing a lock.
class FakeLnbitsPayoutError extends Error {
    constructor(message: string, public readonly paymentHash?: string) {
        super(message);
        this.name = 'LnbitsPayoutError';
    }
}
jest.mock('./lnbits', () => ({
    createLnbitsInvoice: jest.fn(),
    checkLnbitsInvoicePaid: jest.fn(),
    checkValidLnurl: jest.fn(),
    createLnbitsPayout: jest.fn(),
    convertSatsToLnbitsParam: jest.fn((sats: number) => sats * 1000),
    lookupLnbitsPayment: jest.fn(),
    LnbitsPayoutError: FakeLnbitsPayoutError,
}));

// ── Mock: ./crypto — deterministic encrypt/decrypt for tests ────────────────
jest.mock('./crypto', () => ({
    encrypt: jest.fn((v: string) => `enc:${v}`),
    decrypt: jest.fn((v: string) => v.replace(/^enc:/, '')),
}));

// ── Mock: ./security — guards pass unless an individual test overrides ─────
// Route tests exercise handler behavior; guard internals are covered separately.
// `custodialBountiesEnabled` keeps the real env-reading behavior so tests can
// flip ALLOW_CUSTODIAL_BOUNTIES via process.env in beforeEach hooks.
jest.mock('./security', () => ({
    evaluatePayoutGuards: jest.fn().mockResolvedValue({ ok: true }),
    payoutsEnabled: jest.fn().mockReturnValue(true),
    payoutBalanceLooksSane: jest.fn().mockResolvedValue(true),
    alertAnomaly: jest.fn().mockResolvedValue(undefined),
    isLargePayout: jest.fn().mockReturnValue(false),
    custodialBountiesEnabled: jest.fn(() => {
        const raw = (process.env.ALLOW_CUSTODIAL_BOUNTIES ?? 'false').toLowerCase();
        return raw === 'true' || raw === '1' || raw === 'yes';
    }),
}));

// ── Mock: ./nwc — URI validation + LNURL lookup + payout all stubbed ───────
class FakeNwcPayoutError extends Error {
    // Mirrors the real class: `outcome` tells the approve handler whether the
    // payout provably didn't happen ('failed' → release the claim lock) or
    // might have ('unknown' → keep it locked). Defaults to 'unknown' exactly
    // like production, so a test that forgets to pass it gets the safe path.
    constructor(
        message: string,
        public readonly cause?: unknown,
        public readonly outcome: 'failed' | 'unknown' = 'unknown',
    ) {
        super(message);
        this.name = 'NwcPayoutError';
    }
}
jest.mock('./nwc', () => ({
    validateNwcUri: jest.fn(),
    // Use the real (pure, URL-parsing) summarizer so the nwc-status handler
    // test exercises the actual relay/lud16 extraction, not a stub.
    summarizeNwcUri: jest.requireActual('./nwc').summarizeNwcUri,
    lookupInvoiceFromLnurl: jest.fn(),
    createNwcPayout: jest.fn(),
    // Reconciliation surface for claims stuck in `approving`.
    lookupNwcPayment: jest.fn(),
    paymentHashFromBolt11: jest.fn(() => 'payment-hash-abc'),
    // Identity of the wallet a payout was sent from. Reconciliation refuses to
    // trust a lookup unless this matches what was recorded with the lock, so
    // tests that want the lookup path must keep the two in agreement.
    walletPubkeyFromNwcUri: jest.fn(() => WALLET_PUBKEY),
    NwcPayoutError: FakeNwcPayoutError,
}));

// ── Imports (after mocks are registered) ───────────────────────────────────
import { app, warnOnInsecureConfig } from './index';
import { db } from './db';
import * as lnbits from './lnbits';
import * as nwc from './nwc';
import * as security from './security';
import { issueNonce } from './middleware/nonce';

const mockDb = db as any;
const mockLnbits = lnbits as jest.Mocked<typeof lnbits>;
const mockNwc = nwc as jest.Mocked<typeof nwc>;
const mockIssueNonce = issueNonce as jest.Mock;

// Tests construct pay-step failures with the mocked class — index.ts's
// `instanceof LnbitsPayoutError` checks resolve against this same constructor.
const FakeLnbitsPayoutErrorCtor = lnbits.LnbitsPayoutError as unknown as {
    new (message: string, paymentHash?: string): Error & { paymentHash?: string };
};

const WALLET_ID = 'wallet-id-test';
const WALLET_NAME = `sattest-${TEST_PUBKEY.slice(0, 12)}`;
const MOCK_INKEY = 'invoice-key-test';
const MOCK_ADMINKEY = 'admin-key-test';

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Wire up the insert chain: insert().values().returning() and insert().values().onConflictDoUpdate() → resolvedValue */
function mockInsert(returnValue: any[] = []) {
    (mockDb.insert as jest.Mock).mockReturnValue({
        values: jest.fn().mockReturnValue({
            returning: jest.fn().mockResolvedValue(returnValue),
            onConflictDoUpdate: jest.fn().mockResolvedValue(returnValue),
        }),
    });
}

function makeUser(overrides: Record<string, any> = {}) {
    return {
        nostrPubkey: TEST_PUBKEY,
        walletId: WALLET_ID,
        walletName: WALLET_NAME,
        encryptedAdminKey: `enc:${MOCK_ADMINKEY}`,
        encryptedInvoiceKey: `enc:${MOCK_INKEY}`,
        createdAt: new Date(),
        updatedAt: new Date(),
        ...overrides,
    };
}

/**
 * Wire up the two `select({n}).from().where()` counts the claim handler runs:
 * claims filed in the rolling window, then open claims overall. Resolved in
 * call order, so a test can set them independently.
 */
function mockClaimCounts(recentInWindow: number, openTotal: number) {
    const chain = (n: number) => ({
        from: jest.fn().mockReturnValue({
            where: jest.fn().mockResolvedValue([{ n }]),
        }),
    });
    // Reset first: the suite-wide default queues a pair too, and `Once` values
    // stack — without this a test's own counts would sit behind the default's
    // and never be consumed.
    (mockDb.select as jest.Mock)
        .mockReset()
        .mockReturnValueOnce(chain(recentInWindow))
        .mockReturnValueOnce(chain(openTotal));
}

/** Wire up update().set().where() — optionally with .returning() */
function mockUpdate(returnValue: any[] = []) {
    (mockDb.update as jest.Mock).mockReturnValue({
        set: jest.fn().mockReturnValue({
            where: jest.fn().mockReturnValue({
                returning: jest.fn().mockResolvedValue(returnValue),
            }),
        }),
    });
}

function makeBounty(overrides: Record<string, any> = {}) {
    return {
        id: BOUNTY_ID,
        testId: 'test-123',
        creatorId: TEST_PUBKEY,
        amountSats: 1000,
        invoicePaid: false,
        invoice: 'lnbc_invoice',
        paymentHash: VALID_HASH,
        memo: 'Test bounty',
        active: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        claims: [],
        ...overrides,
    };
}

function makeClaim(overrides: Record<string, any> = {}) {
    return {
        id: CLAIM_ID,
        bountyId: BOUNTY_ID,
        claimantLnurl: 'lnurl1test',
        claimantPubkey: CLAIMANT_PUBKEY,
        claimedAt: new Date(),
        status: 'pending',
        payoutTxid: null,
        approvedBy: null,
        approvedAt: null,
        ...overrides,
    };
}

/**
 * Mint a real, signed bolt11 for `sats` with `payment_hash = VALID_HASH`.
 *
 * The create-bounty handler decodes client-supplied invoices for real (amount
 * cross-check + hash derivation), so these tests need genuine invoices rather
 * than placeholder strings. Throwaway key — this signs nothing that leaves the
 * test process.
 */
function makeBolt11(sats: number, paymentHash: string = VALID_HASH): string {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const bolt11 = require('bolt11');
    const throwawayKey = '0001020304050607080900010203040506070809000102030405060708090102';
    return bolt11.sign(
        bolt11.encode({
            satoshis: sats,
            tags: [
                { tagName: 'payment_hash', data: paymentHash },
                { tagName: 'description', data: 'test bounty' },
            ],
        }),
        throwawayKey,
    ).paymentRequest;
}

/**
 * Collect the bound parameter values out of a Drizzle `where` clause.
 *
 * The clause is a nested SQL object with circular table references, so it
 * can't be JSON-stringified — walk it and pull the `Param` leaves instead.
 * Used to assert that a query is genuinely constrained to a value, rather
 * than that a handler merely ran.
 */
function whereParams(node: any, out: unknown[] = []): unknown[] {
    if (!node || typeof node !== 'object') return out;
    if (Array.isArray(node)) {
        node.forEach((n) => whereParams(n, out));
        return out;
    }
    if (node.constructor?.name === 'Param') out.push(node.value);
    if (node.queryChunks) whereParams(node.queryChunks, out);
    return out;
}

beforeEach(() => {
    jest.clearAllMocks();
    process.env.LNBITS_URL = 'http://lnbits.test';
    process.env.LNBITS_INVOICE_KEY = 'test-invoice-key';
    process.env.LNBITS_API_KEY = 'test-api-key';
    // Custodial is OFF by default in production, but the bulk of these route
    // tests exercise the custodial path (they send no fundingMode). Enable it
    // here so they keep covering that path; the "custodial disabled" describe
    // block below flips it to 'false' to assert the new default behavior.
    process.env.ALLOW_CUSTODIAL_BOUNTIES = 'true';

    // Default db stubs (overridden per test where needed)
    (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(null);
    (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);
    (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(null);
    // Open-claim set used by /approve's ambiguity guard and by /pending-claim.
    // Empty by default; tests that exercise a claim populate it.
    (mockDb.query.claims.findMany as jest.Mock).mockResolvedValue([]);
    (mockDb.query.users.findFirst as jest.Mock).mockResolvedValue(null);
    mockInsert([makeBounty()]);
    mockUpdate();
    mockClaimCounts(0, 0);

    // Guard defaults. `jest.clearAllMocks()` clears call records but leaves
    // implementations in place, so a test that trips a guard would otherwise
    // leave it tripped for every test after it.
    (security.evaluatePayoutGuards as jest.Mock).mockResolvedValue({ ok: true });
    (security.payoutsEnabled as jest.Mock).mockReturnValue(true);
    (security.payoutBalanceLooksSane as jest.Mock).mockResolvedValue(true);
    (security.isLargePayout as jest.Mock).mockReturnValue(false);
    // Custodial payout reconciliation: default to "proven not paid" so error
    // paths keep their legacy release-the-lock behavior unless a test says
    // otherwise.
    (mockLnbits.lookupLnbitsPayment as jest.Mock).mockResolvedValue('not-found');
    // Same hazard: a test that simulates a swapped-out wallet would otherwise
    // leave every later test looking at "a different wallet". Reset to the
    // wallet the fixtures record against their claims.
    mockNwc.walletPubkeyFromNwcUri.mockReturnValue(WALLET_PUBKEY);
});

// ============================================================================
describe('warnOnInsecureConfig', () => {
    let warnSpy: jest.SpyInstance;
    beforeEach(() => {
        warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    });
    afterEach(() => {
        warnSpy.mockRestore();
    });

    it('warns loudly when NODE_ENV is not production', () => {
        warnOnInsecureConfig({ NODE_ENV: 'development' } as NodeJS.ProcessEnv);
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('NON-PRODUCTION'));
    });

    it('warns when NODE_ENV is unset', () => {
        warnOnInsecureConfig({} as NodeJS.ProcessEnv);
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('(unset)'));
    });

    it('does not emit the non-production warning in production', () => {
        warnOnInsecureConfig({ NODE_ENV: 'production', ALLOWED_ORIGINS: 'x', AUTH_AUDIENCE: 'y' } as NodeJS.ProcessEnv);
        const messages = warnSpy.mock.calls.map((c) => String(c[0]));
        expect(messages.some((m) => m.includes('NON-PRODUCTION'))).toBe(false);
    });

    it('throws when NODE_ENV is production and AUTH_AUDIENCE is not set', () => {
        expect(() => {
            warnOnInsecureConfig({ NODE_ENV: 'production' } as NodeJS.ProcessEnv);
        }).toThrow(/AUTH_AUDIENCE/);
    });

    it('does not throw when NODE_ENV is production and AUTH_AUDIENCE is set', () => {
        expect(() => {
            warnOnInsecureConfig({ NODE_ENV: 'production', AUTH_AUDIENCE: 'https://api.example.com' } as NodeJS.ProcessEnv);
        }).not.toThrow();
    });
});

// ============================================================================
describe('GET /health', () => {
    it('returns 200 with status ok', async () => {
        const res = await request(app).get('/health');
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ status: 'ok', dbConnected: true });
    });
});

// ============================================================================
describe('POST /auth/nonce', () => {
    it('is gated by nostrAuth and issues a nonce for the authenticated pubkey', async () => {
        const res = await request(app).post('/auth/nonce');

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ nonce: 'test-nonce-value', expiresAt: expect.any(Number) });
        expect(mockIssueNonce).toHaveBeenCalledWith(TEST_PUBKEY);
    });
});

// ============================================================================
describe('POST /bounties', () => {
    const validBody = {
        testId: 'test-abc',
        amountSats: 5000,
    };

    it('returns 400 when testId is missing', async () => {
        const res = await request(app).post('/bounties').send({ amountSats: 100 });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Validation failed');
    });

    it('returns 400 when amountSats is below minimum (0)', async () => {
        const res = await request(app).post('/bounties').send({ testId: 'x', amountSats: 0 });
        expect(res.status).toBe(400);
    });

    it('accepts amountSats at the maximum (50000)', async () => {
        mockLnbits.createLnbitsInvoice.mockResolvedValue({
            payment_request: 'lnbc_new',
            payment_hash: VALID_HASH,
        });
        mockInsert([makeBounty({ amountSats: 50000 })]);

        const res = await request(app)
            .post('/bounties')
            .send({ testId: 'test-abc', amountSats: 50000 });
        expect(res.status).toBe(201);
    });

    it('returns 400 when amountSats exceeds maximum (50001)', async () => {
        // Schema cap is 50,000 sats — matches the frontend validator at
        // sattest/src/bounty/bounty.util.ts:68-77 for defense-in-depth.
        const res = await request(app).post('/bounties').send({ testId: 'x', amountSats: 50001 });
        expect(res.status).toBe(400);
    });

    it('returns 400 when amountSats is not an integer', async () => {
        const res = await request(app).post('/bounties').send({ testId: 'x', amountSats: 1.5 });
        expect(res.status).toBe(400);
    });

    it('returns 400 when frontEndPaymentHash is not 64 hex chars', async () => {
        const res = await request(app).post('/bounties').send({
            ...validBody,
            frontEndPaymentHash: 'tooshort',
        });
        expect(res.status).toBe(400);
    });

    it('returns 400 when frontEndPaymentHash has non-hex characters', async () => {
        const res = await request(app).post('/bounties').send({
            ...validBody,
            frontEndPaymentHash: 'z'.repeat(64),
        });
        expect(res.status).toBe(400);
    });

    it('returns 400 when memo exceeds 500 chars', async () => {
        const res = await request(app).post('/bounties').send({
            ...validBody,
            memo: 'x'.repeat(501),
        });
        expect(res.status).toBe(400);
    });

    it('returns 500 when LNBITS_URL is not configured', async () => {
        delete process.env.LNBITS_URL;
        const res = await request(app).post('/bounties').send(validBody);
        expect(res.status).toBe(500);
    });

    it('returns 500 when LNBITS_INVOICE_KEY is not configured', async () => {
        delete process.env.LNBITS_INVOICE_KEY;
        const res = await request(app).post('/bounties').send(validBody);
        expect(res.status).toBe(500);
    });

    it('creates a LNbits invoice when no frontEnd data is supplied', async () => {
        mockLnbits.createLnbitsInvoice.mockResolvedValue({
            payment_request: 'lnbc_new',
            payment_hash: VALID_HASH,
        });
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);
        mockInsert([makeBounty()]);

        const res = await request(app).post('/bounties').send(validBody);

        expect(res.status).toBe(201);
        expect(mockLnbits.createLnbitsInvoice).toHaveBeenCalledWith(
            'http://lnbits.test',
            'test-invoice-key',
            5000,
            expect.any(String)
        );
    });

    it('skips invoice creation when a matching frontEndInvoice + hash are supplied', async () => {
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);
        mockInsert([makeBounty()]);
        // The suite-wide ./nwc mock stubs this to a fixed string; the handler
        // now compares its result against the supplied hash, so this test needs
        // the genuine derivation.
        mockNwc.paymentHashFromBolt11.mockReturnValue(VALID_HASH);

        const res = await request(app).post('/bounties').send({
            ...validBody,
            frontEndInvoice: makeBolt11(validBody.amountSats),
            frontEndPaymentHash: VALID_HASH,
        });

        expect(res.status).toBe(201);
        expect(mockLnbits.createLnbitsInvoice).not.toHaveBeenCalled();
    });

    it('rejects a frontEndPaymentHash with no accompanying invoice', async () => {
        // A hash alone can never be funded or displayed, and `update-paid`
        // would poll a hash we can't tie to any invoice we issued.
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);

        const res = await request(app).post('/bounties').send({
            ...validBody,
            frontEndPaymentHash: VALID_HASH,
        });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/requires the matching frontEndInvoice/);
        expect(mockDb.insert).not.toHaveBeenCalled();
    });

    it('rejects a frontEndInvoice whose amount does not match amountSats', async () => {
        // The invoice asks for 1 sat while the bounty claims to be worth 5000 —
        // previously stored verbatim, leaving funded-vs-claimable accounting
        // resting on the payment_hash unique constraint rather than validation.
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);

        const res = await request(app).post('/bounties').send({
            ...validBody,
            frontEndInvoice: makeBolt11(1),
        });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/amount does not match amountSats/);
        expect(mockDb.insert).not.toHaveBeenCalled();
    });

    it('rejects a frontEndPaymentHash that does not match the invoice', async () => {
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);

        const res = await request(app).post('/bounties').send({
            ...validBody,
            frontEndInvoice: makeBolt11(validBody.amountSats),
            frontEndPaymentHash: 'f'.repeat(64),
        });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/does not match frontEndInvoice/);
        expect(mockDb.insert).not.toHaveBeenCalled();
    });

    it('uses authenticated pubkey as creatorId (ignores any body.creatorId)', async () => {
        mockLnbits.createLnbitsInvoice.mockResolvedValue({
            payment_request: 'lnbc_new',
            payment_hash: VALID_HASH,
        });
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);
        const inserted = makeBounty({ creatorId: TEST_PUBKEY });
        mockInsert([inserted]);

        const res = await request(app).post('/bounties').send({
            ...validBody,
            creatorId: OTHER_PUBKEY, // should be ignored
        });

        expect(res.status).toBe(201);
        const insertCall = (mockDb.insert as jest.Mock).mock.results[0].value;
        const valuesCall = insertCall.values.mock.calls[0][0];
        expect(valuesCall.creatorId).toBe(TEST_PUBKEY);
    });

    it('deactivates existing unpaid active bounties before inserting', async () => {
        const existingUnpaid = makeBounty({ id: 'old-id', invoicePaid: false });
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([existingUnpaid]);
        mockLnbits.createLnbitsInvoice.mockResolvedValue({
            payment_request: 'lnbc_new',
            payment_hash: VALID_HASH,
        });
        mockInsert([makeBounty()]);

        const res = await request(app).post('/bounties').send(validBody);

        expect(res.status).toBe(201);
        expect(mockDb.update).toHaveBeenCalled();
    });

    it('does not call update when no stale unpaid bounties exist', async () => {
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);
        mockLnbits.createLnbitsInvoice.mockResolvedValue({
            payment_request: 'lnbc_new',
            payment_hash: VALID_HASH,
        });
        mockInsert([makeBounty()]);

        await request(app).post('/bounties').send(validBody);

        expect(mockDb.update).not.toHaveBeenCalled();
    });

    it('uses a default memo when none is provided', async () => {
        mockLnbits.createLnbitsInvoice.mockResolvedValue({
            payment_request: 'lnbc_new',
            payment_hash: VALID_HASH,
        });
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);
        mockInsert([makeBounty()]);

        await request(app).post('/bounties').send(validBody);

        expect(mockLnbits.createLnbitsInvoice).toHaveBeenCalledWith(
            expect.any(String),
            expect.any(String),
            expect.any(Number),
            expect.stringContaining('test-abc')
        );
    });

    it('returns 500 on unexpected db error', async () => {
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);
        mockLnbits.createLnbitsInvoice.mockResolvedValue({
            payment_request: 'lnbc_new',
            payment_hash: VALID_HASH,
        });
        (mockDb.insert as jest.Mock).mockReturnValue({
            values: jest.fn().mockReturnValue({
                returning: jest.fn().mockRejectedValue(new Error('db exploded')),
            }),
        });

        const res = await request(app).post('/bounties').send(validBody);
        expect(res.status).toBe(500);
    });
});

// ============================================================================
describe('PATCH /bounties/:id/deactivate', () => {
    it('returns 400 for a non-UUID bounty id', async () => {
        const res = await request(app).patch('/bounties/not-a-uuid/deactivate');
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/Invalid bounty ID/);
    });

    it('returns 404 when bounty does not exist', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(null);

        const res = await request(app).patch(`/bounties/${BOUNTY_ID}/deactivate`);
        expect(res.status).toBe(404);
    });

    it('returns 403 when requester does not own the bounty', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ creatorId: OTHER_PUBKEY })
        );

        const res = await request(app).patch(`/bounties/${BOUNTY_ID}/deactivate`);
        expect(res.status).toBe(403);
        expect(res.body.error).toMatch(/Forbidden/);
    });

    it('deactivates bounty and returns 200', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(makeBounty());
        mockUpdate([{ id: BOUNTY_ID, active: false }]);

        const res = await request(app).patch(`/bounties/${BOUNTY_ID}/deactivate`);
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.active).toBe(false);
    });

    it('returns 500 on db error', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockRejectedValue(new Error('db error'));

        const res = await request(app).patch(`/bounties/${BOUNTY_ID}/deactivate`);
        expect(res.status).toBe(500);
    });

    // ── Refund flow ────────────────────────────────────────────────────────
    describe('refund flow', () => {
        const REFUND_LNURL = 'lightning@example.com';
        const security = require('./security') as {
            evaluatePayoutGuards: jest.Mock;
            payoutsEnabled: jest.Mock;
            payoutBalanceLooksSane: jest.Mock;
            alertAnomaly: jest.Mock;
            isLargePayout: jest.Mock;
        };

        const okLnurl = (amountSats = 1000) => ({
            minSendable: 1,
            maxSendable: amountSats * 1000, // msat
            callback: 'https://cb',
            tag: 'payRequest',
        });

        it('no-refund path: unpaid bounty deactivates without payout', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ invoicePaid: false })
            );
            mockUpdate([{ id: BOUNTY_ID, active: false }]);

            const res = await request(app).patch(`/bounties/${BOUNTY_ID}/deactivate`).send({});
            expect(res.status).toBe(200);
            expect(res.body.active).toBe(false);
            expect(res.body.refund).toBeUndefined();
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        it('no-refund path: paid bounty deactivates without payout', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ invoicePaid: true })
            );
            mockUpdate([{ id: BOUNTY_ID, active: false }]);

            const res = await request(app).patch(`/bounties/${BOUNTY_ID}/deactivate`).send({});
            expect(res.status).toBe(200);
            expect(res.body.refund).toBeUndefined();
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        it('refund path: paid bounty with no claims → 200, payout fires, refund columns set', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ invoicePaid: true, amountSats: 1000, claims: [] })
            );
            mockLnbits.checkValidLnurl.mockResolvedValue(okLnurl(1000) as any);
            mockLnbits.createLnbitsPayout.mockResolvedValue({ checking_id: 'chk-1' } as any);
            mockUpdate([{ id: BOUNTY_ID, active: false }]);

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(200);
            expect(res.body.refund).toEqual({ checkingId: 'chk-1', amountSats: 1000 });
            expect(mockLnbits.createLnbitsPayout).toHaveBeenCalledWith(
                REFUND_LNURL,
                1000,
                'Refund',
                `refund:${BOUNTY_ID}`,
            );
            // Verify refund columns passed to update().set(). The first set() is
            // now the atomic lock ({ refundAt }); the finalizing update is the
            // one carrying refundCheckingId.
            const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
                (c: any[]) => c[0]
            );
            const finalSet = setArgs.find((arg: any) => 'refundCheckingId' in arg);
            expect(finalSet).toMatchObject({
                active: false,
                refundLnurl: REFUND_LNURL,
                refundCheckingId: 'chk-1',
            });
            expect(finalSet.refundAt).toBeInstanceOf(Date);
        });

        it('refund path: unpaid bounty → 400, no payout', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ invoicePaid: false })
            );

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/never paid/i);
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        it('refund path: NWC bounty → 400, no payout (no custodied funds)', async () => {
            // NWC bounties are invoicePaid=true with no claims, so they'd
            // otherwise pass the refund eligibility checks — but they never
            // custodied funds in our wallet, so a refund must be refused.
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ fundingMode: 'nwc', invoicePaid: true, claims: [] })
            );

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/no custodied funds/i);
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        it('refund path: bounty with approved claim → 400, no payout', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({
                    invoicePaid: true,
                    claims: [{ status: 'approved' }],
                })
            );

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/already paid out/i);
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        // ── Removal while a payout is in flight ────────────────────────────
        //
        // `approving` means the sats may already have left (a payout whose
        // outcome was never confirmed stays in this state). Refunding the
        // creator now would pay the same bounty twice; plain-deactivating hides
        // the bounty from the lens, stranding the claim with no way to reconcile
        // it. Both paths must refuse.
        it('refund path: bounty with an approving claim → 409, no payout', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({
                    invoicePaid: true,
                    claims: [{ status: 'approving' }],
                })
            );

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('CLAIM_IN_PROGRESS');
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
            expect(mockDb.update).not.toHaveBeenCalled();
        });

        it('no-refund path: bounty with an approving claim → 409, stays active', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({
                    fundingMode: 'nwc',
                    invoicePaid: true,
                    claims: [{ status: 'approving' }],
                })
            );

            const res = await request(app).patch(`/bounties/${BOUNTY_ID}/deactivate`).send({});

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('CLAIM_IN_PROGRESS');
            // Never soft-deleted — the lens is the only route back to the claim.
            expect(mockDb.update).not.toHaveBeenCalled();
        });

        // A newer claim must not mask an older one that holds (or spent) the
        // money — the guards read every claim, not just the most recent.
        it('refund path: an approving claim behind a newer pending claim still blocks', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({
                    invoicePaid: true,
                    claims: [{ status: 'pending' }, { status: 'approving' }],
                })
            );

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(409);
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        it('refund path: an approved claim behind a newer pending claim still blocks', async () => {
            // Nothing stops a claimant filing a new claim after an earlier one
            // was paid. Reading only the latest would refund a spent bounty.
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({
                    invoicePaid: true,
                    claims: [{ status: 'pending' }, { status: 'approved' }],
                })
            );

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/already paid out/i);
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        it('refund path: bounty with pending claim → 200, payout fires', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({
                    invoicePaid: true,
                    amountSats: 1000,
                    claims: [{ status: 'pending' }],
                })
            );
            mockLnbits.checkValidLnurl.mockResolvedValue(okLnurl(1000) as any);
            mockLnbits.createLnbitsPayout.mockResolvedValue({ checking_id: 'chk-2' } as any);
            mockUpdate([{ id: BOUNTY_ID, active: false }]);

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(200);
            expect(mockLnbits.createLnbitsPayout).toHaveBeenCalledTimes(1);
        });

        it('refund path: second refund attempt → 400 Already refunded, no payout', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({
                    invoicePaid: true,
                    refundCheckingId: 'chk-prior',
                    refundLnurl: REFUND_LNURL,
                    refundAt: new Date(),
                })
            );

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/already been refunded/i);
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        it('refund path: lock lost (concurrent refund) → 409, no payout', async () => {
            // refundCheckingId is still null so the fast-path check passes, but
            // the atomic lock (set refundAt where both null) matches zero rows
            // because a concurrent refund already claimed the slot.
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ invoicePaid: true, amountSats: 1000, claims: [] })
            );
            mockLnbits.checkValidLnurl.mockResolvedValue(okLnurl(1000) as any);
            mockUpdate([]); // empty returning() → lock not acquired

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(409);
            expect(res.body.error).toMatch(/already in progress or completed/i);
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        it('refund path: non-creator → 403, no payout', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ creatorId: OTHER_PUBKEY, invoicePaid: true })
            );

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(403);
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        it('refund path: invalid LNURL → 400, no payout, lock released', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ invoicePaid: true })
            );
            // The refund lock is now taken BEFORE the LNURL validation network
            // call (refund-vs-approve TOCTOU fix), so the lock must succeed for
            // the validation failure path to be reached — and must be released.
            mockUpdate([{ id: BOUNTY_ID }]);
            mockLnbits.checkValidLnurl.mockRejectedValue(new Error('bad lnurl'));

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: 'not-an-lnurl' });

            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/LNURL/i);
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
            const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
                (c: any[]) => c[0]
            );
            expect(setArgs).toContainEqual({ refundAt: null });
        });

        it('refund path: claim locked by a concurrent approve → 409, refund lock released', async () => {
            // The bounty fixture's claims are empty at first read, but an
            // approve flipped a claim to `approving` before our refund lock
            // landed — the post-lock re-read must see it and bail.
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ invoicePaid: true, amountSats: 1000, claims: [] })
            );
            mockUpdate([{ id: BOUNTY_ID }]); // refund lock acquired
            (mockDb.query.claims.findMany as jest.Mock).mockResolvedValue([
                { status: 'approving' },
            ]);

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('CLAIM_IN_PROGRESS');
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
            // Lock released so the refund can be retried once the claim resolves.
            const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
                (c: any[]) => c[0]
            );
            expect(setArgs).toContainEqual({ refundAt: null });
        });

        it('refund path: payout outcome unknown → 502, refund lock KEPT', async () => {
            // A throw from the pay step (timeout after commit, unreadable
            // success body) is not proof of non-payment. Reconcile by payment
            // hash; unless LNbits proves no payment exists, the refund stays
            // locked so a retry can't pay twice.
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ invoicePaid: true, amountSats: 1000, claims: [] })
            );
            mockLnbits.checkValidLnurl.mockResolvedValue(okLnurl(1000) as any);
            mockUpdate([{ id: BOUNTY_ID }]);
            mockLnbits.createLnbitsPayout.mockRejectedValue(
                new FakeLnbitsPayoutErrorCtor('LNbits payout request failed: timeout', 'pay-hash-1')
            );
            (mockLnbits.lookupLnbitsPayment as jest.Mock).mockResolvedValue('unknown');

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(502);
            expect(res.body.code).toBe('PAYOUT_OUTCOME_UNKNOWN');
            // refundAt is never cleared: the lock set is the only refundAt write.
            const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
                (c: any[]) => c[0]
            );
            expect(setArgs).not.toContainEqual({ refundAt: null });
            expect(setArgs).not.toContainEqual(expect.objectContaining({ active: false }));
            expect(security.alertAnomaly).toHaveBeenCalled();
        });

        it('refund path: payout provably unpaid (reconcile not-found) → lock released', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ invoicePaid: true, amountSats: 1000, claims: [] })
            );
            mockLnbits.checkValidLnurl.mockResolvedValue(okLnurl(1000) as any);
            mockUpdate([{ id: BOUNTY_ID }]);
            mockLnbits.createLnbitsPayout.mockRejectedValue(
                new FakeLnbitsPayoutErrorCtor('LNbits payout error: 500 - boom', 'pay-hash-2')
            );
            (mockLnbits.lookupLnbitsPayment as jest.Mock).mockResolvedValue('not-found');

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            // Released + surfaced as a 500 via the outer catch (no money moved).
            expect(res.status).toBe(500);
            const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
                (c: any[]) => c[0]
            );
            expect(setArgs).toContainEqual({ refundAt: null });
        });

        it('refund path: payout guard trips → status from verdict, lock released', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ invoicePaid: true, amountSats: 1000 })
            );
            mockLnbits.checkValidLnurl.mockResolvedValue(okLnurl(1000) as any);
            // The refund lock is now taken before the guards run (so an
            // in-flight refund is visible to a concurrent payout's cap check),
            // which means this update has to succeed for the guard to be reached.
            mockUpdate([{ id: BOUNTY_ID }]);
            security.evaluatePayoutGuards.mockResolvedValueOnce({
                ok: false,
                reason: 'Hourly payout cap exceeded',
                status: 429,
            });

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(429);
            expect(res.body.error).toMatch(/cap/i);
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
            // The lock is released (refundAt cleared) so the creator can retry,
            // and the bounty is never deactivated.
            const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
                (c: any[]) => c[0]
            );
            expect(setArgs).toContainEqual({ refundAt: null });
            expect(setArgs).not.toContainEqual(expect.objectContaining({ active: false }));
        });

        it('refund path: kill switch bails before taking the refund lock', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ invoicePaid: true, amountSats: 1000 })
            );
            mockLnbits.checkValidLnurl.mockResolvedValue(okLnurl(1000) as any);
            (security.payoutsEnabled as jest.Mock).mockReturnValue(false);

            const res = await request(app)
                .patch(`/bounties/${BOUNTY_ID}/deactivate`)
                .send({ refundLnurl: REFUND_LNURL });

            expect(res.status).toBe(503);
            expect(mockDb.update).not.toHaveBeenCalled();
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });
    });
});

// ============================================================================
describe('GET /bounties', () => {
    // ── Mandatory repo scope ───────────────────────────────────────────────
    //
    // This endpoint is unauthenticated. Unscoped, it served the whole table to
    // anyone — more data than any client needs, and the reconnaissance feed for
    // targeting claims. A scope doesn't authenticate the caller, but it bounds
    // one response to a repository they already had to name.
    it('returns 400 when no repo scope is supplied', async () => {
        const res = await request(app).get('/bounties');
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('REPO_REQUIRED');
        expect(mockDb.query.bounties.findMany).not.toHaveBeenCalled();
    });

    it('returns 400 for a malformed repo scope', async () => {
        const res = await request(app).get('/bounties?repo=not-a-slug');
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('REPO_REQUIRED');
        expect(mockDb.query.bounties.findMany).not.toHaveBeenCalled();
    });

    it('always constrains the query to the requested repo', async () => {
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);

        await request(app).get(`/bounties?repo=${REPO_SLUG}`);

        // The repo predicate must never be `undefined` — that was the shape
        // that let an unscoped listing through.
        const where = (mockDb.query.bounties.findMany as jest.Mock).mock.calls[0][0].where;
        expect(whereParams(where)).toContain(REPO_SLUG);
    });

    it('returns 400 for limit = 0', async () => {
        const res = await request(app).get(`/bounties?repo=${REPO_SLUG}&limit=0`);
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/limit/i);
    });

    it('does not publish claim timing to anonymous callers', async () => {
        // `claimedAt` on every claim, unauthenticated, told an attacker exactly
        // when a legitimate claim landed so they could file one right after it.
        // The lens only needs to know an open claim exists.
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);

        await request(app).get(`/bounties?repo=${REPO_SLUG}`);

        const args = (mockDb.query.bounties.findMany as jest.Mock).mock.calls[0][0];
        expect(args.with.claims.columns).toEqual({ id: true, status: true });
        expect(args.with.claims.columns).not.toHaveProperty('claimedAt');
        expect(args.with.claims.columns).not.toHaveProperty('claimantPubkey');
        expect(args.with.claims.columns).not.toHaveProperty('claimantLnurl');
    });

    it('returns 400 for limit > 100', async () => {
        const res = await request(app).get(`/bounties?repo=${REPO_SLUG}&limit=101`);
        expect(res.status).toBe(400);
    });

    it('returns 400 for non-numeric limit', async () => {
        const res = await request(app).get(`/bounties?repo=${REPO_SLUG}&limit=abc`);
        expect(res.status).toBe(400);
    });

    it('returns 400 for negative offset', async () => {
        const res = await request(app).get(`/bounties?repo=${REPO_SLUG}&offset=-1`);
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/offset/i);
    });

    it('returns 400 for non-numeric offset', async () => {
        const res = await request(app).get(`/bounties?repo=${REPO_SLUG}&offset=abc`);
        expect(res.status).toBe(400);
    });

    it('returns bounties list with default pagination', async () => {
        const bountyList = [makeBounty()];
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue(bountyList);

        const res = await request(app).get(`/bounties?repo=${REPO_SLUG}`);
        expect(res.status).toBe(200);
        expect(res.body.bounties).toHaveLength(1);
    });

    it('projects only the public column allowlist (no invoice / paymentHash / refund fields)', async () => {
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);

        await request(app).get(`/bounties?repo=${REPO_SLUG}`);

        const queryArg = (mockDb.query.bounties.findMany as jest.Mock).mock.calls[0][0];
        expect(queryArg.columns).toMatchObject({
            id: true,
            testId: true,
            creatorId: true,
            amountSats: true,
            invoicePaid: true,
            fundingMode: true,
            repo: true,
            active: true,
            createdAt: true,
        });
        // Sensitive columns must NOT be selected.
        for (const leaked of ['invoice', 'paymentHash', 'refundLnurl', 'refundCheckingId', 'memo']) {
            expect(queryArg.columns[leaked]).toBeUndefined();
        }
    });

    it('accepts valid limit and offset', async () => {
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);

        const res = await request(app).get(`/bounties?repo=${REPO_SLUG}&limit=50&offset=10`);
        expect(res.status).toBe(200);
    });

    it('passes includeInactive flag through to db query', async () => {
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);

        await request(app).get(`/bounties?repo=${REPO_SLUG}&includeInactive=true`);

        expect(mockDb.query.bounties.findMany).toHaveBeenCalled();
    });

    it('filters by testId when provided', async () => {
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);

        await request(app).get(`/bounties?repo=${REPO_SLUG}&testId=some-test`);

        expect(mockDb.query.bounties.findMany).toHaveBeenCalled();
    });

    it('returns 500 on db error', async () => {
        (mockDb.query.bounties.findMany as jest.Mock).mockRejectedValue(new Error('db error'));

        const res = await request(app).get(`/bounties?repo=${REPO_SLUG}`);
        expect(res.status).toBe(500);
    });
});

// ============================================================================
// The other unauthenticated listing endpoint. It had no coverage at all, which
// is how it kept an optional repo scope while GET /bounties was being reviewed.
describe('POST /bounties/filter', () => {
    const testIds = ['src/a.test.ts#works'];

    it('returns 400 when no repo scope is supplied', async () => {
        const res = await request(app).post('/bounties/filter').send({ testIds });
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('REPO_REQUIRED');
        expect(mockDb.query.bounties.findMany).not.toHaveBeenCalled();
    });

    it('returns 400 for a malformed repo scope', async () => {
        const res = await request(app)
            .post('/bounties/filter?repo=../../etc')
            .send({ testIds });
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('REPO_REQUIRED');
        expect(mockDb.query.bounties.findMany).not.toHaveBeenCalled();
    });

    it('rejects the scope before validating the body', async () => {
        // A 500-entry testId batch with no repo was a cross-repository probe;
        // the scope check has to come first so that body never gets processed.
        const res = await request(app).post('/bounties/filter').send({ testIds: [] });
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('REPO_REQUIRED');
    });

    it('constrains the query to the requested repo', async () => {
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);

        const res = await request(app)
            .post(`/bounties/filter?repo=${REPO_SLUG}`)
            .send({ testIds });

        expect(res.status).toBe(200);
        const where = (mockDb.query.bounties.findMany as jest.Mock).mock.calls[0][0].where;
        expect(whereParams(where)).toContain(REPO_SLUG);
    });

    it('still validates the body once the scope is present', async () => {
        const res = await request(app)
            .post(`/bounties/filter?repo=${REPO_SLUG}`)
            .send({ testIds: [] });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Validation failed');
    });

    it('does not publish claim timing to anonymous callers', async () => {
        (mockDb.query.bounties.findMany as jest.Mock).mockResolvedValue([]);

        await request(app).post(`/bounties/filter?repo=${REPO_SLUG}`).send({ testIds });

        const args = (mockDb.query.bounties.findMany as jest.Mock).mock.calls[0][0];
        expect(args.with.claims.columns).toEqual({ id: true, status: true });
    });
});

// ============================================================================
describe('GET /bounties/:paymentHash/check-paid', () => {
    it('returns 400 for a hash that is too short', async () => {
        const res = await request(app).get('/bounties/tooshort/check-paid');
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/Invalid payment hash/);
    });

    it('returns 400 for a hash with non-hex characters', async () => {
        const res = await request(app).get(`/bounties/${'z'.repeat(64)}/check-paid`);
        expect(res.status).toBe(400);
    });

    it('returns 400 for a hash that is too long', async () => {
        const res = await request(app).get(`/bounties/${'a'.repeat(65)}/check-paid`);
        expect(res.status).toBe(400);
    });

    it('returns 404 when no bounty carries the hash', async () => {
        // bounties.findFirst returns null by default (beforeEach)
        const res = await request(app).get(`/bounties/${VALID_HASH}/check-paid`);
        expect(res.status).toBe(404);
        expect(mockLnbits.checkLnbitsInvoicePaid).not.toHaveBeenCalled();
    });

    it('returns 404 when the hash belongs to someone else\'s bounty (no oracle)', async () => {
        // Same 404 as an unknown hash — the route must not confirm existence.
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ creatorId: OTHER_PUBKEY })
        );

        const res = await request(app).get(`/bounties/${VALID_HASH}/check-paid`);
        expect(res.status).toBe(404);
        expect(mockLnbits.checkLnbitsInvoicePaid).not.toHaveBeenCalled();
    });

    it('returns paid: true when invoice is paid', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(makeBounty());
        mockLnbits.checkLnbitsInvoicePaid.mockResolvedValue({ paid: true });

        const res = await request(app).get(`/bounties/${VALID_HASH}/check-paid`);
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, paid: true });
    });

    it('returns paid: false when invoice is unpaid', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(makeBounty());
        mockLnbits.checkLnbitsInvoicePaid.mockResolvedValue({ paid: false });

        const res = await request(app).get(`/bounties/${VALID_HASH}/check-paid`);
        expect(res.status).toBe(200);
        expect(res.body.paid).toBe(false);
    });

    it('returns 500 when LNbits call fails', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(makeBounty());
        mockLnbits.checkLnbitsInvoicePaid.mockRejectedValue(new Error('lnbits down'));

        const res = await request(app).get(`/bounties/${VALID_HASH}/check-paid`);
        expect(res.status).toBe(500);
    });
});

// ============================================================================
describe('POST /lnurl/limits', () => {
    it('returns the resolved minSendable/maxSendable for a valid lnurl', async () => {
        mockLnbits.checkValidLnurl.mockResolvedValue({
            tag: 'payRequest', callback: '', minSendable: 1000, maxSendable: 100_000_000,
            metadata: '', commentAllowed: 0, allowsNostr: false, nostrPubkey: '',
        });

        const res = await request(app).post('/lnurl/limits').send({ lnurl: 'alice@primal.net' });
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ minSendable: 1000, maxSendable: 100_000_000 });
        expect(mockLnbits.checkValidLnurl).toHaveBeenCalledWith('alice@primal.net');
        // Read-only: never creates a claim.
        expect(mockDb.insert).not.toHaveBeenCalled();
    });

    it('returns 400 when the lnurl is missing or blank', async () => {
        expect((await request(app).post('/lnurl/limits').send({})).status).toBe(400);
        expect((await request(app).post('/lnurl/limits').send({ lnurl: '   ' })).status).toBe(400);
    });

    it('returns 400 when the lnurl cannot be resolved', async () => {
        mockLnbits.checkValidLnurl.mockRejectedValue(new Error('unreachable'));
        const res = await request(app).post('/lnurl/limits').send({ lnurl: 'lnurl1bad' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/Invalid or unreachable LNURL/);
    });
});

describe('POST /bounties/:id/claim', () => {
    // min/max are MILLISATS (LUD-06). Default range [1 sat, 100k sats]
    // comfortably contains the default 1000-sat bounty (makeBounty()).
    const validLnurlResult = {
        tag: 'payRequest', callback: '', minSendable: 1000, maxSendable: 100_000_000,
        metadata: '', commentAllowed: 0, allowsNostr: false, nostrPubkey: '',
    };

    it('returns 400 for a non-UUID bounty id', async () => {
        const res = await request(app).post('/bounties/not-a-uuid/claim').send({ lnurl: 'lnurl1test' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/Invalid bounty ID/);
    });

    it('returns 400 when LNURL is invalid or unreachable', async () => {
        mockLnbits.checkValidLnurl.mockRejectedValue(new Error('unreachable'));
        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'lnurl1bad' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/Invalid or unreachable LNURL/);
        expect(mockDb.insert).not.toHaveBeenCalled();
    });

    it('returns 400 when lnurl is missing', async () => {
        const res = await request(app).post(`/bounties/${BOUNTY_ID}/claim`).send({});
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Validation failed');
        expect(res.body.issues.some((i: any) => i.field === 'lnurl')).toBe(true);
    });

    it('returns 400 when lnurl exceeds the length cap', async () => {
        // Uncapped previously: the 1024kb body limit was the only bound, so a
        // ~1 MB value went straight into a `text` column on someone else's
        // bounty. Every sibling field is capped; this one now matches.
        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: `${'a'.repeat(2100)}@example.com` });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Validation failed');
        expect(res.body.issues.some((i: any) => /max 2048/.test(i.message))).toBe(true);
    });

    it('returns 400 when lnurl is an empty string', async () => {
        const res = await request(app).post(`/bounties/${BOUNTY_ID}/claim`).send({ lnurl: '   ' });
        expect(res.status).toBe(400);
    });

    it('returns 400 when lnurl is not a string', async () => {
        const res = await request(app).post(`/bounties/${BOUNTY_ID}/claim`).send({ lnurl: 123 });
        expect(res.status).toBe(400);
    });

    it('returns 400 when bounty does not exist', async () => {
        mockLnbits.checkValidLnurl.mockResolvedValue(validLnurlResult);
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(null);

        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'lnurl1test' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/not claimable/);
    });

    it('returns 400 when bounty invoice is not paid', async () => {
        mockLnbits.checkValidLnurl.mockResolvedValue(validLnurlResult);
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: false })
        );

        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'lnurl1test' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/not claimable/);
    });

    it('returns 400 when the bounty was removed (inactive), and inserts no claim', async () => {
        // `active=false` used to be display-only: the lens hid the bounty but
        // the API still took a claim on it. That let a removed — or refunded,
        // or already paid out — bounty acquire a fresh claim to approve
        // against, which is the first half of a double payout.
        mockLnbits.checkValidLnurl.mockResolvedValue(validLnurlResult);
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true, active: false })
        );

        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'lnurl1test' });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/no longer available/i);
        expect(mockDb.insert).not.toHaveBeenCalled();
    });

    it('returns 400 when the bounty exceeds the LNURL maxSendable (msat-correct)', async () => {
        // 1000-sat bounty = 1_000_000 msat; wallet max is 500_000 msat (500 sats).
        // The old sats-vs-msat check (1000 > 500_000 → false) wrongly let this through.
        mockLnbits.checkValidLnurl.mockResolvedValue({ ...validLnurlResult, maxSendable: 500_000 });
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true, amountSats: 1000 })
        );

        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'lnurl1test' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/outside this LNURL's range/);
    });

    it('returns 400 when the bounty is below the LNURL minSendable (msat-correct)', async () => {
        // 1000-sat bounty = 1_000_000 msat; wallet min is 5_000_000 msat (5000 sats).
        mockLnbits.checkValidLnurl.mockResolvedValue({ ...validLnurlResult, minSendable: 5_000_000 });
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true, amountSats: 1000 })
        );

        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'lnurl1test' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/outside this LNURL's range/);
    });

    it('creates a claim with status="pending" and returns the claim object', async () => {
        mockLnbits.checkValidLnurl.mockResolvedValue(validLnurlResult);
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true, amountSats: 1000 })
        );
        const insertedClaim = makeClaim({ status: 'pending', claimantLnurl: 'lnurl1test' });
        mockInsert([insertedClaim]);

        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'lnurl1test' });
        expect(res.status).toBe(200);
        // Frontend expects a single ClaimInfo at the top level — not wrapped
        // in `{ success, claim: [...] }` like the old shape.
        expect(res.body.id).toBe(insertedClaim.id);
        expect(res.body.status).toBe('pending');
        expect(res.body.claimantLnurl).toBe('lnurl1test');
    });

    it('inserts the claim with status set to pending', async () => {
        mockLnbits.checkValidLnurl.mockResolvedValue(validLnurlResult);
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true, amountSats: 1000 })
        );
        mockInsert([makeClaim({ status: 'pending' })]);

        await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'lnurl1test' });

        // Regression: previous handler relied on the column default and
        // shipped claims with status=null, which broke the frontend's
        // `claims[0].status === 'pending'` check.
        const valuesCall = (mockDb.insert as jest.Mock).mock.results[0].value.values.mock.calls[0][0];
        expect(valuesCall.status).toBe('pending');
        expect(valuesCall.bountyId).toBe(BOUNTY_ID);
    });

    it('defaults lnurlPrivate to false when hideLnurl is omitted', async () => {
        mockLnbits.checkValidLnurl.mockResolvedValue(validLnurlResult);
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true, amountSats: 1000 })
        );
        mockInsert([makeClaim({ status: 'pending' })]);

        await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'lnurl1test' });

        const valuesCall = (mockDb.insert as jest.Mock).mock.results[0].value.values.mock.calls[0][0];
        expect(valuesCall.lnurlPrivate).toBe(false);
    });

    it('stores lnurlPrivate=true when the claimant sets hideLnurl', async () => {
        mockLnbits.checkValidLnurl.mockResolvedValue(validLnurlResult);
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true, amountSats: 1000 })
        );
        mockInsert([makeClaim({ status: 'pending', lnurlPrivate: true })]);

        await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'lnurl1test', hideLnurl: true });

        const valuesCall = (mockDb.insert as jest.Mock).mock.results[0].value.values.mock.calls[0][0];
        expect(valuesCall.lnurlPrivate).toBe(true);
        // The LNURL is still stored — privacy hides it from the creator, it
        // doesn't stop the backend from routing the payout to it.
        expect(valuesCall.claimantLnurl).toBe('lnurl1test');
    });

    it('rejects a non-boolean hideLnurl with 400', async () => {
        mockLnbits.checkValidLnurl.mockResolvedValue(validLnurlResult);
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true, amountSats: 1000 })
        );

        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'lnurl1test', hideLnurl: 'yes' });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Validation failed');
        expect(res.body.issues.some((i: any) => i.field === 'hideLnurl')).toBe(true);
    });

    it('does not call db.update on claims (no longer mutates prior rows)', async () => {
        mockLnbits.checkValidLnurl.mockResolvedValue(validLnurlResult);
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true, amountSats: 1000 })
        );
        mockInsert([makeClaim({ status: 'pending' })]);

        await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'lnurl1test' });

        // Regression: the old handler ran `update(claims).where(eq(bounties.id, ...))`
        // which referenced the wrong table and threw — that's the 500 we just fixed.
        expect(mockDb.update).not.toHaveBeenCalled();
    });

    it('persists the authenticated claimant pubkey on the claim', async () => {
        // Previously the pubkey was derived, used for a null check, and thrown
        // away — leaving the payout with no verifiable counterparty and no
        // audit trail of who was paid.
        mockLnbits.checkValidLnurl.mockResolvedValue(validLnurlResult);
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true, amountSats: 1000 })
        );
        mockInsert([makeClaim({ status: 'pending' })]);

        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'alice@wallet.com' });

        expect(res.status).toBe(200);
        const values = (mockDb.insert as jest.Mock).mock.results[0].value.values.mock.calls[0][0];
        expect(values.claimantPubkey).toBe(TEST_PUBKEY);
    });

    it('rejects a second claim on the same bounty from the same identity', async () => {
        // Stacking claims is how a later claimant displaced an earlier one as
        // "newest" and became the payout destination.
        mockLnbits.checkValidLnurl.mockResolvedValue(validLnurlResult);
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true, amountSats: 1000 })
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
            makeClaim({ claimantPubkey: TEST_PUBKEY })
        );

        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'alice@wallet.com' });

        expect(res.status).toBe(409);
        expect(res.body.code).toBe('CLAIM_ALREADY_FILED');
        expect(mockDb.insert).not.toHaveBeenCalled();
    });

    it('turns a lost insert race on the unique index into the same benign 409', async () => {
        mockLnbits.checkValidLnurl.mockResolvedValue(validLnurlResult);
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true, amountSats: 1000 })
        );
        const uniqueViolation = Object.assign(new Error('duplicate key'), { code: '23505' });
        (mockDb.insert as jest.Mock).mockReturnValue({
            values: jest.fn().mockReturnValue({
                returning: jest.fn().mockRejectedValue(uniqueViolation),
            }),
        });

        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/claim`)
            .send({ lnurl: 'alice@wallet.com' });

        expect(res.status).toBe(409);
        expect(res.body.code).toBe('CLAIM_ALREADY_FILED');
    });

    // ── Anti-stuffing bounds ───────────────────────────────────────────────
    //
    // Keypairs are free, so any per-bounty quota is fillable by a Sybil. What
    // these bounds have to get right is the *failure mode*: a bounty may
    // degrade to a noisy picker, but must never become permanently unclaimable
    // by the genuine contributor.
    describe('anti-stuffing bounds', () => {
        beforeEach(() => {
            mockLnbits.checkValidLnurl.mockResolvedValue(validLnurlResult);
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ invoicePaid: true, amountSats: 1000 })
            );
            mockInsert([makeClaim({ status: 'pending' })]);
        });

        it('admits a claim when the bounty is quiet', async () => {
            mockClaimCounts(0, 0);

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/claim`)
                .send({ lnurl: 'alice@wallet.com' });

            expect(res.status).toBe(200);
        });

        it('rate-limits a burst of claims within the rolling window', async () => {
            mockClaimCounts(10, 10);

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/claim`)
                .send({ lnurl: 'alice@wallet.com' });

            expect(res.status).toBe(429);
            expect(res.body.code).toBe('CLAIM_RATE_LIMITED');
            expect(res.body.retryAfterSeconds).toBeGreaterThan(0);
            expect(mockDb.insert).not.toHaveBeenCalled();
        });

        it('lets a genuine claimant in once the window drains, even with many stacked claims', async () => {
            // The regression this shape exists to prevent: a hard low ceiling
            // meant 25 requests from 25 free keypairs locked the real
            // contributor out of the bounty permanently. A rolling window
            // drains, so stale stuffing can't deny the bounty its purpose.
            mockClaimCounts(0, 40);

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/claim`)
                .send({ lnurl: 'alice@wallet.com' });

            expect(res.status).toBe(200);
            expect(mockDb.insert).toHaveBeenCalled();
        });

        it('still refuses past the absolute storage ceiling', async () => {
            mockClaimCounts(0, 200);

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/claim`)
                .send({ lnurl: 'alice@wallet.com' });

            expect(res.status).toBe(429);
            expect(res.body.code).toBe('TOO_MANY_CLAIMS');
            expect(mockDb.insert).not.toHaveBeenCalled();
        });

        it('answers an existing claimant with their claimId, not a rate-limit error', async () => {
            // The dedupe runs before the bounds: someone who already holds a
            // claim adds no load, and a 429 here would be both wrong and
            // confusing — they need their claimId back.
            mockClaimCounts(10, 200);
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
                makeClaim({ claimantPubkey: TEST_PUBKEY })
            );

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/claim`)
                .send({ lnurl: 'alice@wallet.com' });

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('CLAIM_ALREADY_FILED');
            expect(res.body.claimId).toBe(CLAIM_ID);
        });
    });
});

// ============================================================================
describe('GET /bounties/:id/pending-claim', () => {
    it('returns the claimant LNURL to the creator for a normal (shared) claim', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ creatorId: TEST_PUBKEY })
        );
        (mockDb.query.claims.findMany as jest.Mock).mockResolvedValue([
            makeClaim({ claimantLnurl: 'alice@wallet.com', lnurlPrivate: false }),
        ]);

        const res = await request(app).get(`/bounties/${BOUNTY_ID}/pending-claim`);
        expect(res.status).toBe(200);
        expect(res.body.claimantLnurl).toBe('alice@wallet.com');
        expect(res.body.lnurlHidden).toBe(false);
        expect(res.body.id).toBe(CLAIM_ID);
    });

    it('redacts the LNURL from the creator when the claimant made it private', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ creatorId: TEST_PUBKEY })
        );
        (mockDb.query.claims.findMany as jest.Mock).mockResolvedValue([
            makeClaim({ claimantLnurl: 'alice@wallet.com', lnurlPrivate: true }),
        ]);

        const res = await request(app).get(`/bounties/${BOUNTY_ID}/pending-claim`);
        expect(res.status).toBe(200);
        // The real destination never reaches the creator's client…
        expect(res.body.claimantLnurl).toBeNull();
        expect(res.body.lnurlHidden).toBe(true);
        // …but the claimId the creator needs to approve is still present.
        expect(res.body.id).toBe(CLAIM_ID);
        // Belt-and-suspenders: the address must not leak anywhere in the body.
        expect(JSON.stringify(res.body)).not.toContain('alice@wallet.com');
    });

    it('returns EVERY open claim so the creator picks the recipient, not the server', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ creatorId: TEST_PUBKEY })
        );
        (mockDb.query.claims.findMany as jest.Mock).mockResolvedValue([
            makeClaim({ id: OTHER_CLAIM_ID, claimantPubkey: 'e'.repeat(64) }),
            makeClaim({ id: CLAIM_ID, claimantPubkey: CLAIMANT_PUBKEY }),
        ]);

        const res = await request(app).get(`/bounties/${BOUNTY_ID}/pending-claim`);
        expect(res.status).toBe(200);
        expect(res.body.claims).toHaveLength(2);
        expect(res.body.claims.map((c: any) => c.id)).toEqual([OTHER_CLAIM_ID, CLAIM_ID]);
        // Backward-compatible top-level shape is still the newest claim.
        expect(res.body.id).toBe(OTHER_CLAIM_ID);
    });

    it('discloses claimantPubkey even when the claimant hid their LNURL', async () => {
        // Hiding a payout *address* is a supported privacy choice; hiding *who
        // is being paid* from the payer is what made a substituted claim
        // invisible at the confirmation dialog.
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ creatorId: TEST_PUBKEY })
        );
        (mockDb.query.claims.findMany as jest.Mock).mockResolvedValue([
            makeClaim({ claimantLnurl: 'alice@wallet.com', lnurlPrivate: true }),
        ]);

        const res = await request(app).get(`/bounties/${BOUNTY_ID}/pending-claim`);
        expect(res.status).toBe(200);
        expect(res.body.claimantLnurl).toBeNull();
        expect(res.body.claimantPubkey).toBe(CLAIMANT_PUBKEY);
    });
});

// ============================================================================
describe('POST /bounties/:id/approve', () => {

    it('returns 400 when claimId is missing from request body', async () => {
        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({});
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/Validation failed/);
    });

    it('returns 400 for a non-UUID bounty id', async () => {
        const res = await request(app).post('/bounties/not-a-uuid/approve');
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/Invalid bounty ID/);
    });

    it('returns 404 when bounty does not exist', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(null);

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });
        expect(res.status).toBe(404);
    });

    it('returns 403 when requester does not own the bounty', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ creatorId: OTHER_PUBKEY, claims: [{ status: 'pending' }] })
        );

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });
        expect(res.status).toBe(403);
        expect(res.body.error).toMatch(/Forbidden/);
    });

    it('returns 404 when bounty has no pending claim', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty()
        );
        // claims.findFirst returns null by default (beforeEach) — no claim with this ID

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });
        expect(res.status).toBe(404);
        expect(res.body.error).toMatch(/Claim not found/);
    });

    it('returns a benign CLAIM_ALREADY_APPROVED (409) for a duplicate approve of a paid claim', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty()
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
            makeClaim({ status: 'approved', payoutTxid: 'preimage-abc' })
        );

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });
        // 409, not 400 — and a machine-readable code so the client can treat a
        // duplicate/concurrent approve as benign instead of a scary failure.
        expect(res.status).toBe(409);
        expect(res.body.code).toBe('CLAIM_ALREADY_APPROVED');
        expect(res.body.payoutTxid).toBe('preimage-abc');
    });

    it('returns CLAIM_IN_PROGRESS (409) when the claim is mid-approval', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty()
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
            makeClaim({ status: 'approving' })
        );

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });
        expect(res.status).toBe(409);
        expect(res.body.code).toBe('CLAIM_IN_PROGRESS');
    });

    it('returns 404 when no claim record is found in claims table', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty()
        );
        // claims.findFirst returns null by default — no claim with this ID

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });
        expect(res.status).toBe(404);
        expect(res.body.error).toMatch(/Claim not found/);
    });

    it('triggers payout and returns checking_id on success', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ claims: [{ status: 'pending' }] })
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
        mockLnbits.createLnbitsPayout.mockResolvedValue({
            checking_id: 'payout-check-id',
        } as any);
        // Non-empty returning() → the pending→approving lock is acquired.
        mockUpdate([{ id: 'claim-id-1' }]);

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.checking_id).toBe('payout-check-id');
    });

    it('takes the claim lock (pending→approving) before paying out', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ claims: [{ status: 'pending' }] })
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
        mockLnbits.createLnbitsPayout.mockResolvedValue({ checking_id: 'cid' } as any);
        mockUpdate([{ id: 'claim-id-1' }]);

        await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        // First db.update is the atomic lock: status → 'approving', carrying the
        // bookkeeping needed to reconcile the attempt if its outcome is lost.
        const setCalls = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls;
        expect(setCalls[0][0]).toEqual(expect.objectContaining({ status: 'approving' }));
    });

    it('returns 409 and does NOT pay out when the claim lock is lost (concurrent approve)', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ claims: [{ status: 'pending' }] })
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
        // Empty returning() → another request already flipped the claim, so the
        // conditional UPDATE matched zero rows: we must bail without paying.
        mockUpdate([]);

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });
        expect(res.status).toBe(409);
        expect(res.body.error).toMatch(/already being approved/i);
        expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
    });

    it('uses authenticated pubkey as approvedBy', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ claims: [{ status: 'pending' }] })
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
        mockLnbits.createLnbitsPayout.mockResolvedValue({ checking_id: 'cid' } as any);
        mockUpdate([{ id: 'claim-id-1' }]);

        await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        // All db.update() calls share one mock, so set() accumulates every call:
        // [lock {status:'approving'}, bounty {active:false}, claim {approved…}].
        // Find the finalizing claim update and assert it stamps approvedBy.
        const setCalls = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls;
        const approvedSet = setCalls.map((c: any[]) => c[0]).find((arg: any) => 'approvedBy' in arg);
        expect(approvedSet?.approvedBy).toBe(TEST_PUBKEY);
        expect(approvedSet?.status).toBe('approved');
    });

    it('returns 500 and releases the lock when payout fails', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ claims: [{ status: 'pending' }] })
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
        // Lock acquired, then the payout throws.
        mockUpdate([{ id: 'claim-id-1' }]);
        mockLnbits.createLnbitsPayout.mockRejectedValue(new Error('payout failed'));

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });
        expect(res.status).toBe(500);
        // The lock is released: a later set() reverts status → 'pending' and
        // clears the payout bookkeeping, which only ever describes the attempt
        // currently holding the lock.
        const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
            (c: any[]) => c[0]
        );
        expect(setArgs).toContainEqual(expect.objectContaining({
            status: 'pending',
            payoutPaymentHash: null,
            payoutBolt11: null,
            approvingAt: null,
        }));
    });

    it('returns 409 REFUND_IN_PROGRESS when a refund started after the bounty was read', async () => {
        // Refund-vs-approve TOCTOU: the bounty is read before the claim lock is
        // taken; a refund that took its own lock in between must stop this
        // approve from paying the claimant on top of the creator's refund.
        (mockDb.query.bounties.findFirst as jest.Mock)
            .mockResolvedValueOnce(makeBounty({ claims: [{ status: 'pending' }] }))
            // Post-lock re-read: the refund lock marker is now stamped.
            .mockResolvedValueOnce(makeBounty({ refundAt: new Date() }));
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
        mockUpdate([{ id: 'claim-id-1' }]);

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        expect(res.status).toBe(409);
        expect(res.body.code).toBe('REFUND_IN_PROGRESS');
        expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        // The claim lock was released (status reverts to 'pending').
        const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
            (c: any[]) => c[0]
        );
        expect(setArgs).toContainEqual(expect.objectContaining({ status: 'pending' }));
    });

    it('custodial payout outcome unknown → 502 PAYOUT_OUTCOME_UNKNOWN, claim lock KEPT', async () => {
        // A throw from the pay step (timeout after commit, unreadable success
        // body) is not proof of non-payment — reconcile by payment hash, and
        // unless LNbits proves no payment exists, never release for a retry.
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ claims: [{ status: 'pending' }] })
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
        mockUpdate([{ id: 'claim-id-1' }]);
        mockLnbits.createLnbitsPayout.mockRejectedValue(
            new FakeLnbitsPayoutErrorCtor('LNbits payout request failed: timeout', 'pay-hash-3')
        );
        (mockLnbits.lookupLnbitsPayment as jest.Mock).mockResolvedValue('unknown');

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        expect(res.status).toBe(502);
        expect(res.body.code).toBe('PAYOUT_OUTCOME_UNKNOWN');
        // The lock is NOT released: no set() reverts status to 'pending', and
        // the claim is never finalized to 'approved' either.
        const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
            (c: any[]) => c[0]
        );
        expect(setArgs).not.toContainEqual(expect.objectContaining({ status: 'pending' }));
        expect(setArgs).not.toContainEqual(expect.objectContaining({ status: 'approved' }));
        expect(security.alertAnomaly).toHaveBeenCalled();
    });

    it('custodial payout provably unpaid (reconcile not-found) → 502, lock released', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ claims: [{ status: 'pending' }] })
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
        mockUpdate([{ id: 'claim-id-1' }]);
        mockLnbits.createLnbitsPayout.mockRejectedValue(
            new FakeLnbitsPayoutErrorCtor('LNbits payout error: 520 - must reserve at least 10 sat for routing fees', 'pay-hash-4')
        );
        (mockLnbits.lookupLnbitsPayment as jest.Mock).mockResolvedValue('not-found');

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        expect(res.status).toBe(502);
        expect(res.body.error).toMatch(/LNbits payout error/);
        const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
            (c: any[]) => c[0]
        );
        expect(setArgs).toContainEqual(expect.objectContaining({ status: 'pending' }));
    });

    // ── Claimant binding (anti-hijack) ────────────────────────────────────
    //
    // `claimId` alone never protected against the attack it looks like it
    // does: the client reads that id from /pending-claim, and the server used
    // to hand back whichever claim was newest — so anyone could file a claim
    // and become the recipient the creator approved. The recipient must be
    // named by the creator, who is the only party that knows (out-of-band)
    // whose work this is.
    describe('claimant binding', () => {
        const ATTACKER_PUBKEY = 'e'.repeat(64);

        beforeEach(() => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ claims: [{ status: 'pending' }] })
            );
            mockUpdate([{ id: CLAIM_ID }]);
            mockLnbits.createLnbitsPayout.mockResolvedValue({ checking_id: 'chk_1' } as any);
        });

        it('refuses to pay when several claims are open and no claimant is named', async () => {
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
            (mockDb.query.claims.findMany as jest.Mock).mockResolvedValue([
                { id: OTHER_CLAIM_ID, claimantPubkey: ATTACKER_PUBKEY },
                { id: CLAIM_ID, claimantPubkey: CLAIMANT_PUBKEY },
            ]);

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/approve`)
                .send({ claimId: CLAIM_ID });

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('MULTIPLE_OPEN_CLAIMS');
            expect(res.body.openClaimCount).toBe(2);
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        it('pays when the named claimant matches the claim', async () => {
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
            (mockDb.query.claims.findMany as jest.Mock).mockResolvedValue([
                { id: OTHER_CLAIM_ID, claimantPubkey: ATTACKER_PUBKEY },
                { id: CLAIM_ID, claimantPubkey: CLAIMANT_PUBKEY },
            ]);

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/approve`)
                .send({ claimId: CLAIM_ID, claimantPubkey: CLAIMANT_PUBKEY });

            expect(res.status).toBe(200);
            expect(mockLnbits.createLnbitsPayout).toHaveBeenCalled();
        });

        it('refuses when the claim belongs to a different claimant than the one named', async () => {
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
                makeClaim({ claimantPubkey: ATTACKER_PUBKEY })
            );
            (mockDb.query.claims.findMany as jest.Mock).mockResolvedValue([
                { id: CLAIM_ID, claimantPubkey: ATTACKER_PUBKEY },
            ]);

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/approve`)
                .send({ claimId: CLAIM_ID, claimantPubkey: CLAIMANT_PUBKEY });

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('CLAIMANT_MISMATCH');
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        it('refuses to match a named claimant against a legacy claim with no identity', async () => {
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
                makeClaim({ claimantPubkey: null })
            );
            (mockDb.query.claims.findMany as jest.Mock).mockResolvedValue([
                { id: CLAIM_ID, claimantPubkey: null },
            ]);

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/approve`)
                .send({ claimId: CLAIM_ID, claimantPubkey: CLAIMANT_PUBKEY });

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('CLAIMANT_UNVERIFIABLE');
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        it('still pays a single open claim without a named claimant (older clients)', async () => {
            // One open claim is unambiguous: it IS the claim the creator saw.
            // Older extensions never send `claimantPubkey`, and the attack
            // requires ADDING a claim — which creates the ambiguity that the
            // guard above refuses. So old clients stay working, and fail closed
            // exactly when it matters.
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
            (mockDb.query.claims.findMany as jest.Mock).mockResolvedValue([
                { id: CLAIM_ID, claimantPubkey: CLAIMANT_PUBKEY },
            ]);

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/approve`)
                .send({ claimId: CLAIM_ID });

            expect(res.status).toBe(200);
            expect(mockLnbits.createLnbitsPayout).toHaveBeenCalled();
        });

        it('rejects a malformed claimantPubkey', async () => {
            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/approve`)
                .send({ claimId: CLAIM_ID, claimantPubkey: 'not-a-pubkey' });

            expect(res.status).toBe(400);
            expect(res.body.error).toBe('Validation failed');
        });
    });

    // ── Payout guards run AFTER the lock, and release it on failure ────────
    it('releases the claim lock when a payout guard trips', async () => {
        // The guards moved behind the lock so concurrent approvals publish an
        // `approving` row (which the caps count) before any total is read. A
        // tripped guard must therefore put the claim back to `pending` rather
        // than stranding it — the pre-move behaviour left it pending by never
        // locking at all.
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ claims: [{ status: 'pending' }] })
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
        (mockDb.query.claims.findMany as jest.Mock).mockResolvedValue([
            { id: CLAIM_ID, claimantPubkey: CLAIMANT_PUBKEY },
        ]);
        mockUpdate([{ id: CLAIM_ID }]);
        (security.evaluatePayoutGuards as jest.Mock).mockResolvedValue({
            ok: false,
            reason: 'Hourly payout cap exceeded',
            status: 429,
        });

        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/approve`)
            .send({ claimId: CLAIM_ID });

        expect(res.status).toBe(429);
        expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
            (c: any[]) => c[0]
        );
        expect(setArgs).toContainEqual(expect.objectContaining({
            status: 'pending',
            payoutPaymentHash: null,
            payoutBolt11: null,
            approvingAt: null,
        }));
    });

    it('fails fast on the kill switch, before minting a claimant invoice', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ fundingMode: 'nwc', claims: [{ status: 'pending' }] })
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
        (security.payoutsEnabled as jest.Mock).mockReturnValue(false);

        const res = await request(app)
            .post(`/bounties/${BOUNTY_ID}/approve`)
            .send({ claimId: CLAIM_ID });

        expect(res.status).toBe(503);
        expect(mockNwc.lookupInvoiceFromLnurl).not.toHaveBeenCalled();
        expect(mockDb.update).not.toHaveBeenCalled();
    });

    // ── Inactive bounties can't originate a new payout ─────────────────────
    //
    // Removal, a refund, and a successful approve all set active=false. In each
    // case the money is already spent or has gone back to the creator, so a new
    // payout would be a second spend of the same bounty.
    describe('inactive bounty', () => {
        it('refuses to pay out a pending claim on a removed bounty', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ active: false, claims: [{ status: 'pending' }] })
            );
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
            mockUpdate([{ id: 'claim-id-1' }]);

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/approve`)
                .send({ claimId: CLAIM_ID });

            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/no longer active/i);
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
            // Never even took the lock.
            expect(mockDb.update).not.toHaveBeenCalled();
        });

        it('refuses a SECOND claim on a bounty already paid out to someone else', async () => {
            // Chain B: approving claim A deactivates the bounty; claimant B then
            // files a new claim. Without the active check, approving B fires a
            // second payout for the same bounty.
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({
                    active: false,
                    claims: [{ status: 'approved' }, { status: 'pending' }],
                })
            );
            // The caller names claim B, which is genuinely still pending.
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
                makeClaim({ id: '33333333-3333-4333-8333-333333333333', status: 'pending' })
            );
            mockUpdate([{ id: 'claim-b' }]);

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/approve`)
                .send({ claimId: '33333333-3333-4333-8333-333333333333' });

            expect(res.status).toBe(400);
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
        });

        // ── Ordering proofs ────────────────────────────────────────────────
        // A successful approve sets active=false itself, so the guard above has
        // to sit AFTER the claim-status branches. If it ever gets hoisted, these
        // two break.
        it('still returns the benign CLAIM_ALREADY_APPROVED for a duplicate on an inactive bounty', async () => {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ active: false, claims: [{ status: 'approved' }] })
            );
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
                makeClaim({ status: 'approved', payoutTxid: 'preimage-abc' })
            );

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/approve`)
                .send({ claimId: CLAIM_ID });

            // Benign 409, NOT the 400 "no longer active" — a duplicate approve
            // of a paid claim must never surface as a failure.
            expect(res.status).toBe(409);
            expect(res.body.code).toBe('CLAIM_ALREADY_APPROVED');
            expect(res.body.payoutTxid).toBe('preimage-abc');
        });

        it('still reconciles a held claim on an inactive bounty', async () => {
            // A claim held after an unconfirmed payout must stay reconcilable
            // even once the bounty is inactive — otherwise the dead end this
            // whole flow exists to remove comes straight back.
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({
                    active: false,
                    fundingMode: 'nwc',
                    claims: [{ status: 'approving' }],
                })
            );
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
                // Still the same wallet, so the lookup path is available — the
                // point here is that `active: false` doesn't block reconciling.
                makeClaim({
                    status: 'approving',
                    payoutPaymentHash: 'hash-xyz',
                    payoutWalletPubkey: WALLET_PUBKEY,
                })
            );
            (mockDb.query.users.findFirst as jest.Mock).mockResolvedValue(makeUser({
                encryptedNwcUri: 'enc:nostr+walletconnect://abc',
            }));
            mockNwc.walletPubkeyFromNwcUri.mockReturnValue(WALLET_PUBKEY);
            mockNwc.lookupNwcPayment.mockResolvedValue({ state: 'settled', preimage: 'late-pre' });
            mockUpdate([{ id: 'claim-id-1' }]);

            const res = await request(app)
                .post(`/bounties/${BOUNTY_ID}/approve`)
                .send({ claimId: CLAIM_ID });

            expect(res.body.code).toBe('CLAIM_ALREADY_APPROVED');
            expect(res.body.payoutTxid).toBe('late-pre');
        });
    });

    it('keeps the claim LOCKED when the payout succeeded but finalizing threw', async () => {
        // The sats already left the wallet; only the bookkeeping failed.
        // Releasing here would let someone approve — and pay — a second time.
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ claims: [{ status: 'pending' }] })
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
        mockLnbits.createLnbitsPayout.mockResolvedValue({ checking_id: 'paid-cid' } as any);

        // Lock acquires, then every subsequent update (the finalize) throws.
        let call = 0;
        (mockDb.update as jest.Mock).mockImplementation(() => {
            call += 1;
            if (call === 1) {
                return {
                    set: jest.fn().mockReturnValue({
                        where: jest.fn().mockReturnValue({
                            returning: jest.fn().mockResolvedValue([{ id: 'claim-id-1' }]),
                        }),
                    }),
                };
            }
            throw new Error('db write failed');
        });

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        expect(res.status).toBe(500);
        // Only the lock update ran; no release was attempted.
        const lockSet = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls[0][0];
        expect(lockSet).toEqual(expect.objectContaining({ status: 'approving' }));
        const security = require('./security') as { alertAnomaly: jest.Mock };
        expect(security.alertAnomaly).toHaveBeenCalledWith(
            expect.objectContaining({ reason: expect.stringMatching(/sent but/i) })
        );
    });
});

// ============================================================================
describe('PATCH /bounties/:id/update-paid', () => {
    it('returns 400 for a non-UUID bounty id', async () => {
        const res = await request(app).patch('/bounties/not-a-uuid/update-paid');
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/Invalid bounty ID/);
    });

    it('returns 404 when bounty does not exist', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(null);

        const res = await request(app).patch(`/bounties/${BOUNTY_ID}/update-paid`);
        expect(res.status).toBe(404);
    });

    it('returns 403 when the caller does not own the bounty', async () => {
        // Every sibling bounty-scoped handler gates on ownership; this one did
        // not, so any authenticated key could force a paid-status refresh on a
        // stranger's bounty (and spend our LNbits rate budget doing it).
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ creatorId: OTHER_PUBKEY })
        );

        const res = await request(app).patch(`/bounties/${BOUNTY_ID}/update-paid`);
        expect(res.status).toBe(403);
        expect(res.body.error).toMatch(/do not own this bounty/);
        expect(mockLnbits.checkLnbitsInvoicePaid).not.toHaveBeenCalled();
    });

    it('updates invoicePaid and returns 200 when status differs', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: false })
        );
        mockLnbits.checkLnbitsInvoicePaid.mockResolvedValue({ paid: true });
        mockUpdate();

        const res = await request(app).patch(`/bounties/${BOUNTY_ID}/update-paid`);
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(mockDb.update).toHaveBeenCalled();
    });

    it('returns 200 with updated:false when paid status is already in sync', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true })
        );
        mockLnbits.checkLnbitsInvoicePaid.mockResolvedValue({ paid: true });

        const res = await request(app).patch(`/bounties/${BOUNTY_ID}/update-paid`);
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, updated: false });
    });

    it('returns 500 on LNbits error', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(makeBounty());
        mockLnbits.checkLnbitsInvoicePaid.mockRejectedValue(new Error('lnbits error'));

        const res = await request(app).patch(`/bounties/${BOUNTY_ID}/update-paid`);
        expect(res.status).toBe(500);
    });

    it('returns 200 with success when invoice transitions to paid', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: false })
        );
        mockLnbits.checkLnbitsInvoicePaid.mockResolvedValue({ paid: true });
        mockUpdate();

        const res = await request(app).patch(`/bounties/${BOUNTY_ID}/update-paid`);

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true });
        // No per-user LNbits wallet should be provisioned — Treasury/Payout
        // wallets handle custody, and NWC handles non-custodial creators.
        expect(res.body.wallet).toBeUndefined();
        // The bounty row was updated to paid=true.
        expect(mockDb.update).toHaveBeenCalled();
    });

    it('returns 200 when invoice transitions to unpaid', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ invoicePaid: true })
        );
        mockLnbits.checkLnbitsInvoicePaid.mockResolvedValue({ paid: false });
        mockUpdate();

        const res = await request(app).patch(`/bounties/${BOUNTY_ID}/update-paid`);

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true });
    });
});

// ============================================================================
describe('NWC user routes', () => {
    const GOOD_URI = `nostr+walletconnect://${'a'.repeat(64)}?relay=wss%3A%2F%2Frelay.example.com&secret=${'b'.repeat(64)}`;

    describe('PATCH /users/me/nwc', () => {
        it('stores an encrypted URI and returns { configured: true }', async () => {
            mockInsert([]);
            mockNwc.validateNwcUri.mockImplementation(() => { /* ok */ });

            const res = await request(app)
                .patch('/users/me/nwc')
                .send({ uri: GOOD_URI, budgetSats: 10_000, budgetWindow: 'daily' });

            expect(res.status).toBe(200);
            expect(res.body).toEqual({ configured: true });
            // URI is encrypted before it hits the DB and never echoed back.
            const valuesCall = (mockDb.insert as jest.Mock).mock.results[0].value.values.mock.calls[0][0];
            expect(valuesCall.encryptedNwcUri).toBe(`enc:${GOOD_URI}`);
            expect(JSON.stringify(res.body)).not.toContain(GOOD_URI);
        });

        it('returns 400 when the URI fails validation', async () => {
            mockNwc.validateNwcUri.mockImplementation(() => {
                throw new Error('NWC URI must use the nostr+walletconnect:// scheme');
            });

            const res = await request(app).patch('/users/me/nwc').send({ uri: 'http://nope' });
            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/scheme/);
            // Not inserted.
            expect((mockDb.insert as jest.Mock)).not.toHaveBeenCalled();
        });

        it('returns 400 when the body is empty', async () => {
            const res = await request(app).patch('/users/me/nwc').send({});
            expect(res.status).toBe(400);
            expect(res.body.error).toBe('Validation failed');
        });
    });

    describe('DELETE /users/me/nwc', () => {
        it('clears the stored connection', async () => {
            mockUpdate();
            const res = await request(app).delete('/users/me/nwc');
            expect(res.status).toBe(200);
            expect(res.body).toEqual({ configured: false });
            expect(mockDb.update).toHaveBeenCalled();
        });

        it('is gated by nostrAuth (read scope), NOT moneyAuth', async () => {
            // Disconnect must work without a live signer: it uses the read-path
            // middleware, so revoking a wallet never needs the money nonce.
            const { nostrAuth, moneyAuth } = require('./middleware/auth');
            (nostrAuth as jest.Mock).mockClear();
            (moneyAuth as jest.Mock).mockClear();
            mockUpdate();

            await request(app).delete('/users/me/nwc');

            expect(nostrAuth).toHaveBeenCalled();
            expect(moneyAuth).not.toHaveBeenCalled();
        });
    });

    describe('GET /users/me/nwc-status', () => {
        it('returns configured:false when no URI is stored', async () => {
            (mockDb.query.users.findFirst as jest.Mock).mockResolvedValue(null);
            const res = await request(app).get('/users/me/nwc-status');
            expect(res.status).toBe(200);
            expect(res.body.configured).toBe(false);
        });

        it('returns configured:true + budget fields + safe wallet summary when stored', async () => {
            // crypto.decrypt is mocked to strip the "enc:" prefix, so the
            // stored value decrypts to a real NWC URI the handler can summarize.
            const secret = 'b'.repeat(64);
            const uri =
                `nostr+walletconnect://${'a'.repeat(64)}` +
                `?relay=${encodeURIComponent('wss://relay.getalby.com/v1')}` +
                `&secret=${secret}` +
                `&lud16=${encodeURIComponent('alice@getalby.com')}`;
            (mockDb.query.users.findFirst as jest.Mock).mockResolvedValue({
                encryptedNwcUri: `enc:${uri}`,
                nwcBudgetSats: 10_000,
                nwcBudgetWindow: 'daily',
                nwcUpdatedAt: new Date('2026-01-01T00:00:00Z'),
            });
            const res = await request(app).get('/users/me/nwc-status');
            expect(res.status).toBe(200);
            expect(res.body.configured).toBe(true);
            expect(res.body.budgetSats).toBe(10_000);
            expect(res.body.budgetWindow).toBe('daily');
            // Public wallet identity surfaced for the creation-time prompt.
            expect(res.body.relay).toBe('relay.getalby.com');
            expect(res.body.lud16).toBe('alice@getalby.com');
            // Neither the URI nor the spending secret may ever leak.
            const body = JSON.stringify(res.body);
            expect(body).not.toContain('enc:');
            expect(body).not.toContain('nostr+walletconnect://');
            expect(body).not.toContain(secret);
        });

        it('degrades to null relay/lud16 when the stored URI is unparseable', async () => {
            (mockDb.query.users.findFirst as jest.Mock).mockResolvedValue({
                encryptedNwcUri: 'enc:not-a-valid-uri',
                nwcUpdatedAt: new Date('2026-01-01T00:00:00Z'),
            });
            const res = await request(app).get('/users/me/nwc-status');
            expect(res.status).toBe(200);
            expect(res.body.configured).toBe(true);
            expect(res.body.relay).toBeNull();
            expect(res.body.lud16).toBeNull();
        });
    });
});

// ============================================================================
describe('POST /bounties — fundingMode: nwc', () => {
    const validBody = { testId: 'test-nwc', amountSats: 5000, fundingMode: 'nwc' as const };

    it('creates an NWC bounty without calling LNbits when user has a URI', async () => {
        (mockDb.query.users.findFirst as jest.Mock).mockResolvedValue(makeUser({
            encryptedNwcUri: 'enc:nostr+walletconnect://abc',
        }));
        mockInsert([makeBounty({ fundingMode: 'nwc', invoice: null, paymentHash: null, invoicePaid: true })]);

        const res = await request(app).post('/bounties').send(validBody);

        expect(res.status).toBe(201);
        expect(mockLnbits.createLnbitsInvoice).not.toHaveBeenCalled();
        const valuesCall = (mockDb.insert as jest.Mock).mock.results[0].value.values.mock.calls[0][0];
        expect(valuesCall.fundingMode).toBe('nwc');
        expect(valuesCall.invoice).toBeNull();
        expect(valuesCall.paymentHash).toBeNull();
        expect(valuesCall.invoicePaid).toBe(true);
    });

    it('returns 400 when the creator has not connected a wallet', async () => {
        (mockDb.query.users.findFirst as jest.Mock).mockResolvedValue(null);

        const res = await request(app).post('/bounties').send(validBody);

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/Connect a Lightning wallet/);
        expect(mockLnbits.createLnbitsInvoice).not.toHaveBeenCalled();
    });

    it('falls through to the custodial path when fundingMode is omitted', async () => {
        mockLnbits.createLnbitsInvoice.mockResolvedValue({ payment_request: 'lnbc_x', payment_hash: VALID_HASH });
        mockInsert([makeBounty()]);

        const res = await request(app).post('/bounties').send({ testId: 't', amountSats: 100 });
        expect(res.status).toBe(201);
        expect(mockLnbits.createLnbitsInvoice).toHaveBeenCalled();
    });
});

// ============================================================================
describe('POST /bounties — custodial disabled (default)', () => {
    // The top-level beforeEach turns custodial ON for the legacy route tests;
    // here we assert the production default where it's OFF.
    beforeEach(() => {
        process.env.ALLOW_CUSTODIAL_BOUNTIES = 'false';
    });

    it('defaults to NWC when fundingMode is omitted and the user has a wallet', async () => {
        (mockDb.query.users.findFirst as jest.Mock).mockResolvedValue(makeUser({
            encryptedNwcUri: 'enc:nostr+walletconnect://abc',
        }));
        mockInsert([makeBounty({ fundingMode: 'nwc', invoice: null, paymentHash: null, invoicePaid: true })]);

        const res = await request(app).post('/bounties').send({ testId: 't', amountSats: 5000 });

        expect(res.status).toBe(201);
        // No fundingMode in the body, custodial off → NWC, no LNbits invoice.
        expect(mockLnbits.createLnbitsInvoice).not.toHaveBeenCalled();
        const valuesCall = (mockDb.insert as jest.Mock).mock.results[0].value.values.mock.calls[0][0];
        expect(valuesCall.fundingMode).toBe('nwc');
    });

    it('returns 400 when defaulting to NWC but the user has no wallet', async () => {
        (mockDb.query.users.findFirst as jest.Mock).mockResolvedValue(null);

        const res = await request(app).post('/bounties').send({ testId: 't', amountSats: 5000 });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/Connect a Lightning wallet/);
        expect(mockLnbits.createLnbitsInvoice).not.toHaveBeenCalled();
    });

    it('rejects an explicit custodial request with 400', async () => {
        const res = await request(app)
            .post('/bounties')
            .send({ testId: 't', amountSats: 5000, fundingMode: 'custodial' });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/Custodial bounties are currently disabled/);
        expect(mockLnbits.createLnbitsInvoice).not.toHaveBeenCalled();
    });
});

// ============================================================================
describe('POST /bounties/:id/approve — fundingMode: nwc', () => {
    function mockNwcBountyApproveSetup() {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ fundingMode: 'nwc', invoice: null, paymentHash: null, invoicePaid: true,
                         claims: [{ status: 'pending' }] })
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
            makeClaim({ claimantLnurl: 'alice@example.com' })
        );
        (mockDb.query.users.findFirst as jest.Mock).mockResolvedValue(makeUser({
            encryptedNwcUri: 'enc:nostr+walletconnect://abc',
        }));
        // Non-empty returning() so the pending→approving lock is acquired.
        mockUpdate([{ id: 'claim-id-1' }]);
    }

    it('pays the claimant via NWC on the happy path', async () => {
        mockNwcBountyApproveSetup();
        mockNwc.lookupInvoiceFromLnurl.mockResolvedValue('lnbc1fake');
        mockNwc.createNwcPayout.mockResolvedValue({ preimage: 'deadbeef', feesPaidSats: 0 });

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, checking_id: 'deadbeef' });
        expect(mockNwc.createNwcPayout).toHaveBeenCalledWith(
            'enc:nostr+walletconnect://abc',
            'lnbc1fake',
            1000,
        );
        // Critically, the custodial payout path is untouched.
        expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();
    });

    it('returns 400 when LNURL lookup fails (claim stays pending)', async () => {
        mockNwcBountyApproveSetup();
        mockNwc.lookupInvoiceFromLnurl.mockRejectedValue(new Error('LNURL unreachable'));

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/LNURL unreachable/);
        expect(mockNwc.createNwcPayout).not.toHaveBeenCalled();
        // Claim was not flipped to approved.
        expect(mockDb.update).not.toHaveBeenCalled();
    });

    it('returns 502 when the NWC wallet refuses the payment', async () => {
        mockNwcBountyApproveSetup();
        mockNwc.lookupInvoiceFromLnurl.mockResolvedValue('lnbc1fake');
        // outcome 'failed' — the wallet explicitly declined, so nothing was paid.
        mockNwc.createNwcPayout.mockRejectedValue(
            new FakeNwcPayoutError('budget exceeded', undefined, 'failed')
        );

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        expect(res.status).toBe(502);
        expect(res.body.error).toMatch(/budget exceeded/);
        // The lock was taken then released (status reverts to 'pending'); the
        // claim is never finalized to 'approved'.
        const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
            (c: any[]) => c[0]
        );
        expect(setArgs).not.toContainEqual(expect.objectContaining({ status: 'approved' }));
        expect(setArgs).toContainEqual(expect.objectContaining({ status: 'pending' }));
    });

    // ── Unknown payout outcome (the double-spend guard) ────────────────────
    //
    // A NIP-47 reply timeout means the request was published but no answer came
    // back — the wallet may well have paid. Releasing the lock here would let a
    // retry mint a *second* invoice and pay the claimant twice, so the claim
    // must stay locked until the wallet can be asked directly.
    it('keeps the claim LOCKED when the payout outcome is unknown (reply timeout)', async () => {
        mockNwcBountyApproveSetup();
        mockNwc.lookupInvoiceFromLnurl.mockResolvedValue('lnbc1fake');
        mockNwc.createNwcPayout.mockRejectedValue(
            new FakeNwcPayoutError('reply timeout: event abc123', undefined, 'unknown')
        );

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        expect(res.status).toBe(502);
        expect(res.body.code).toBe('PAYOUT_OUTCOME_UNKNOWN');
        // The raw SDK message must not reach the user as a plain failure.
        expect(res.body.error).toMatch(/could not confirm/i);

        const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
            (c: any[]) => c[0]
        );
        // Locked, and never unlocked or finalized.
        expect(setArgs).toContainEqual(expect.objectContaining({ status: 'approving' }));
        expect(setArgs).not.toContainEqual(expect.objectContaining({ status: 'pending' }));
        expect(setArgs).not.toContainEqual(expect.objectContaining({ status: 'approved' }));
    });

    it('defaults to keeping the lock when an NWC failure carries no outcome', async () => {
        mockNwcBountyApproveSetup();
        mockNwc.lookupInvoiceFromLnurl.mockResolvedValue('lnbc1fake');
        // No explicit outcome → must be treated as unknown, not as a failure.
        mockNwc.createNwcPayout.mockRejectedValue(new FakeNwcPayoutError('something odd'));

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        expect(res.body.code).toBe('PAYOUT_OUTCOME_UNKNOWN');
        const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
            (c: any[]) => c[0]
        );
        expect(setArgs).not.toContainEqual(expect.objectContaining({ status: 'pending' }));
    });

    it('records the payment hash and invoice with the lock so it can be reconciled', async () => {
        mockNwcBountyApproveSetup();
        mockNwc.lookupInvoiceFromLnurl.mockResolvedValue('lnbc1fake');
        mockNwc.paymentHashFromBolt11.mockReturnValue('hash-xyz');
        mockNwc.createNwcPayout.mockResolvedValue({ preimage: 'deadbeef', feesPaidSats: 0 });

        await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        const lockSet = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls[0][0];
        expect(lockSet).toEqual(expect.objectContaining({
            status: 'approving',
            payoutPaymentHash: 'hash-xyz',
            payoutBolt11: 'lnbc1fake',
            approvingAt: expect.any(Date),
        }));
    });

    // ── Reconciling a claim already stuck in `approving` ───────────────────
    describe('reconcile on approve of an already-locked claim', () => {
        function mockLockedClaim() {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({ fundingMode: 'nwc', invoice: null, paymentHash: null,
                             invoicePaid: true, claims: [{ status: 'approving' }] })
            );
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
                makeClaim({
                    status: 'approving',
                    claimantLnurl: 'alice@example.com',
                    payoutPaymentHash: 'hash-xyz',
                    payoutBolt11: 'lnbc1fake',
                    // Same wallet still connected → the lookup path is allowed.
                    payoutWalletPubkey: WALLET_PUBKEY,
                })
            );
            (mockDb.query.users.findFirst as jest.Mock).mockResolvedValue(makeUser({
                encryptedNwcUri: 'enc:nostr+walletconnect://abc',
            }));
            mockNwc.walletPubkeyFromNwcUri.mockReturnValue(WALLET_PUBKEY);
            mockUpdate([{ id: 'claim-id-1' }]);
        }

        it('finalizes the claim when the wallet confirms the earlier payment settled', async () => {
            mockLockedClaim();
            mockNwc.lookupNwcPayment.mockResolvedValue({ state: 'settled', preimage: 'late-preimage' });

            const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('CLAIM_ALREADY_APPROVED');
            expect(res.body.payoutTxid).toBe('late-preimage');
            // No second payment.
            expect(mockNwc.createNwcPayout).not.toHaveBeenCalled();
            const setArgs = (mockDb.update as jest.Mock).mock.results[0].value.set.mock.calls.map(
                (c: any[]) => c[0]
            );
            expect(setArgs).toContainEqual(expect.objectContaining({
                status: 'approved',
                payoutTxid: 'late-preimage',
            }));
        });

        it('unlocks and pays when the wallet confirms the earlier payment failed', async () => {
            mockLockedClaim();
            mockNwc.lookupNwcPayment.mockResolvedValue({ state: 'failed' });
            mockNwc.lookupInvoiceFromLnurl.mockResolvedValue('lnbc1fresh');
            mockNwc.createNwcPayout.mockResolvedValue({ preimage: 'deadbeef', feesPaidSats: 0 });

            const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

            expect(res.status).toBe(200);
            expect(mockNwc.createNwcPayout).toHaveBeenCalled();
        });

        it('holds the lock when the wallet still cannot confirm', async () => {
            mockLockedClaim();
            mockNwc.lookupNwcPayment.mockResolvedValue({ state: 'unknown', reason: 'NOT_IMPLEMENTED' });

            const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('CLAIM_IN_PROGRESS');
            expect(mockNwc.createNwcPayout).not.toHaveBeenCalled();
        });

        it('holds the lock while the payment is still settling', async () => {
            mockLockedClaim();
            mockNwc.lookupNwcPayment.mockResolvedValue({ state: 'pending' });

            const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('CLAIM_IN_PROGRESS');
            expect(mockNwc.createNwcPayout).not.toHaveBeenCalled();
        });

        it('holds the lock when there is no payment reference to look up', async () => {
            mockLockedClaim();
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
                makeClaim({ status: 'approving', payoutPaymentHash: null, payoutBolt11: null })
            );

            const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('CLAIM_IN_PROGRESS');
            expect(mockNwc.lookupNwcPayment).not.toHaveBeenCalled();
            expect(mockNwc.createNwcPayout).not.toHaveBeenCalled();
        });

        // ── Only the wallet that paid can be believed ──────────────────────
        //
        // A creator whose wallet died can connect a different one. That wallet
        // has never seen this payment, so nothing it says about it is evidence.
        it('does NOT query a different wallet than the one that made the payout', async () => {
            mockLockedClaim();
            // Creator has since reconnected a different wallet.
            mockNwc.walletPubkeyFromNwcUri.mockReturnValue(OTHER_WALLET_PUBKEY);

            const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('PAYOUT_NEEDS_CONFIRMATION');
            // The whole point: we never ask a wallet that can't know.
            expect(mockNwc.lookupNwcPayment).not.toHaveBeenCalled();
            expect(mockNwc.createNwcPayout).not.toHaveBeenCalled();
        });

        it('does not release the lock on a "failed" report from a different wallet', async () => {
            // The double-pay case: a replacement wallet reporting `failed` for a
            // hash it never saw must not unlock a payment the old wallet may
            // have settled.
            mockLockedClaim();
            mockNwc.walletPubkeyFromNwcUri.mockReturnValue(OTHER_WALLET_PUBKEY);
            mockNwc.lookupNwcPayment.mockResolvedValue({ state: 'failed' });

            const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

            expect(res.body.code).toBe('PAYOUT_NEEDS_CONFIRMATION');
            const setArgs = (mockDb.update as jest.Mock).mock.results.flatMap(
                (r: any) => r.value.set.mock.calls.map((c: any[]) => c[0])
            );
            expect(setArgs).not.toContainEqual(expect.objectContaining({ status: 'pending' }));
            expect(mockNwc.createNwcPayout).not.toHaveBeenCalled();
        });

        it('needs confirmation when the claim predates wallet-identity recording', async () => {
            mockLockedClaim();
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
                makeClaim({
                    status: 'approving',
                    payoutPaymentHash: 'hash-xyz',
                    payoutWalletPubkey: null,
                })
            );

            const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

            expect(res.body.code).toBe('PAYOUT_NEEDS_CONFIRMATION');
            expect(mockNwc.lookupNwcPayment).not.toHaveBeenCalled();
        });
    });

    // ── Creator-confirmed resolution of an unverifiable payout ─────────────
    describe('POST /bounties/:id/claims/:claimId/resolve', () => {
        const RESOLVE_URL = `/bounties/${BOUNTY_ID}/claims/${CLAIM_ID}/resolve`;

        function mockHeldClaim(bountyOverrides: Record<string, any> = {}) {
            (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
                makeBounty({
                    fundingMode: 'nwc', invoice: null, paymentHash: null, invoicePaid: true,
                    claims: [{ status: 'approving' }], ...bountyOverrides,
                })
            );
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
                makeClaim({
                    status: 'approving',
                    payoutPaymentHash: 'hash-xyz',
                    payoutWalletPubkey: WALLET_PUBKEY,
                })
            );
            mockUpdate([{ id: 'claim-id-1' }]);
        }

        it('closes the claim out as paid without sending a second payment', async () => {
            mockHeldClaim();

            const res = await request(app).post(RESOLVE_URL).send({ outcome: 'paid' });

            expect(res.status).toBe(200);
            expect(mockNwc.createNwcPayout).not.toHaveBeenCalled();
            expect(mockLnbits.createLnbitsPayout).not.toHaveBeenCalled();

            const setArgs = (mockDb.update as jest.Mock).mock.results.flatMap(
                (r: any) => r.value.set.mock.calls.map((c: any[]) => c[0])
            );
            expect(setArgs).toContainEqual(expect.objectContaining({
                status: 'approved',
                payoutResolution: 'creator-confirmed-paid',
            }));
            // No preimage exists, so payout_txid must not be fabricated.
            const approved = setArgs.find((a: any) => a.status === 'approved');
            expect(approved.payoutTxid).toBeUndefined();
        });

        it('unlocks the claim for retry when confirmed unpaid', async () => {
            mockHeldClaim();

            const res = await request(app).post(RESOLVE_URL).send({ outcome: 'not-paid' });

            expect(res.status).toBe(200);
            const setArgs = (mockDb.update as jest.Mock).mock.results.flatMap(
                (r: any) => r.value.set.mock.calls.map((c: any[]) => c[0])
            );
            expect(setArgs).toContainEqual(expect.objectContaining({
                status: 'pending',
                payoutPaymentHash: null,
                payoutBolt11: null,
                payoutWalletPubkey: null,
                payoutResolution: 'creator-confirmed-unpaid',
            }));
        });

        it('alerts an operator whichever way the creator resolves it', async () => {
            mockHeldClaim();

            await request(app).post(RESOLVE_URL).send({ outcome: 'paid' });

            expect(security.alertAnomaly).toHaveBeenCalledWith(
                expect.objectContaining({ reason: expect.stringMatching(/creator confirmed/i) })
            );
        });

        it('refuses on a custodial bounty — that would spend the house\'s money on a claim', async () => {
            mockHeldClaim({ fundingMode: 'custodial' });

            const res = await request(app).post(RESOLVE_URL).send({ outcome: 'paid' });

            expect(res.status).toBe(400);
            expect(res.body.error).toMatch(/non-custodial/i);
            expect(mockDb.update).not.toHaveBeenCalled();
        });

        it('refuses when the caller does not own the bounty', async () => {
            mockHeldClaim({ creatorId: OTHER_PUBKEY });

            const res = await request(app).post(RESOLVE_URL).send({ outcome: 'paid' });

            expect(res.status).toBe(403);
            expect(mockDb.update).not.toHaveBeenCalled();
        });

        it('refuses when the claim is not actually held', async () => {
            mockHeldClaim();
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
                makeClaim({ status: 'pending' })
            );

            const res = await request(app).post(RESOLVE_URL).send({ outcome: 'paid' });

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('CLAIM_NOT_HELD');
            expect(mockDb.update).not.toHaveBeenCalled();
        });

        it('is benign when the claim was already approved', async () => {
            mockHeldClaim();
            (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(
                makeClaim({ status: 'approved', payoutTxid: 'preimage-abc' })
            );

            const res = await request(app).post(RESOLVE_URL).send({ outcome: 'paid' });

            expect(res.status).toBe(409);
            expect(res.body.code).toBe('CLAIM_ALREADY_APPROVED');
        });

        it('rejects an unrecognised outcome', async () => {
            mockHeldClaim();

            const res = await request(app).post(RESOLVE_URL).send({ outcome: 'maybe' });

            expect(res.status).toBe(400);
            expect(mockDb.update).not.toHaveBeenCalled();
        });
    });

    it('returns 400 when the creator has disconnected their wallet between create + approve', async () => {
        (mockDb.query.bounties.findFirst as jest.Mock).mockResolvedValue(
            makeBounty({ fundingMode: 'nwc', invoice: null, paymentHash: null, invoicePaid: true,
                         claims: [{ status: 'pending' }] })
        );
        (mockDb.query.claims.findFirst as jest.Mock).mockResolvedValue(makeClaim());
        (mockDb.query.users.findFirst as jest.Mock).mockResolvedValue(makeUser({
            encryptedNwcUri: null,
        }));

        const res = await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/not connected/);
        expect(mockNwc.lookupInvoiceFromLnurl).not.toHaveBeenCalled();
    });

    it('skips payoutBalanceLooksSane for NWC bounties', async () => {
        const security = require('./security');
        mockNwcBountyApproveSetup();
        mockNwc.lookupInvoiceFromLnurl.mockResolvedValue('lnbc1fake');
        mockNwc.createNwcPayout.mockResolvedValue({ preimage: 'deadbeef', feesPaidSats: 0 });

        await request(app).post(`/bounties/${BOUNTY_ID}/approve`).send({ claimId: CLAIM_ID });

        expect(security.payoutBalanceLooksSane).not.toHaveBeenCalled();
        // But shared guards still run.
        expect(security.evaluatePayoutGuards).toHaveBeenCalled();
    });
});
