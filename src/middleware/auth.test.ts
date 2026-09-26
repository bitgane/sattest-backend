import { nostrAuth, moneyAuth, NostrAuthRequest } from './auth';
import { issueNonce, _resetNonceStoreForTests } from './nonce';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools';
import { Request, Response } from 'express';

beforeEach(() => {
    _resetNonceStoreForTests();
});

function makeAuthHeader(event: object): string {
    const json = JSON.stringify(event);
    return `Nostr ${Buffer.from(json).toString('base64')}`;
}

function mockReqRes(authHeader?: string) {
    const req = {
        headers: authHeader ? { authorization: authHeader } : {},
    } as NostrAuthRequest;

    const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
    } as unknown as Response;

    const next = jest.fn();

    return { req, res, next };
}

function createValidAuthEvent() {
    return createAgedAuthEvent(0);
}

function createAgedAuthEvent(ageSeconds: number) {
    const sk = generateSecretKey();
    return finalizeEvent(
        {
            kind: 22242,
            created_at: Math.floor(Date.now() / 1000) - ageSeconds,
            tags: [['challenge', 'sattest-auth']],
            content: 'sattest-auth',
        },
        sk
    );
}


function createValidWriteAuthEvent() {
    return createAgedWriteAuthEvent(0);
}

/**
 * Builds a write-scope event for `sk` (or a fresh key if omitted), aged by
 * `ageSeconds`. By default it embeds a freshly issued, valid nonce for the
 * signer's pubkey — matching what `signMoneyAuthEvent` produces on the
 * extension side. Pass `tags` to override for negative nonce tests.
 */
function createAgedWriteAuthEvent(
    ageSeconds: number,
    opts: { sk?: Uint8Array; tags?: string[][] } = {}
) {
    const sk = opts.sk ?? generateSecretKey();
    const pubkey = getPublicKey(sk);
    const tags = opts.tags ?? [
        ['challenge', 'sattest-auth:write'],
        ['nonce', issueNonce(pubkey).nonce],
    ];
    return finalizeEvent(
        {
            kind: 22242,
            created_at: Math.floor(Date.now() / 1000) - ageSeconds,
            tags,
            content: 'sattest-auth:write',
        },
        sk
    );
}

describe('nostrAuth middleware', () => {
    it('rejects requests with no Authorization header', () => {
        const { req, res, next } = mockReqRes();

        nostrAuth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(
            expect.objectContaining({ error: expect.stringContaining('Missing') })
        );
        expect(next).not.toHaveBeenCalled();
    });

    it('rejects requests with wrong auth scheme', () => {
        const { req, res, next } = mockReqRes('Bearer some-token');

        nostrAuth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(next).not.toHaveBeenCalled();
    });

    it('rejects invalid base64', () => {
        const { req, res, next } = mockReqRes('Nostr !!!invalid-base64!!!');

        nostrAuth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(
            expect.objectContaining({ error: expect.stringContaining('Invalid base64') })
        );
        expect(next).not.toHaveBeenCalled();
    });

    it('rejects event with wrong kind', () => {
        const sk = generateSecretKey();
        const event = finalizeEvent(
            {
                kind: 1, // wrong kind — should be 22242
                created_at: Math.floor(Date.now() / 1000),
                tags: [],
                content: 'sattest-auth',
            },
            sk
        );

        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        nostrAuth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(
            expect.objectContaining({ error: expect.stringContaining('kind') })
        );
        expect(next).not.toHaveBeenCalled();
    });

    it('rejects event with wrong content', () => {
        const sk = generateSecretKey();
        const event = finalizeEvent(
            {
                kind: 22242,
                created_at: Math.floor(Date.now() / 1000),
                tags: [],
                content: 'wrong-content',
            },
            sk
        );

        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        nostrAuth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(
            expect.objectContaining({ error: expect.stringContaining('content') })
        );
        expect(next).not.toHaveBeenCalled();
    });

    it('rejects expired event', () => {
        const sk = generateSecretKey();
        const event = finalizeEvent(
            {
                kind: 22242,
                created_at: Math.floor(Date.now() / 1000) - 60 * 60 * 24 * 31, // 31 days ago
                tags: [['challenge', 'sattest-auth']],
                content: 'sattest-auth',
            },
            sk
        );

        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        nostrAuth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(
            expect.objectContaining({ error: expect.stringContaining('expired') })
        );
        expect(next).not.toHaveBeenCalled();
    });

    it('rejects event with tampered signature', () => {
        const event = createValidAuthEvent();
        // Tamper with the signature (flip the first char to a value it can't
        // already be, so this doesn't depend on the random signature's contents)
        const flipped = event.sig[0] === '0' ? '1' : '0';
        const tampered = { ...event, sig: flipped + event.sig.slice(1) };

        const { req, res, next } = mockReqRes(makeAuthHeader(tampered));
        nostrAuth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(
            expect.objectContaining({ error: expect.stringContaining('signature') })
        );
        expect(next).not.toHaveBeenCalled();
    });

    it('accepts valid auth event and sets req.nostrPubkey', () => {
        const event = createValidAuthEvent();

        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        nostrAuth(req, res, next);

        expect(next).toHaveBeenCalled();
        expect(req.nostrPubkey).toBe(event.pubkey);
        expect(res.status).not.toHaveBeenCalled();
    });

    it('accepts event with minor clock skew (future timestamp)', () => {
        const sk = generateSecretKey();
        const event = finalizeEvent(
            {
                kind: 22242,
                created_at: Math.floor(Date.now() / 1000) + 120, // 2 minutes in the future
                tags: [['challenge', 'sattest-auth']],
                content: 'sattest-auth',
            },
            sk
        );

        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        nostrAuth(req, res, next);

        expect(next).toHaveBeenCalled();
        expect(req.nostrPubkey).toBe(event.pubkey);
    });
});

// Prod windows: read = 30 min, write = 5 min. Jest runs with NODE_ENV=test,
// so the production branch of the window constants applies.
describe('moneyAuth — tighter write-path window', () => {
    it('accepts a fresh read event on nostrAuth and a fresh write event on moneyAuth', () => {
        const readEvent = createValidAuthEvent();
        const writeEvent = createValidWriteAuthEvent();

        const read = mockReqRes(makeAuthHeader(readEvent));
        nostrAuth(read.req, read.res, read.next);
        expect(read.next).toHaveBeenCalled();

        const write = mockReqRes(makeAuthHeader(writeEvent));
        moneyAuth(write.req, write.res, write.next);
        expect(write.next).toHaveBeenCalled();
    });

    it('rejects a read-scope event on moneyAuth (scope separation)', () => {
        const readEvent = createValidAuthEvent(); // content: 'sattest-auth'
        const { req, res, next } = mockReqRes(makeAuthHeader(readEvent));
        moneyAuth(req, res, next);
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(
            expect.objectContaining({ error: expect.stringContaining('sattest-auth:write') })
        );
        expect(next).not.toHaveBeenCalled();
    });

    it('rejects a write-scope event on nostrAuth (scope separation)', () => {
        const writeEvent = createValidWriteAuthEvent(); // content: 'sattest-auth:write'
        const { req, res, next } = mockReqRes(makeAuthHeader(writeEvent));
        nostrAuth(req, res, next);
        expect(res.status).toHaveBeenCalledWith(401);
        expect(next).not.toHaveBeenCalled();
    });

    it('accepts a 10-min-old read event on nostrAuth (30-min window) but rejects 10-min-old write event on moneyAuth (5-min window)', () => {
        const readEvent = createAgedAuthEvent(10 * 60);   // 10 minutes old
        const writeEvent = createAgedWriteAuthEvent(10 * 60); // 10 minutes old

        const read = mockReqRes(makeAuthHeader(readEvent));
        nostrAuth(read.req, read.res, read.next);
        expect(read.next).toHaveBeenCalled(); // within the 30-min read window

        const write = mockReqRes(makeAuthHeader(writeEvent));
        moneyAuth(write.req, write.res, write.next);
        expect(write.res.status).toHaveBeenCalledWith(401); // beyond the 5-min write window
        expect(write.next).not.toHaveBeenCalled();
    });

    it('rejects an event older than the read window on both', () => {
        const readEvent = createAgedAuthEvent(40 * 60);      // 40 minutes > both windows
        const writeEvent = createAgedWriteAuthEvent(40 * 60); // 40 minutes > both windows

        const read = mockReqRes(makeAuthHeader(readEvent));
        nostrAuth(read.req, read.res, read.next);
        expect(read.res.status).toHaveBeenCalledWith(401);

        const write = mockReqRes(makeAuthHeader(writeEvent));
        moneyAuth(write.req, write.res, write.next);
        expect(write.res.status).toHaveBeenCalledWith(401);
    });
});

// ── server-issued single-use nonce (write path only) ───────────────────────
describe('moneyAuth — single-use nonce enforcement', () => {
    it('rejects a write event with no nonce tag at all', () => {
        const sk = generateSecretKey();
        const event = createAgedWriteAuthEvent(0, {
            sk,
            tags: [['challenge', 'sattest-auth:write']], // no ['nonce', …]
        });

        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        moneyAuth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(
            expect.objectContaining({ error: expect.stringContaining('nonce') })
        );
        expect(next).not.toHaveBeenCalled();
    });

    it('rejects a write event carrying a nonce that was never issued', () => {
        const sk = generateSecretKey();
        const event = createAgedWriteAuthEvent(0, {
            sk,
            tags: [['challenge', 'sattest-auth:write'], ['nonce', 'not-a-real-nonce']],
        });

        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        moneyAuth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(next).not.toHaveBeenCalled();
    });

    it('accepts a write event carrying a nonce freshly issued to its own pubkey', () => {
        const event = createValidWriteAuthEvent(); // default helper issues + embeds a valid nonce

        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        moneyAuth(req, res, next);

        expect(next).toHaveBeenCalled();
        expect(req.nostrPubkey).toBe(event.pubkey);
    });

    it('rejects replay of the exact same write event a second time (nonce already consumed)', () => {
        const event = createValidWriteAuthEvent();
        const header = makeAuthHeader(event);

        const first = mockReqRes(header);
        moneyAuth(first.req, first.res, first.next);
        expect(first.next).toHaveBeenCalled();

        const second = mockReqRes(header);
        moneyAuth(second.req, second.res, second.next);
        expect(second.res.status).toHaveBeenCalledWith(401);
        expect(second.next).not.toHaveBeenCalled();
    });

    it('rejects a nonce presented by a pubkey it was not issued to', () => {
        const issuedTo = generateSecretKey();
        const issuedToPubkey = getPublicKey(issuedTo);
        const { nonce } = issueNonce(issuedToPubkey);

        // A different key signs an event that names the same nonce.
        const attackerSk = generateSecretKey();
        const event = finalizeEvent(
            {
                kind: 22242,
                created_at: Math.floor(Date.now() / 1000),
                tags: [['challenge', 'sattest-auth:write'], ['nonce', nonce]],
                content: 'sattest-auth:write',
            },
            attackerSk
        );

        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        moneyAuth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(next).not.toHaveBeenCalled();
    });

    it('does not require a nonce on the read path (nostrAuth)', () => {
        const readEvent = createValidAuthEvent(); // no nonce tag at all
        const { req, res, next } = mockReqRes(makeAuthHeader(readEvent));
        nostrAuth(req, res, next);
        expect(next).toHaveBeenCalled();
    });
});

// ── audience binding (AUTH_AUDIENCE) ────────────────────────────────────────
describe('audience binding', () => {
    const AUDIENCE = 'https://api.sattest.example';

    function eventWithTags(tags: string[][]) {
        const sk = generateSecretKey();
        return finalizeEvent(
            {
                kind: 22242,
                created_at: Math.floor(Date.now() / 1000),
                tags,
                content: 'sattest-auth',
            },
            sk
        );
    }

    const realAudience = process.env.AUTH_AUDIENCE;
    afterEach(() => {
        if (realAudience === undefined) {
            delete process.env.AUTH_AUDIENCE;
        } else {
            process.env.AUTH_AUDIENCE = realAudience;
        }
    });

    it('accepts an event whose relay tag origin matches AUTH_AUDIENCE', () => {
        process.env.AUTH_AUDIENCE = AUDIENCE;
        const event = eventWithTags([
            ['challenge', 'sattest-auth'],
            ['relay', AUDIENCE],
        ]);
        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        nostrAuth(req, res, next);
        expect(next).toHaveBeenCalled();
    });

    it('matches by origin, ignoring path and trailing slash', () => {
        process.env.AUTH_AUDIENCE = AUDIENCE;
        const event = eventWithTags([['relay', `${AUDIENCE}/`]]);
        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        nostrAuth(req, res, next);
        expect(next).toHaveBeenCalled();
    });

    it('rejects an event whose relay tag points at a different origin', () => {
        process.env.AUTH_AUDIENCE = AUDIENCE;
        const event = eventWithTags([['relay', 'https://evil.example.com']]);
        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        nostrAuth(req, res, next);
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(
            expect.objectContaining({ error: expect.stringContaining('audience') })
        );
        expect(next).not.toHaveBeenCalled();
    });

    it('rejects an event with no relay tag when AUTH_AUDIENCE is set', () => {
        process.env.AUTH_AUDIENCE = AUDIENCE;
        const event = eventWithTags([['challenge', 'sattest-auth']]);
        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        nostrAuth(req, res, next);
        expect(res.status).toHaveBeenCalledWith(401);
        expect(next).not.toHaveBeenCalled();
    });

    it('skips the check entirely when AUTH_AUDIENCE is unset (backward compatible)', () => {
        delete process.env.AUTH_AUDIENCE;
        const event = eventWithTags([['challenge', 'sattest-auth']]); // no relay tag
        const { req, res, next } = mockReqRes(makeAuthHeader(event));
        nostrAuth(req, res, next);
        expect(next).toHaveBeenCalled();
    });
});