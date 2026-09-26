import { issueNonce, consumeNonce, _resetNonceStoreForTests } from './nonce';

const PUBKEY = 'a'.repeat(64);
const OTHER_PUBKEY = 'b'.repeat(64);

beforeEach(() => {
    _resetNonceStoreForTests();
});

describe('issueNonce / consumeNonce', () => {
    it('issues a nonce that can be consumed once for the pubkey it was issued to', () => {
        const { nonce } = issueNonce(PUBKEY);
        expect(consumeNonce(nonce, PUBKEY)).toBe(true);
    });

    it('rejects consuming the same nonce twice (single-use)', () => {
        const { nonce } = issueNonce(PUBKEY);
        expect(consumeNonce(nonce, PUBKEY)).toBe(true);
        expect(consumeNonce(nonce, PUBKEY)).toBe(false);
    });

    it('rejects a nonce consumed by a different pubkey than it was issued to', () => {
        const { nonce } = issueNonce(PUBKEY);
        expect(consumeNonce(nonce, OTHER_PUBKEY)).toBe(false);
    });

    it('burns the nonce even when the pubkey check fails (no retry with the right key)', () => {
        const { nonce } = issueNonce(PUBKEY);
        expect(consumeNonce(nonce, OTHER_PUBKEY)).toBe(false);
        expect(consumeNonce(nonce, PUBKEY)).toBe(false);
    });

    it('rejects an unknown/never-issued nonce', () => {
        expect(consumeNonce('never-issued-nonce', PUBKEY)).toBe(false);
    });

    it('issues distinct nonces across calls', () => {
        const a = issueNonce(PUBKEY);
        const b = issueNonce(PUBKEY);
        expect(a.nonce).not.toBe(b.nonce);
    });

    it('rejects a nonce once it has expired', () => {
        const nowSpy = jest.spyOn(Date, 'now');
        nowSpy.mockReturnValue(1_000_000);
        const { nonce, expiresAt } = issueNonce(PUBKEY);
        expect(expiresAt).toBeGreaterThan(1_000_000);

        nowSpy.mockReturnValue(expiresAt + 1);
        expect(consumeNonce(nonce, PUBKEY)).toBe(false);

        nowSpy.mockRestore();
    });

    it('sweeps expired entries when issuing new nonces (no unbounded growth)', () => {
        const nowSpy = jest.spyOn(Date, 'now');
        nowSpy.mockReturnValue(1_000_000);
        const { nonce: staleNonce, expiresAt } = issueNonce(PUBKEY);

        nowSpy.mockReturnValue(expiresAt + 1);
        issueNonce(PUBKEY); // triggers a sweep of the now-expired entry above

        nowSpy.mockReturnValue(expiresAt + 2);
        expect(consumeNonce(staleNonce, PUBKEY)).toBe(false);

        nowSpy.mockRestore();
    });
});
