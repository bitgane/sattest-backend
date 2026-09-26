import { NOSTR_AUTH_KIND, READ_AUTH_CONTENT, WRITE_AUTH_CONTENT } from './auth';

/**
 * Wire-contract pins for the Nostr auth protocol.
 *
 * The extension and the backend live in separate repos and share no package, so
 * these constants exist twice: here, and in
 * `sattest/src/api/nostr-protocol.ts`. Nothing but a comment used to hold them
 * together — and a one-sided edit doesn't fail loudly, it makes every
 * money-moving call 401 in production.
 *
 * These are deliberately hardcoded literals rather than references. Asserting
 * `READ_AUTH_CONTENT === READ_AUTH_CONTENT` would pass no matter what; the point
 * is that changing the value requires editing this file too, which is the moment
 * to go change the other repo. The extension has the mirror of this test.
 */
describe('Nostr auth wire contract (mirrored in the extension repo)', () => {
    it('pins the NIP-42 auth event kind', () => {
        expect(NOSTR_AUTH_KIND).toBe(22242);
    });

    it('pins the read-scope challenge string', () => {
        expect(READ_AUTH_CONTENT).toBe('sattest-auth');
    });

    it('pins the write-scope challenge string', () => {
        expect(WRITE_AUTH_CONTENT).toBe('sattest-auth:write');
    });

    it('keeps the two scopes distinct', () => {
        // A read credential must never satisfy `moneyAuth`.
        expect(READ_AUTH_CONTENT).not.toBe(WRITE_AUTH_CONTENT);
    });
});
