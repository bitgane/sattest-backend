import { encrypt, decrypt } from './crypto';

// A valid base64-encoded 32-byte key for testing
const TEST_KEY = Buffer.alloc(32, 0xab).toString('base64');

beforeEach(() => {
    process.env.WALLET_ENCRYPTION_KEY = TEST_KEY;
});

afterEach(() => {
    delete process.env.WALLET_ENCRYPTION_KEY;
});

describe('encrypt / decrypt', () => {
    it('round-trips a plaintext string', () => {
        const plaintext = 'super-secret-api-key-abc123';
        const ciphertext = encrypt(plaintext);
        expect(decrypt(ciphertext)).toBe(plaintext);
    });

    it('produces different ciphertext on every call (random IV)', () => {
        const plaintext = 'same-input';
        const a = encrypt(plaintext);
        const b = encrypt(plaintext);
        expect(a).not.toBe(b);
        // Both must still decrypt correctly
        expect(decrypt(a)).toBe(plaintext);
        expect(decrypt(b)).toBe(plaintext);
    });

    it('ciphertext has three colon-separated parts (iv:authTag:data)', () => {
        const parts = encrypt('hello').split(':');
        expect(parts).toHaveLength(3);
        // Each part must be non-empty base64
        parts.forEach(p => expect(p.length).toBeGreaterThan(0));
    });

    it('throws when WALLET_ENCRYPTION_KEY is missing', () => {
        delete process.env.WALLET_ENCRYPTION_KEY;
        expect(() => encrypt('test')).toThrow('WALLET_ENCRYPTION_KEY env var is not set');
    });

    it('throws when WALLET_ENCRYPTION_KEY decodes to wrong length', () => {
        process.env.WALLET_ENCRYPTION_KEY = Buffer.alloc(16).toString('base64'); // 16 bytes, not 32
        expect(() => encrypt('test')).toThrow('must decode to exactly 32 bytes');
    });

    it('throws on tampered ciphertext (auth tag mismatch)', () => {
        const ciphertext = encrypt('sensitive-data');
        const parts = ciphertext.split(':');
        // Flip the last character of the ciphertext part
        const tampered = parts[0] + ':' + parts[1] + ':' + parts[2].slice(0, -1) + 'X';
        expect(() => decrypt(tampered)).toThrow();
    });

    it('throws on malformed ciphertext (wrong number of parts)', () => {
        expect(() => decrypt('only-two:parts')).toThrow('Invalid ciphertext format');
    });

    it('handles empty string plaintext', () => {
        const ciphertext = encrypt('');
        expect(decrypt(ciphertext)).toBe('');
    });

    it('handles unicode and special characters', () => {
        const plaintext = '🔑 key with üñícode & special <chars>';
        expect(decrypt(encrypt(plaintext))).toBe(plaintext);
    });
});
