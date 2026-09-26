import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { config } from './config';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;       // 96-bit IV recommended for GCM
const AUTH_TAG_LENGTH = 16; // 128-bit auth tag

/**
 * Returns the 32-byte encryption key from the WALLET_ENCRYPTION_KEY env var.
 * The env var must be a base64-encoded 32-byte value.
 * Generate one with: openssl rand -base64 32
 */
function getEncryptionKey(): Buffer {
    const raw = config.walletEncryptionKey;
    if (!raw) throw new Error('WALLET_ENCRYPTION_KEY env var is not set');
    const key = Buffer.from(raw, 'base64');
    if (key.length !== 32) {
        throw new Error('WALLET_ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256)');
    }
    return key;
}

/**
 * Encrypts a plaintext string using AES-256-GCM.
 * Returns a single string in the format: base64(iv):base64(authTag):base64(ciphertext)
 */
export function encrypt(plaintext: string): string {
    const key = getEncryptionKey();
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, key, iv);

    const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    return [
        iv.toString('base64'),
        authTag.toString('base64'),
        encrypted.toString('base64'),
    ].join(':');
}

/**
 * Decrypts a string produced by encrypt().
 * Throws if the ciphertext has been tampered with (GCM auth tag mismatch).
 */
export function decrypt(ciphertext: string): string {
    const key = getEncryptionKey();
    const parts = ciphertext.split(':');
    if (parts.length !== 3) throw new Error('Invalid ciphertext format');

    const [ivB64, authTagB64, dataB64] = parts;
    const iv      = Buffer.from(ivB64,      'base64');
    const authTag = Buffer.from(authTagB64, 'base64');
    const data    = Buffer.from(dataB64,    'base64');

    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}
