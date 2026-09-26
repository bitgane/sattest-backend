// Polyfill globalThis.crypto for Node versions that don't expose it globally.
// Required by @noble/curves / @noble/hashes (used transitively by nostr-tools).
if (!globalThis.crypto) {
    globalThis.crypto = require('crypto').webcrypto;
}

// Provide env var defaults that some modules read at load-time.
// These are overridden per-test where needed.
process.env.NOSTR_RELAYS   = process.env.NOSTR_RELAYS   ?? 'wss://relay.test';
process.env.LNBITS_URL     = process.env.LNBITS_URL     ?? 'http://lnbits.test';
process.env.LNBITS_API_KEY = process.env.LNBITS_API_KEY ?? 'test-api-key';
