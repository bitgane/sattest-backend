import './env';

/**
 * Single source of truth for environment configuration.
 *
 * Every accessor reads `process.env` **lazily** (at call time, not at import) so
 * that per-test env overrides and any runtime changes are respected exactly as
 * the inline `process.env.*` reads this centralizes were. Defaults are preserved
 * verbatim from those reads — do not change them without a matching test update.
 *
 * Boot-time posture checks (the ones that refuse to start on an unsafe prod
 * config) live in `warnOnInsecureConfig` in index.ts; this module only reads.
 */
export const config = {
    /** Raw NODE_ENV. Prefer `isDevelopment` for the dev/prod branch. */
    get nodeEnv(): string | undefined {
        return process.env.NODE_ENV;
    },

    /** True in development — relaxes CORS, auth freshness, SSRF, and error detail. */
    get isDevelopment(): boolean {
        return process.env.NODE_ENV === 'development';
    },

    /** HTTP port; falls back to 3000. */
    get port(): string | number {
        return process.env.PORT || 3000;
    },

    /** CORS allowlist parsed from ALLOWED_ORIGINS (comma-separated); [] if unset. */
    get allowedOrigins(): string[] {
        return process.env.ALLOWED_ORIGINS
            ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
            : [];
    },

    /** Postgres connection string (used for the boot host-only log). */
    get databaseUrl(): string | undefined {
        return process.env.DATABASE_URL;
    },

    /**
     * LNbits credentials.
     *
     * `invoiceKey` mints invoices (custodial funding); `adminKey` is the payout
     * wallet's key and is what actually moves money out. `adminKey` was read
     * straight from `process.env.LNBITS_API_KEY` in three places, so this module
     * did not in fact describe what the service consumes — which is the whole
     * point of it existing.
     */
    lnbits: {
        get url(): string | undefined {
            return process.env.LNBITS_URL;
        },
        get invoiceKey(): string | undefined {
            return process.env.LNBITS_INVOICE_KEY;
        },
        get adminKey(): string | undefined {
            return process.env.LNBITS_API_KEY;
        },
    },

    /**
     * Public URL this service is reachable at. When set, auth events must carry
     * a matching `relay` tag, so a credential harvested by another server can't
     * be replayed here. Mandatory in production (enforced at boot).
     */
    get authAudience(): string | undefined {
        return process.env.AUTH_AUDIENCE;
    },

    /** AES-256-GCM key for the NWC URIs stored at rest. */
    get walletEncryptionKey(): string | undefined {
        return process.env.WALLET_ENCRYPTION_KEY;
    },

    /** Optional webhook that payout anomalies are POSTed to. */
    get alertWebhookUrl(): string | undefined {
        return process.env.ALERT_WEBHOOK_URL;
    },

    /** Payout circuit-breaker knobs. See `security.ts` for how each is applied. */
    payout: {
        /** Kill switch. Defaults to enabled so a missing var never blocks payouts. */
        get enabled(): boolean {
            const raw = (process.env.PAYOUTS_ENABLED ?? 'true').toLowerCase();
            return raw === 'true' || raw === '1' || raw === 'yes';
        },
        /**
         * Whether the custodial (LNbits invoice/QR) bounty path is allowed.
         * Defaults OFF — the inverse of the kill switch — because custodial
         * bounties require holding creator funds, which we aren't deploying.
         */
        get custodialBountiesEnabled(): boolean {
            const raw = (process.env.ALLOW_CUSTODIAL_BOUNTIES ?? 'false').toLowerCase();
            return raw === 'true' || raw === '1' || raw === 'yes';
        },
    },
};
