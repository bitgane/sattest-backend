import './env'; // must be first — loads .env before any other module reads process.env
import { config } from './config';

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { and, eq, lt } from 'drizzle-orm';
import * as schema from './schema';
import { pool, db } from './db';
import { claimStatusApproving } from './types/claim.types';
import { generalLimiter } from './lib/rate-limit';
import { registerSystemRoutes } from './routes/system';
import { registerUserNwcRoutes } from './routes/users-nwc';
import { registerBountyRoutes } from './routes/bounties';
import { registerDeactivateRoute } from './routes/deactivate';
import { registerApproveRoute } from './routes/approve';
import { reconcileApprovingClaim } from './services/reconcile';

const app = express();
const port = config.port;

// Railway (and most PaaS hosts) front the service with a reverse proxy that
// sets `X-Forwarded-For`. Trust exactly one hop so `express-rate-limit` can
// key on the real client IP without blindly trusting arbitrarily deep chains.
// See: https://express-rate-limit.github.io/ERR_ERL_UNEXPECTED_X_FORWARDED_FOR/
app.set('trust proxy', 1);


// Standard security headers (HSTS, X-Content-Type-Options, frame-deny, etc.).
// This is a JSON API with no server-rendered HTML, so helmet's defaults are a
// clean fit and add cheap defense-in-depth.
app.use(helmet());

app.use(generalLimiter);

// CORS — restrict to trusted origins via env var; deny all if not configured
const allowedOrigins = config.allowedOrigins;

app.use(cors({
    origin: (origin, callback) => {
        // In development, allow all origins (includes VSCode extension webviews, curl, etc.)
        if (config.isDevelopment) return callback(null, true);
        // In production, require an explicit allowlist
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error('Not allowed by CORS'));
    },
}));

// Cap request bodies. Sized to accommodate the worst-case /bounties/filter
// payload (up to 500 test IDs × 500 chars each ≈ 250 KB) with headroom;
// rate limiters still guard against abuse above the per-window budget.
app.use(express.json({ limit: '1024kb' }));



registerSystemRoutes(app);

// ---------------------------------------------------------------------------
// NIP-47 Nostr Wallet Connect (per-user grant)
//
// Creators paste a budgeted NWC URI once; the backend stores it encrypted and
// reuses it for every non-custodial bounty they create. The URI itself is a
// secret — we never echo it back out.
// ---------------------------------------------------------------------------

// PATCH /users/me/nwc — connect or update the caller's NWC grant.
registerUserNwcRoutes(app);

registerBountyRoutes(app);
registerDeactivateRoute(app);

registerApproveRoute(app);

export { app };

/**
 * Startup posture check. Doesn't throw — just warns loudly — so an operator who
 * ships with a dev/loose config sees it in the logs. `NODE_ENV !== 'production'`
 * disables auth-event expiry, opens CORS to all origins, relaxes the SSRF guard,
 * and echoes internal errors; on a public host that's a security problem.
 */
export function warnOnInsecureConfig(env: NodeJS.ProcessEnv = process.env): void {
    if (env.NODE_ENV !== 'production') {
        console.warn(
            `[security] NODE_ENV is "${env.NODE_ENV ?? '(unset)'}" — running in NON-PRODUCTION mode: ` +
            'auth-event freshness is disabled, CORS allows all origins, the SSRF guard is relaxed, ' +
            'and internal error detail is exposed. Set NODE_ENV=production for any public deployment.'
        );
        return;
    }
    if (!env.ALLOWED_ORIGINS) {
        console.warn('[security] ALLOWED_ORIGINS is empty — browser clients will be blocked by CORS.');
    }
    if (!env.AUTH_AUDIENCE) {
        throw new Error(
            '[security] AUTH_AUDIENCE is not set — Nostr auth events are not audience-bound. ' +
            'Set AUTH_AUDIENCE to this service\'s public URL so credentials harvested by other ' +
            'servers cannot be replayed here. Refusing to start in production without it.'
        );
    }
}

/**
 * How long a claim may sit in `approving` before the sweep treats it as
 * orphaned. Comfortably longer than the 180 s NWC reply budget so a payout
 * that's merely slow is never disturbed.
 */
const STALE_APPROVING_MS = 10 * 60 * 1000;

/**
 * Resolve claims left locked by a process that died mid-payout (a redeploy,
 * a crash) — without this they stay `approving` forever and the creator sees
 * "Payout Processing" with no way forward.
 *
 * Runs the same wallet lookup the approve handler uses, so the outcome is
 * decided by the wallet rather than by a timeout heuristic. Rows we can't
 * resolve are logged and left alone for the next run.
 */
export async function sweepStaleApprovingClaims(): Promise<void> {
    let stuck: Array<typeof schema.claims.$inferSelect>;
    try {
        stuck = await db.query.claims.findMany({
            where: and(
                eq(schema.claims.status, claimStatusApproving),
                lt(schema.claims.approvingAt, new Date(Date.now() - STALE_APPROVING_MS)),
            ),
        });
    } catch (err) {
        console.error('[sweep] failed to query stale approving claims:', err);
        return;
    }

    if (stuck.length === 0) {
        return;
    }
    console.log(`[sweep] reconciling ${stuck.length} claim(s) stuck in approving`);

    for (const claim of stuck) {
        try {
            const bounty = await db.query.bounties.findFirst({
                where: eq(schema.bounties.id, claim.bountyId),
            });
            if (!bounty) continue;
            const result = await reconcileApprovingClaim(bounty, claim);
            if (result.resolution === 'still-locked') {
                console.warn(
                    `[sweep] claim ${claim.id} still unresolved: ${result.detail} — ` +
                    'left locked for manual reconciliation',
                );
            }
        } catch (err) {
            console.error(`[sweep] failed to reconcile claim ${claim.id}:`, err);
        }
    }
}

// Only bind to a port when run directly (not during tests)
if (require.main === module) {
    try {
        warnOnInsecureConfig();
    } catch (err) {
        console.error((err as Error).message);
        process.exit(1);
    }
    app.listen(port, async () => {
        console.log(`Server running on http://localhost:${port}`);
        console.log(`DB: ${config.databaseUrl?.split('@')[1] || 'unknown'}`);

        try {
            await pool.query('SELECT 1');
            console.log('Database connection OK');
        } catch (err) {
            console.error('DB connection failed:', err);
        }

        // Claims orphaned by the previous process (redeploy mid-payout) can
        // only be resolved by asking the wallet — do it once at boot.
        await sweepStaleApprovingClaims();
    });
}
