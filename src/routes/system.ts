import type { Express, Request, Response } from 'express';
import { nostrAuth, NostrAuthRequest } from '../middleware/auth';
import { issueNonce } from '../middleware/nonce';

/** Health check + nonce issuance — the two unauthenticated-ish utility routes. */
export function registerSystemRoutes(app: Express) {
    // Health check
    app.get('/health', nostrAuth, (req: Request, res: Response) => {
        res.json({ status: 'ok', dbConnected: true });
    });

    // POST /auth/nonce — issues a short-lived, single-use nonce
    // that the caller must embed in a freshly signed write-scope event to pass
    // `moneyAuth` on a money-moving endpoint. Gated by the cheap, reusable read
    // credential (`nostrAuth`) so fetching a nonce never requires a signer
    // round-trip — only the subsequent money call does.
    app.post('/auth/nonce', nostrAuth, (req: NostrAuthRequest, res: Response) => {
        const pubkey = req.nostrPubkey!;
        const { nonce, expiresAt } = issueNonce(pubkey);
        res.json({ nonce, expiresAt });
    });
}
