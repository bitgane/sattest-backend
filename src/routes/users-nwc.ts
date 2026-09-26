import type { Express, Response } from 'express';
import { z } from 'zod';
import { eq } from 'drizzle-orm';
import { nostrAuth, moneyAuth, NostrAuthRequest } from '../middleware/auth';
import * as schema from '../schema';
import { db } from '../db';
import { encrypt, decrypt } from '../crypto';
import { validateNwcUri, summarizeNwcUri } from '../nwc';
import { SetNwcSchema } from '../schemas';
import { sendZodValidationError } from '../lib/http';

/** Per-user NWC (NIP-47) wallet-grant management: connect, disconnect, status. */
export function registerUserNwcRoutes(app: Express) {
    app.patch('/users/me/nwc', moneyAuth, async (req: NostrAuthRequest, res: Response) => {
        let input: z.infer<typeof SetNwcSchema>;
        try {
            input = SetNwcSchema.parse(req.body ?? {});
        } catch (error) {
            if (error instanceof z.ZodError) {
                return sendZodValidationError(res, error);
            }
            throw error;
        }

        try {
            validateNwcUri(input.uri);
        } catch (err) {
            return res.status(400).json({
                error: err instanceof Error ? err.message : 'Invalid NWC URI',
            });
        }

        const pubkey = req.nostrPubkey!;
        const now = new Date();
        const encryptedUri = encrypt(input.uri);

        try {
            await db
                .insert(schema.users)
                .values({
                    nostrPubkey: pubkey,
                    encryptedNwcUri: encryptedUri,
                    nwcBudgetSats: input.budgetSats ?? null,
                    nwcBudgetWindow: input.budgetWindow ?? null,
                    nwcUpdatedAt: now,
                })
                .onConflictDoUpdate({
                    target: schema.users.nostrPubkey,
                    set: {
                        encryptedNwcUri: encryptedUri,
                        nwcBudgetSats: input.budgetSats ?? null,
                        nwcBudgetWindow: input.budgetWindow ?? null,
                        nwcUpdatedAt: now,
                        updatedAt: now,
                    },
                });
            return res.status(200).json({ configured: true });
        } catch (err) {
            console.error('[PATCH /users/me/nwc] Error:', err);
            return res.status(500).json({ error: 'Failed to store NWC connection' });
        }
    });

    // DELETE /users/me/nwc — disconnect the caller's wallet. Existing NWC bounties
    // become un-approvable until the creator reconnects, but they stay in the DB
    // (we don't silently destroy them).
    //
    // Uses `nostrAuth` (read scope), NOT `moneyAuth`: revoking a spending grant
    // can't move funds, so it doesn't need the single-use nonce — and a user whose
    // signer session has ended must still be able to disconnect. Requiring a live
    // signer to REVOKE would make the safety valve the most fragile path in the
    // app. The only widening is that a replayed read credential could disconnect a
    // wallet (a nuisance, reversible by reconnecting) — an acceptable trade for
    // guaranteed revocability. Connect (PATCH) stays `moneyAuth`: it grants.
    app.delete('/users/me/nwc', nostrAuth, async (req: NostrAuthRequest, res: Response) => {
        const pubkey = req.nostrPubkey!;
        const now = new Date();
        try {
            await db.update(schema.users)
                .set({
                    encryptedNwcUri: null,
                    nwcBudgetSats: null,
                    nwcBudgetWindow: null,
                    nwcUpdatedAt: null,
                    updatedAt: now,
                })
                .where(eq(schema.users.nostrPubkey, pubkey));
            return res.status(200).json({ configured: false });
        } catch (err) {
            console.error('[DELETE /users/me/nwc] Error:', err);
            return res.status(500).json({ error: 'Failed to clear NWC connection' });
        }
    });

    // GET /users/me/nwc-status — UI helper. Returns booleans + the informational
    // budget fields; never returns the URI itself.
    app.get('/users/me/nwc-status', nostrAuth, async (req: NostrAuthRequest, res: Response) => {
        const pubkey = req.nostrPubkey!;
        try {
            const user = await db.query.users.findFirst({
                where: eq(schema.users.nostrPubkey, pubkey),
                columns: {
                    encryptedNwcUri: true,
                    nwcBudgetSats: true,
                    nwcBudgetWindow: true,
                    nwcUpdatedAt: true,
                },
            });
            // Decrypt in memory only long enough to extract the public relay/lud16
            // for display. The secret and full URI are never returned. A parse or
            // decrypt failure degrades to null fields rather than failing the call.
            let summary: { relay?: string; lud16?: string } = {};
            if (user?.encryptedNwcUri) {
                try {
                    summary = summarizeNwcUri(decrypt(user.encryptedNwcUri));
                } catch (e) {
                    console.error('[nwc-status] summary failed:', e);
                }
            }
            return res.json({
                configured: Boolean(user?.encryptedNwcUri),
                relay: summary.relay ?? null,
                lud16: summary.lud16 ?? null,
                budgetSats: user?.nwcBudgetSats ?? null,
                budgetWindow: user?.nwcBudgetWindow ?? null,
                updatedAt: user?.nwcUpdatedAt ?? null,
            });
        } catch (err) {
            console.error('[GET /users/me/nwc-status] Error:', err);
            return res.status(500).json({ error: 'Failed to read NWC status' });
        }
    });
}
