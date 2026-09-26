// src/schema.ts
import { pgTable, uuid, text, bigint, timestamp, boolean, index, uniqueIndex } from 'drizzle-orm/pg-core';
import { relations, sql } from 'drizzle-orm';

/**
 * One row per Nostr user. Created automatically when a bounty invoice is first paid.
 * adminkey is stored encrypted at rest (AES-256-GCM via src/crypto.ts) and is
 * never returned to the front-end.
 */
export const users = pgTable('users', {
    nostrPubkey:        text('nostr_pubkey').primaryKey(),
    walletId:           text('wallet_id'),
    walletName:         text('wallet_name'),
    encryptedAdminKey:  text('encrypted_admin_key'),
    encryptedInvoiceKey: text('encrypted_invoice_key'),
    // NIP-47 Nostr Wallet Connect grant. When set, the user can opt their new
    // bounties into the non-custodial funding path: on approval the backend
    // asks this wallet to pay the claimer directly — funds never pool on our
    // LNbits host. URI is encrypted at rest via src/crypto.ts; budget fields
    // are informational only (real enforcement happens in the wallet itself).
    encryptedNwcUri:    text('encrypted_nwc_uri'),
    nwcBudgetSats:      bigint('nwc_budget_sats', { mode: 'number' }),
    nwcBudgetWindow:    text('nwc_budget_window'),
    nwcUpdatedAt:       timestamp('nwc_updated_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const bounties = pgTable('bounties', {
    id: uuid('id').primaryKey().default(sql`gen_random_uuid()`),
    testId: text('test_id').notNull(),
    creatorId: text('creator_id').notNull(),
    amountSats: bigint('amount_sats', { mode: 'number' }).notNull(),
    invoicePaid: boolean('invoice_paid').notNull().default(false),
    // 'custodial' bounties flow through LNbits (invoice + paymentHash required).
    // 'nwc' bounties are funded on approval from the creator's own wallet via
    // NIP-47, so no up-front invoice is generated — both columns stay null.
    fundingMode: text('funding_mode').notNull().default('custodial'),
    invoice: text('invoice'),
    paymentHash: text('payment_hash').unique(),
    memo: text('memo'),
    // Git repo slug (e.g. "owner/repo") derived by the client from `git remote
    // get-url origin`. Optional — bounties created outside a git repo have null.
    // Used as the primary scope for unauthenticated bounty listing.
    repo: text('repo'),
    // Refund metadata — populated when the creator removes an already-funded
    // bounty and supplies an LNURL to receive the sats back. `refundCheckingId`
    // is both the payout's LNbits id and the idempotency guard (non-null ⇒
    // already refunded, don't pay again).
    refundLnurl: text('refund_lnurl'),
    refundCheckingId: text('refund_checking_id'),
    refundAt: timestamp('refund_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    active: boolean('active').notNull().default(false),
}, (table) => ({
    // Speeds up the `/bounties?repo=<slug>` and `/bounties/filter?repo=<slug>` paths.
    repoIdx: index('bounties_repo_idx').on(table.repo),
    // Speeds up lookups by test id (used in the /filter endpoint's IN clause).
    testIdIdx: index('bounties_test_id_idx').on(table.testId),
    // POST /bounties looks up a creator's existing active bounties for a test
    // on every create, and the NWC routes read bounties by creator.
    creatorIdIdx: index('bounties_creator_id_idx').on(table.creatorId),
    // The payout cap query sums refunds in a time window on every payout
    // (`sumOutflowWindows`). Partial: only refunded rows are ever scanned, and
    // they are a small minority of the table.
    refundAtIdx: index('bounties_refund_at_idx')
        .on(table.refundAt)
        .where(sql`${table.refundAt} IS NOT NULL`),
}));

export const claims = pgTable('claims', {
    id: uuid('id')
        .primaryKey()
        .default(sql`gen_random_uuid()`),

    bountyId: uuid('bounty_id')
        .notNull()
        .references(() => bounties.id, { onDelete: 'cascade' }),

    claimantLnurl: text('claimant_lnurl').notNull().default('none'),
    // Authenticated Nostr pubkey of the claimant, captured from the write-scope
    // credential that filed the claim.
    //
    // Without this the payout had no verifiable counterparty: the creator vets a
    // contributor out-of-band (by reviewing their code), but the only thing the
    // approve flow could bind to was "the newest pending claim" — so anyone who
    // filed a later claim became the payout destination, and nothing recorded
    // who was actually paid. `approvedBy` pins the payer; this pins the payee.
    //
    // Nullable because rows written before this column exists have no identity
    // to backfill. Handlers must treat null as "unverifiable, legacy" rather
    // than as a match.
    claimantPubkey: text('claimant_pubkey'),
    // When true, the claimant asked to keep their payout destination private:
    // the backend still stores and pays `claimantLnurl` (it must, to route the
    // payment), but never discloses it to the bounty creator/approver. The
    // creator approves "blind" via the claimId binding — the payout still goes
    // to this pinned address and can't be redirected, so front-running
    // protection is unchanged; the creator just can't see where it lands.
    lnurlPrivate: boolean('lnurl_private').notNull().default(false),
    claimedAt: timestamp('claimed_at', { withTimezone: true }).notNull().defaultNow(),
    status: text('status'),
    payoutTxid: text('payout_txid'),
    approvedBy: text('approved_by'),
    approvedAt: timestamp('approved_at', { withTimezone: true }),
    // --- In-flight payout bookkeeping (written when the claim is locked) -----
    // A NIP-47 reply timeout leaves us genuinely unsure whether the creator's
    // wallet paid. These three columns are what make that recoverable: the
    // payment hash lets us ask the wallet after the fact (`lookupNwcPayment`),
    // the bolt11 lets a retry re-present the SAME invoice instead of minting a
    // second one, and the timestamp tells an operator (or the startup sweep)
    // how long a claim has been stuck in `approving`.
    payoutPaymentHash: text('payout_payment_hash'),
    payoutBolt11: text('payout_bolt11'),
    approvingAt: timestamp('approving_at', { withTimezone: true }),
    // Which wallet actually made the attempt (the NWC wallet-service pubkey —
    // non-secret). A creator whose wallet dies can connect a different one, and
    // that new wallet has never seen this payment: neither its "not found" nor
    // its "failed" is evidence about what happened. Recording the identity lets
    // reconciliation refuse to trust an answer it can't attribute, and ask the
    // creator instead. Null on rows predating this column.
    payoutWalletPubkey: text('payout_wallet_pubkey'),
    // Set only when a human asserted the outcome because no wallet could
    // confirm it ('creator-confirmed-paid' / 'creator-confirmed-unpaid'), so a
    // manually-resolved claim is never indistinguishable from a
    // wallet-verified one.
    payoutResolution: text('payout_resolution'),
}, (table) => ({
    // One claim per identity per bounty. Stacking claims was how a second
    // claimant displaced the first as "newest", so the DB — not just the
    // handler — enforces that a pubkey gets one row here. Partial (WHERE NOT
    // NULL) so legacy rows with no recorded identity don't collide with each
    // other on a shared null.
    claimantPerBountyIdx: uniqueIndex('claims_bounty_claimant_idx')
        .on(table.bountyId, table.claimantPubkey)
        .where(sql`${table.claimantPubkey} IS NOT NULL`),
    // The approve/pending-claim paths always filter claims by bounty.
    bountyIdIdx: index('claims_bounty_id_idx').on(table.bountyId),
    // The payout cap query (`sumOutflowWindows`) and the startup sweep both
    // filter on status, which was previously unindexed — so every payout paid
    // for a sequential scan of the whole claims table.
    statusIdx: index('claims_status_idx').on(table.status),
    // The same cap query windows on `coalesce(approved_at, approving_at)`. That
    // expression is not sargable against a plain column index, so it needs a
    // matching *expression* index or it can never use one at all.
    payoutWindowIdx: index('claims_payout_window_idx')
        .on(sql`coalesce(${table.approvedAt}, ${table.approvingAt})`),
    // The startup sweep scans for claims stuck in `approving` past a cutoff.
    approvingAtIdx: index('claims_approving_at_idx')
        .on(table.approvingAt)
        .where(sql`${table.approvingAt} IS NOT NULL`),
}));

export const bountiesRelations = relations(bounties, ({ many }) => ({
    claims: many(claims),
}));

export const claimsRelations = relations(claims, ({ one }) => ({
    bounty: one(bounties, {
        fields: [claims.bountyId],
        references: [bounties.id],
    }),
}));