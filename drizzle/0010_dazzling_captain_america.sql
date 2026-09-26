-- Money-path indexes.
--
-- Every payout runs the cumulative cap query (security.ts `sumOutflowWindows`),
-- which filters claims on `status` and windows on
-- `coalesce(approved_at, approving_at)`. Neither was indexed, so each payout
-- paid for a sequential scan of claims joined to bounties. The coalesce()
-- predicate is not sargable against a plain column index, hence the expression
-- index below — without it the window filter can never use an index at all.
--
-- OPERATIONAL NOTE: `IF NOT EXISTS` is deliberate, not decorative. On a table
-- with meaningful volume, run the CONCURRENTLY equivalent of each statement by
-- hand first (see the runbook) — CONCURRENTLY cannot run inside the transaction
-- drizzle wraps this migration in. Once those exist, running this migration
-- normally (`npm run migrate`) becomes a safe no-op that just records 0010 as
-- applied, rather than erroring on indexes that already exist.
--
-- All statements are additive: no column, constraint, or row is altered.

CREATE INDEX IF NOT EXISTS "bounties_creator_id_idx" ON "bounties" USING btree ("creator_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "bounties_refund_at_idx" ON "bounties" USING btree ("refund_at") WHERE "bounties"."refund_at" IS NOT NULL;--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "claims_status_idx" ON "claims" USING btree ("status");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "claims_payout_window_idx" ON "claims" USING btree (coalesce("approved_at", "approving_at"));--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "claims_approving_at_idx" ON "claims" USING btree ("approving_at") WHERE "claims"."approving_at" IS NOT NULL;