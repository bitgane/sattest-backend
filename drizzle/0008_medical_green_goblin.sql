ALTER TABLE "claims" ADD COLUMN "claimant_pubkey" text;--> statement-breakpoint
CREATE UNIQUE INDEX "claims_bounty_claimant_idx" ON "claims" USING btree ("bounty_id","claimant_pubkey") WHERE "claims"."claimant_pubkey" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "claims_bounty_id_idx" ON "claims" USING btree ("bounty_id");