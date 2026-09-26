ALTER TABLE "bounties" ALTER COLUMN "invoice" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "bounties" ALTER COLUMN "payment_hash" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "bounties" ADD COLUMN "funding_mode" text DEFAULT 'custodial' NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "encrypted_nwc_uri" text;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "nwc_budget_sats" bigint;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "nwc_budget_window" text;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "nwc_updated_at" timestamp with time zone;