ALTER TABLE "claims" ADD COLUMN "payout_payment_hash" text;--> statement-breakpoint
ALTER TABLE "claims" ADD COLUMN "payout_bolt11" text;--> statement-breakpoint
ALTER TABLE "claims" ADD COLUMN "approving_at" timestamp with time zone;