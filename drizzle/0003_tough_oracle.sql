ALTER TABLE "bounties" ADD COLUMN "refund_lnurl" text;--> statement-breakpoint
ALTER TABLE "bounties" ADD COLUMN "refund_checking_id" text;--> statement-breakpoint
ALTER TABLE "bounties" ADD COLUMN "refund_at" timestamp with time zone;