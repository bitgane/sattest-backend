CREATE TABLE "bounties" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"test_id" text NOT NULL,
	"creator_id" text NOT NULL,
	"amount_sats" bigint NOT NULL,
	"invoice_paid" boolean DEFAULT false NOT NULL,
	"invoice" text NOT NULL,
	"payment_hash" text NOT NULL,
	"memo" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"active" boolean DEFAULT false NOT NULL,
	CONSTRAINT "bounties_payment_hash_unique" UNIQUE("payment_hash")
);
--> statement-breakpoint
CREATE TABLE "claims" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"bounty_id" uuid NOT NULL,
	"claimant_lnurl" text DEFAULT 'none' NOT NULL,
	"claimed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"status" text,
	"payout_txid" text,
	"approved_by" text,
	"approved_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "users" (
	"nostr_pubkey" text PRIMARY KEY NOT NULL,
	"wallet_id" text,
	"wallet_name" text,
	"encrypted_admin_key" text,
	"encrypted_invoice_key" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "claims" ADD CONSTRAINT "claims_bounty_id_bounties_id_fk" FOREIGN KEY ("bounty_id") REFERENCES "public"."bounties"("id") ON DELETE cascade ON UPDATE no action;