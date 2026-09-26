CREATE TABLE "used_event_ids" (
	"event_id" text PRIMARY KEY NOT NULL,
	"seen_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "used_event_ids_seen_at_idx" ON "used_event_ids" USING btree ("seen_at");