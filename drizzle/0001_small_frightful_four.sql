ALTER TABLE "bounties" ADD COLUMN "repo" text;--> statement-breakpoint
CREATE INDEX "bounties_repo_idx" ON "bounties" USING btree ("repo");--> statement-breakpoint
CREATE INDEX "bounties_test_id_idx" ON "bounties" USING btree ("test_id");