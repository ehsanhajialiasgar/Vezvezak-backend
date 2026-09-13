-- 2026-09-14 · launch chain step 5 + ledger 1.2 — user_plans gains an expiry and a provenance.
-- schema.sql uses CREATE TABLE IF NOT EXISTS, so it cannot alter a table that already exists in D1; this
-- file does. NOT APPLIED BY CODE. Applying it to the production database is a deploy action:
--   npx wrangler d1 execute vezvezak --remote --file=./migrations_user_plans_expiry.sql
-- Safe on existing rows: every column is nullable, and planFor() treats a paid row with a NULL expires_at as
-- free — so a row that predates this migration cannot accidentally become an unexpiring paid plan.
ALTER TABLE user_plans ADD COLUMN expires_at TEXT;
ALTER TABLE user_plans ADD COLUMN source TEXT;
ALTER TABLE user_plans ADD COLUMN original_transaction_id TEXT;
ALTER TABLE user_plans ADD COLUMN environment TEXT;
ALTER TABLE user_plans ADD COLUMN comp_redeemed TEXT;   -- step 6: hashes of comp codes redeemed by this account
CREATE INDEX IF NOT EXISTS idx_user_plans_original_tx ON user_plans(original_transaction_id);
