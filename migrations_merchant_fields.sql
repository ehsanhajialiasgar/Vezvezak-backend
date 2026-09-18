-- 2026-09-18 · the eight fields the app sends, and the end of the pending trap.
--
-- PART 1 — merchants: eight columns that never existed. The submit screen has always collected these and
-- postSubmission has always put them on the wire; the INSERT had no columns for them, so they vanished on
-- arrival. commission_agreed is the important one: a merchant agreed to pay a commission and nothing kept
-- the fact. D1/SQLite has no "ADD COLUMN IF NOT EXISTS" — if a column already exists the statement errors
-- and the rest still apply, so run it once and read the output.
ALTER TABLE merchants ADD COLUMN seller_type TEXT;
ALTER TABLE merchants ADD COLUMN offer_type TEXT;
ALTER TABLE merchants ADD COLUMN sale_channel TEXT;
ALTER TABLE merchants ADD COLUMN showcase TEXT;
ALTER TABLE merchants ADD COLUMN radius_miles INTEGER;
ALTER TABLE merchants ADD COLUMN commission_agreed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE merchants ADD COLUMN luxury_brand TEXT;
ALTER TABLE merchants ADD COLUMN luxury_cert TEXT;

-- PART 2 — the catalogue items already in the database. Every one of them is 'pending', and until today
-- nothing could ever move them: the only writer of 'live' was an AI branch that is off in production. They
-- are now published under the same rule as a new item — listed by the merchant, unverified — except any the
-- deterministic prohibited screen already rejected, which stay rejected.
UPDATE catalog_items SET status = 'live', updated_at = datetime('now') WHERE status = 'pending';
