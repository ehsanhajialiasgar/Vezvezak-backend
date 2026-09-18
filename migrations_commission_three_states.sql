-- 2026-09-18 · commission_agreed becomes three states: agreed · declined · never asked.
--
-- WHY. The column was added as INTEGER NOT NULL DEFAULT 0, so SQLite backfilled every row that already existed
-- with 0. On the remote database that is all 8 rows (newest submitted_at 2026-09-17T18:11Z, the columns were
-- added on 2026-09-18, and all 8 have seller_type NULL — none was written by the new code). Every one of those
-- zeros is a default wearing the clothes of an answer: "declined" and "never asked" read identically, and the
-- second is the truth, because the consent checkbox was removed from the wizard on 2026-08-17 and nobody has
-- been asked since.
--
-- SQLite cannot drop NOT NULL in place, so this is the standard table rebuild. It runs as ONE file on purpose:
-- a rebuild must be all-or-nothing, and a batched file gives exactly that. Idempotency is NOT in this file —
-- it cannot be — it is in migrations_commission_three_states.sh, which reads the live schema first and runs
-- this only while the column is still NOT NULL. Running this file twice would fail at the CREATE.
--
-- THE BOUNDARY: submitted_at < '2026-09-18' is every row that existed before the column did. A row written
-- after that carries whatever the server recorded, which is now NULL unless the merchant actually answered.
CREATE TABLE merchants_rebuild (
  id           TEXT PRIMARY KEY,
  user_id      TEXT,
  store_name   TEXT NOT NULL,
  category     TEXT,
  biz_type     TEXT,
  address      TEXT NOT NULL,
  latitude     REAL,
  longitude    REAL,
  phone        TEXT,
  website      TEXT,
  notes        TEXT,
  services     TEXT,
  wholesale    INTEGER NOT NULL DEFAULT 0,
  seller_type       TEXT,
  offer_type        TEXT,
  sale_channel      TEXT,
  showcase          TEXT,
  radius_miles      INTEGER,
  commission_agreed INTEGER,          -- 1 agreed · 0 declined · NULL never asked
  luxury_brand      TEXT,
  luxury_cert       TEXT,
  status       TEXT NOT NULL DEFAULT 'pending',
  submitted_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Columns are named on both sides — never SELECT * — so a future column order cannot silently misalign them.
INSERT INTO merchants_rebuild (
  id, user_id, store_name, category, biz_type, address, latitude, longitude, phone, website, notes, services,
  wholesale, seller_type, offer_type, sale_channel, showcase, radius_miles, commission_agreed, luxury_brand,
  luxury_cert, status, submitted_at)
SELECT
  id, user_id, store_name, category, biz_type, address, latitude, longitude, phone, website, notes, services,
  wholesale, seller_type, offer_type, sale_channel, showcase, radius_miles,
  CASE WHEN submitted_at < '2026-09-18' THEN NULL ELSE commission_agreed END,
  luxury_brand, luxury_cert, status, submitted_at
FROM merchants;

DROP TABLE merchants;
ALTER TABLE merchants_rebuild RENAME TO merchants;
CREATE INDEX IF NOT EXISTS idx_merchants_geo ON merchants(latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_merchants_status ON merchants(status);
