-- ── Telemetry (Ehsan 2026-08-09) ────────────────────────────────────────────
-- PII-free by construction. Every column is a whitelisted, non-identifying field:
-- no query text, no user id, no location finer than country (never collected).
-- One row per event; the client batches and the Worker (/t) re-applies the
-- whitelist before insert.
CREATE TABLE IF NOT EXISTS telemetry (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  name                TEXT    NOT NULL,   -- search.performed | claim.shown | claim.evidence | offer.referred | watch.added | purchase.referred
  at                  INTEGER NOT NULL,   -- client event time (ms epoch)
  lang                TEXT,               -- search.performed
  script              TEXT,               -- search.performed
  result_count        INTEGER,            -- search.performed
  unknown_count       INTEGER,            -- search.performed (feeds abstention rate)
  engine              TEXT,               -- claim.shown | claim.evidence | watch.added
  certainty           TEXT,               -- claim.shown (certain|probable|unsure|unknown)
  seller_id           TEXT,               -- offer.referred
  landed_cost         REAL,               -- offer.referred
  product_fingerprint TEXT                -- purchase.referred (non-reversible hash)
);
CREATE INDEX IF NOT EXISTS idx_telemetry_name_at ON telemetry (name, at);
