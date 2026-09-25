-- App Store Server Notifications v2 — the idempotency record (Ehsan 2026-09-25).
-- Safe to run more than once: both statements are IF NOT EXISTS.
CREATE TABLE IF NOT EXISTS apple_notifications (
  notification_uuid TEXT PRIMARY KEY,
  notification_type TEXT,
  subtype           TEXT,
  original_transaction_id TEXT,
  outcome           TEXT,
  received_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_apple_notif_txn ON apple_notifications(original_transaction_id);
