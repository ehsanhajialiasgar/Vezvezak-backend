-- D1 + D2 (Ehsan 2026-09-21) — merchants: a real status, and one store per name per seller.
--
-- SAFE TO RUN TWICE. Every statement is either guarded by IF [NOT] EXISTS or is a WHERE-scoped UPDATE/DELETE
-- that matches nothing on a second run. Run it as many times as you like.
--
-- D1 — THE STATUS WAS A QUEUE WITH NO REVIEWER. merchants.status defaulted to 'pending' and NOTHING in the whole
-- backend ever wrote anything else: no UPDATE merchants exists. Every store ever submitted was 'pending' forever,
-- while the app told the seller their listing was waiting to be reviewed. A submitted store is live — under the
-- label it has always carried, listed by the merchant and unverified — so the data now says that.
--
-- D2 — THE SAME STORE COULD BE SUBMITTED TWICE. There was no uniqueness on (user_id, store_name) and
-- merchantSubmit does not look before it inserts, so a double tap or a retry made a second row. The duplicates
-- are collapsed to the OLDEST row (the one any existing catalog item points at) before the index is created,
-- because creating a unique index over duplicate rows fails.

-- ── 1 · collapse existing duplicates, keeping the oldest row per (user_id, store_name) ────────────────────────
-- Catalog items reference merchants(id), so the survivors are re-pointed BEFORE the losers are removed. Rows with
-- a NULL user_id are left alone: SQLite treats NULLs as distinct in a unique index, and they are not a duplicate
-- of anything we can attribute.
-- NOTE ON THE FIRST DRAFT OF THIS STATEMENT, kept because it nearly shipped: it read
--     SET merchant_id = (SELECT MIN(m2.rowid) AND m2.id FROM ...)
-- and `MIN(rowid) AND id` is a boolean AND, not a tuple — so every re-pointed item got merchant_id = 0 and was
-- orphaned. It was found by running the migration against a seeded copy of the real schema and LOOKING at the
-- row afterwards, which is the only reason it is not in production.
UPDATE catalog_items
   SET merchant_id = (
     SELECT o.id FROM merchants o
      WHERE o.user_id    = (SELECT user_id    FROM merchants WHERE id = catalog_items.merchant_id)
        AND o.store_name = (SELECT store_name FROM merchants WHERE id = catalog_items.merchant_id)
      ORDER BY o.rowid ASC LIMIT 1)
 WHERE merchant_id IN (
     SELECT m.id FROM merchants m
      WHERE m.user_id IS NOT NULL
        AND EXISTS (SELECT 1 FROM merchants o
                     WHERE o.user_id = m.user_id AND o.store_name = m.store_name AND o.rowid < m.rowid));

DELETE FROM merchants
 WHERE user_id IS NOT NULL
   AND EXISTS (SELECT 1 FROM merchants o
                WHERE o.user_id = merchants.user_id
                  AND o.store_name = merchants.store_name
                  AND o.rowid < merchants.rowid);

-- ── 2 · one store per name per seller, enforced by the database and not by a comment ──────────────────────────
CREATE UNIQUE INDEX IF NOT EXISTS idx_merchants_user_store ON merchants(user_id, store_name);

-- ── 3 · every store that was stuck in a queue that does not exist is what it always was: live ─────────────────
UPDATE merchants SET status = 'live' WHERE status = 'pending';
