-- 2026-09-16 · /ai/normalize cache (src/translate.js). schema.sql declares this table, but production answers every
-- repeated query as slowly as a new one (live: /health ~0.2 s; the same «میز» three times ~1.4–1.6 s each), which is
-- what a missing table looks like — cacheGet/cacheSet fail silently by design. Inferred from timing, NOT queried
-- (production reads are the founder's). Safe to run whether or not the table exists.
--   npx wrangler d1 execute vezvezak --remote --file=./migrations_translation_cache.sql
-- Privacy §5/§12 (publish 5) describe this store: English terms under a one-way hash, up to 30 days.
CREATE TABLE IF NOT EXISTS translation_cache (
  k          TEXT PRIMARY KEY,   -- sha256(namespace || query); no raw query, no user, no IP
  translated TEXT NOT NULL,
  at         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_translation_cache_at ON translation_cache(at);
