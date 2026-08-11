-- THE THREE NUMBERS (Ehsan 2026-08-09). Run against the vezvezak-api D1 database.
-- All derived from the six PII-free events in the `telemetry` table.

-- 1) ABSTENTION RATE — the share of shown claims that returned 'unknown'.
--    The central metric of NSF Phase I; unique to this product.
SELECT
  ROUND(100.0 * SUM(CASE WHEN certainty = 'unknown' THEN 1 ELSE 0 END) / COUNT(*), 1) AS abstention_pct,
  COUNT(*) AS claims_shown
FROM telemetry
WHERE name = 'claim.shown';

-- Search-level cross-check: unknown results / all results.
SELECT ROUND(100.0 * SUM(unknown_count) / NULLIF(SUM(result_count), 0), 1) AS unknown_result_pct
FROM telemetry WHERE name = 'search.performed';

-- 2) FUNNEL DROP-OFF — search.performed -> claim.shown -> claim.evidence -> offer.referred.
SELECT
  SUM(CASE WHEN name = 'search.performed' THEN 1 ELSE 0 END) AS searches,
  SUM(CASE WHEN name = 'claim.shown'      THEN 1 ELSE 0 END) AS claims_shown,
  SUM(CASE WHEN name = 'claim.evidence'   THEN 1 ELSE 0 END) AS evidence_opened,
  SUM(CASE WHEN name = 'offer.referred'   THEN 1 ELSE 0 END) AS offers_referred
FROM telemetry;

-- 3) COHORT RETENTION — weekly active buckets (privacy-preserving; no device id).
SELECT
  strftime('%Y-%W', datetime(at / 1000, 'unixepoch')) AS week,
  COUNT(*)                                             AS events,
  SUM(CASE WHEN name = 'search.performed' THEN 1 ELSE 0 END) AS searches
FROM telemetry
GROUP BY week
ORDER BY week;
