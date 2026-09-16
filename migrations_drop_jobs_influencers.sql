-- 2026-09-16 · Drop the jobs and influencers tables (founder decision). Their routes were deleted (61afb45), no app path
-- ever reached them, and no policy sentence describes what they stored — rows held for a feature that does not exist.
-- NOT APPLIED BY CODE. RUN ONLY IN THE DEPLOY SESSION, AND ONLY AFTER the Worker built from this branch is live:
--   npx wrangler d1 execute vezvezak --remote --file=./migrations_drop_jobs_influencers.sql
-- ORDER MATTERS: the Worker at 531bee3 deletes from both tables inside ONE atomic batch during account deletion.
-- Dropping them while that Worker is live makes EVERY account deletion fail ("nothing removed"). Code first, then this.
DROP INDEX IF EXISTS idx_jobs_geo;
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS influencers;
