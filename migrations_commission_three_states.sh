#!/usr/bin/env bash
# 2026-09-18 · run the commission_agreed rebuild ONLY while it is still needed. Safe to run twice.
#
# The rebuild itself cannot be idempotent (its CREATE would collide on a second run), so the guard lives here:
# this asks the DATABASE what the column looks like right now, and does nothing at all if it is already
# nullable. It never decides from what a previous run believed it did.
#
#   bash migrations_commission_three_states.sh            # REMOTE
#   bash migrations_commission_three_states.sh --local     # local
set -u
FLAG="${1:---remote}"
DB=vezvezak
schema=$(npx wrangler d1 execute "$DB" "$FLAG" --command="SELECT sql FROM sqlite_master WHERE type='table' AND name='merchants';" 2>&1)
if echo "$schema" | grep -q "commission_agreed INTEGER NOT NULL"; then
  echo "  commission_agreed is still NOT NULL — rebuilding the table."
  npx wrangler d1 execute "$DB" "$FLAG" --file=./migrations_commission_three_states.sql || { echo "  ✗ rebuild failed — the table is unchanged (the file runs as one batch)"; exit 1; }
elif echo "$schema" | grep -q "commission_agreed INTEGER"; then
  echo "  commission_agreed is already nullable — nothing to do."
else
  echo "  ✗ could not read the merchants schema; refusing to guess."; exit 1
fi
# Report from the database, never from this script's beliefs.
npx wrangler d1 execute "$DB" "$FLAG" --command="SELECT COUNT(*) AS rows, SUM(commission_agreed IS NULL) AS never_asked, SUM(commission_agreed=0) AS declined, SUM(commission_agreed=1) AS agreed FROM merchants;"
