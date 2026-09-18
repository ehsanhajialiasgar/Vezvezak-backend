#!/usr/bin/env bash
# 2026-09-18 · the eight merchant columns, one statement per execution, safe to run twice.
#
# WHY NOT A .sql FILE. `wrangler d1 execute --file` sends the file as ONE batch, so the first failing statement
# aborts the rest and the CLI reports a rollback — and SQLite has no `ADD COLUMN IF NOT EXISTS`, so re-running a
# DDL file always fails on the first column that already exists. Each ALTER is its own execution here: a column
# that is already there fails ONLY its own command, the script says so and carries on.
#
# Every DEFAULT below is a constant. `commission_agreed INTEGER NOT NULL DEFAULT 0` is legal precisely because
# the default is constant and non-null — SQLite refuses ADD COLUMN ... NOT NULL with no default.
#
#   bash migrations_merchant_columns.sh          # against the REMOTE database (asks nothing, writes columns)
#   bash migrations_merchant_columns.sh --local  # against the local one
set -u
FLAG="${1:---remote}"
DB=vezvezak
COLUMNS=(
  "seller_type TEXT"
  "offer_type TEXT"
  "sale_channel TEXT"
  "showcase TEXT"
  "radius_miles INTEGER"
  "commission_agreed INTEGER NOT NULL DEFAULT 0"
  "luxury_brand TEXT"
  "luxury_cert TEXT"
)
added=0; already=0; failed=0
for col in "${COLUMNS[@]}"; do
  name="${col%% *}"
  out=$(npx wrangler d1 execute "$DB" "$FLAG" --command="ALTER TABLE merchants ADD COLUMN ${col};" 2>&1)
  if echo "$out" | grep -q "duplicate column name"; then
    echo "  = ${name}: already there"; already=$((already+1))
  elif echo "$out" | grep -qi "error"; then
    echo "  ✗ ${name}: $(echo "$out" | grep -i error | head -1)"; failed=$((failed+1))
  else
    echo "  + ${name}: added"; added=$((added+1))
  fi
done
echo ""
echo "  added ${added}, already present ${already}, failed ${failed}"
# Say what the table looks like now, from the database itself — never from what this script believes it did.
npx wrangler d1 execute "$DB" "$FLAG" --command="SELECT sql FROM sqlite_master WHERE type='table' AND name='merchants';"
[ "$failed" -eq 0 ]
