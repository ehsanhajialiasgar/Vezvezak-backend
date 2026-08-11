#!/bin/bash
# Vezvezak backend — one-command setup.
# Run:  bash ~/Desktop/Vezvezak/backend/setup.sh
#
# Does everything in the right order, and is safe to re-run.

set -u
cd "$(dirname "$0")" || exit 1   # always run from the backend folder

W="npx --yes wrangler@4"
say() { printf "\n\033[1;36m==> %s\033[0m\n" "$1"; }
ok()  { printf "\033[1;32m✅ %s\033[0m\n" "$1"; }
bad() { printf "\033[1;31m❌ %s\033[0m\n" "$1"; }

# ── 1. Cloudflare login ─────────────────────────────────────────────────────
say "1/6  Checking your Cloudflare login"
if ! $W whoami >/dev/null 2>&1; then
  bad "Not logged in to Cloudflare."
  echo "   Run this first, finish it in the browser, then run this script again:"
  echo "     npx wrangler login"
  exit 1
fi
ok "Logged in."

# ── 2. D1 database ──────────────────────────────────────────────────────────
say "2/6  Creating the database (skipped if it already exists)"
DB_ID=$($W d1 list --json 2>/dev/null | python3 -c "
import sys, json
try:
    for d in json.load(sys.stdin):
        if d.get('name') == 'vezvezak':
            print(d.get('uuid') or d.get('database_id') or ''); break
except Exception:
    pass
")

if [ -z "$DB_ID" ]; then
  OUT=$($W d1 create vezvezak 2>&1)
  echo "$OUT" | grep -v "^$"
  DB_ID=$(echo "$OUT" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
fi

if [ -z "$DB_ID" ]; then
  bad "Could not get the database id. Paste the output above to Claude."
  exit 1
fi
ok "Database id: $DB_ID"

# ── 3. Write the id into wrangler.toml ──────────────────────────────────────
say "3/6  Saving the database id into wrangler.toml"
python3 - "$DB_ID" <<'PY'
import re, sys
p = 'wrangler.toml'
s = open(p).read()
s = re.sub(r'database_id = "[^"]*"', 'database_id = "%s"' % sys.argv[1], s, count=1)
open(p, 'w').write(s)
PY
ok "Saved."

# ── 4. Create the tables ────────────────────────────────────────────────────
say "4/6  Creating the tables"
if $W d1 execute vezvezak --remote --file=./schema.sql --yes >/dev/null 2>&1; then
  ok "Tables created."
else
  $W d1 execute vezvezak --remote --file=./schema.sql --yes
  bad "Table creation reported a problem (often fine if they already exist)."
fi

# ── 5. Deploy ───────────────────────────────────────────────────────────────
say "5/6  Deploying the API"
DEPLOY=$($W deploy 2>&1)
echo "$DEPLOY" | grep -iE "https://|Uploaded|Deployed|error" | head -5
URL=$(echo "$DEPLOY" | grep -oE 'https://[a-z0-9._-]*workers\.dev' | head -1)
[ -n "$URL" ] && ok "Deployed to: $URL" || bad "No URL found — paste the output above to Claude."

# ── 6. Secret (generated for you — no need to invent one) ───────────────────
say "6/6  Creating the login signing key"
SECRET=$(openssl rand -base64 48 | tr -d '\n=' | tr '/+' '_-')
if echo "$SECRET" | $W secret put JWT_SECRET >/dev/null 2>&1; then
  ok "Signing key stored (only Cloudflare has it — it is not saved on your Mac)."
else
  bad "Could not store the signing key. Run manually:  npx wrangler secret put JWT_SECRET"
fi

# ── verify ──────────────────────────────────────────────────────────────────
if [ -n "${URL:-}" ]; then
  say "Checking it is alive"
  sleep 3
  BODY=$(curl -s --max-time 15 "$URL/health")
  echo "$BODY"
  case "$BODY" in
    *'"ok":true'*) ok "BACKEND IS LIVE 🎉" ;;
    *) bad "Not answering yet. Wait ~30s and run:  curl $URL/health" ;;
  esac
  echo
  echo "Your API URL:  $URL"
  echo "Give that URL to Claude so it can point the app at it."
fi
