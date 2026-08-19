-- Vezvezak backend — D1 (SQLite) schema.
--
-- PRIVACY (Doctrine Art.7): we store the minimum needed to run the account and
-- to build the L5 contribution corpus. No income/expense data, no individual
-- economic profile — that stays on the device. Passwords are never stored, only
-- a PBKDF2-SHA256 hash + per-user random salt.
--
-- Apply:  npx wrangler d1 execute vezvezak --remote --file=./schema.sql

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  identifier    TEXT NOT NULL UNIQUE,      -- email or phone, normalized lowercase
  channel       TEXT NOT NULL,             -- 'email' | 'phone'
  name          TEXT,
  pw_hash       TEXT NOT NULL,             -- base64 PBKDF2-SHA256 derived key
  pw_salt       TEXT NOT NULL,             -- base64 random 16 bytes
  pw_iter       INTEGER NOT NULL DEFAULT 210000,
  verified      INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL,
  last_login_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_identifier ON users(identifier);

-- One-time codes for signup / signin / reset. Hashed, single-use, expiring.
CREATE TABLE IF NOT EXISTS otp_codes (
  id          TEXT PRIMARY KEY,
  identifier  TEXT NOT NULL,
  purpose     TEXT NOT NULL,               -- 'signup' | 'signin' | 'reset'
  code_hash   TEXT NOT NULL,               -- SHA-256 of the code (never plaintext)
  expires_at  INTEGER NOT NULL,            -- epoch ms
  attempts    INTEGER NOT NULL DEFAULT 0,
  consumed_at INTEGER,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_otp_lookup ON otp_codes(identifier, purpose, consumed_at);

-- Short-lived tokens proving an OTP was verified, so /auth/password/reset can
-- trust the caller without re-sending the code.
CREATE TABLE IF NOT EXISTS reset_tokens (
  token      TEXT PRIMARY KEY,
  identifier TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
);

-- L5 ⭐ — the contribution corpus. This is the only data a competitor cannot buy.
CREATE TABLE IF NOT EXISTS reviews (
  id         TEXT PRIMARY KEY,
  user_id    TEXT,                          -- nullable: anonymous contributions allowed
  subject    TEXT NOT NULL,                 -- product title / query the review is about
  stars      INTEGER NOT NULL CHECK (stars BETWEEN 1 AND 5),
  text       TEXT,
  lang       TEXT,
  created_at TEXT NOT NULL,
  ip_hash    TEXT,                          -- hashed, for abuse control only
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_reviews_subject ON reviews(subject);
CREATE INDEX IF NOT EXISTS idx_reviews_user ON reviews(user_id);

-- Reviews OF the app itself. Only AI-approved 4-5★ go on the public wall.
CREATE TABLE IF NOT EXISTS app_reviews (
  id          TEXT PRIMARY KEY,
  user_id     TEXT,
  stars       INTEGER NOT NULL CHECK (stars BETWEEN 1 AND 5),
  text        TEXT NOT NULL,
  approved    INTEGER NOT NULL DEFAULT 0,
  reject_note TEXT,
  created_at  TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_app_reviews_approved ON app_reviews(approved, created_at);

-- Seller self-listings. Vezvezak introduces, never guarantees (Doctrine Art.3).
CREATE TABLE IF NOT EXISTS merchants (
  id           TEXT PRIMARY KEY,
  user_id      TEXT,
  store_name   TEXT NOT NULL,
  category     TEXT,
  biz_type     TEXT,                        -- retail | wholesale | services | food | online
  address      TEXT NOT NULL,
  latitude     REAL,
  longitude    REAL,
  phone        TEXT,
  website      TEXT,
  notes        TEXT,
  services     TEXT,
  wholesale    INTEGER NOT NULL DEFAULT 0,
  status       TEXT NOT NULL DEFAULT 'pending',  -- pending | live | rejected
  submitted_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_merchants_geo ON merchants(latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_merchants_status ON merchants(status);

-- Simple per-identifier/IP rate limiting (abuse + cost control).
CREATE TABLE IF NOT EXISTS rate_limits (
  bucket     TEXT PRIMARY KEY,              -- e.g. 'login:foo@bar.com'
  count      INTEGER NOT NULL,
  window_at  INTEGER NOT NULL
);

-- Referrals: each user gets a stable code; when a NEW device first opens the app
-- with that code, the referrer is credited once. Self-referral and double-credit
-- are prevented server-side (a device fingerprint can be claimed only once).
CREATE TABLE IF NOT EXISTS referrals (
  id            TEXT PRIMARY KEY,
  referrer_code TEXT NOT NULL,            -- the inviter's code
  referred_hash TEXT NOT NULL UNIQUE,     -- hashed new-device id (one claim ever)
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_referrals_code ON referrals(referrer_code);

-- A per-user referral code (derived, stored so it's stable + unique).
CREATE TABLE IF NOT EXISTS referral_codes (
  code       TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Local job postings (submit + browse nearby). Introductions only (Art.3).
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, user_id TEXT, title TEXT NOT NULL, business TEXT NOT NULL,
  employment_type TEXT, description TEXT, address TEXT, phone TEXT,
  latitude REAL, longitude REAL, status TEXT NOT NULL DEFAULT 'live', submitted_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_geo ON jobs(latitude, longitude);

-- The advertising subsystem (ads / coupons / luxury offers) was REMOVED entirely
-- (Ehsan 2026-08-13): a dormant paid-placement mechanism in a product whose central
-- claim is that it does not sell placement. These DROPs retire the tables. They are
-- deliberately NOT auto-run against production yet — the drops touch what was
-- deployed, so they need separate approval before `wrangler d1 execute`.
DROP TABLE IF EXISTS ads;
DROP TABLE IF EXISTS coupons;
DROP TABLE IF EXISTS luxury_offers;

-- Verification requests (seller/influencer/advertiser). Doc review is manual.
CREATE TABLE IF NOT EXISTS verifications (
  id TEXT PRIMARY KEY, user_id TEXT, kind TEXT NOT NULL, company_name TEXT,
  is_company INTEGER NOT NULL DEFAULT 0, passport_consent INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending', submitted_at TEXT NOT NULL,
  UNIQUE(user_id, kind),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Influencer self-listings.
CREATE TABLE IF NOT EXISTS influencers (
  id TEXT PRIMARY KEY, user_id TEXT, name TEXT NOT NULL, handle TEXT NOT NULL,
  offer TEXT, phone TEXT, website TEXT, latitude REAL, longitude REAL,
  status TEXT NOT NULL DEFAULT 'pending', submitted_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);


-- Commission attribution. A click is registered when the user taps through to a
-- retailer; a conversion arrives later as a server-to-server postback from the
-- affiliate network. We only RECORD what is owed — Vezvezak never moves money
-- (Doctrine Art.4). No PII: `device_hash` is a one-way hash, never a raw id.
CREATE TABLE IF NOT EXISTS affiliate_clicks (
  click_id TEXT PRIMARY KEY,
  seller TEXT,
  host TEXT,
  device_hash TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS conversions (
  id TEXT PRIMARY KEY,
  click_id TEXT,
  network TEXT NOT NULL,
  order_id TEXT NOT NULL,
  amount REAL,
  currency TEXT,
  commission REAL,
  status TEXT NOT NULL,          -- confirmed | pending | rejected
  seller TEXT,
  host TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(network, order_id)      -- idempotency: one network order counts once
);
CREATE INDEX IF NOT EXISTS idx_conversions_click ON conversions(click_id);
CREATE INDEX IF NOT EXISTS idx_clicks_device ON affiliate_clicks(device_hash);

-- Seller catalog: first-party goods + prices that sellers upload themselves (the
-- lawful "feed" and the moat). An item is an introduction awaiting review, never
-- a guarantee (Art.3); stock is never faked (NULL = unknown, Art.8); a discount
-- exists only when a real was_price is provided (Art.8). Vezvezak never handles
-- the payment (Art.4) — these are listings, not transactions.
CREATE TABLE IF NOT EXISTS catalog_items (
  id           TEXT PRIMARY KEY,
  merchant_id  TEXT NOT NULL,
  user_id      TEXT,
  title        TEXT NOT NULL,
  brand        TEXT,
  model        TEXT,
  gtin         TEXT,
  category     TEXT,
  condition    TEXT,                              -- new | used | refurbished
  description  TEXT,
  image_url    TEXT,
  status       TEXT NOT NULL DEFAULT 'pending',   -- pending | live | rejected
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  FOREIGN KEY (merchant_id) REFERENCES merchants(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS catalog_variants (
  id           TEXT PRIMARY KEY,
  item_id      TEXT NOT NULL,
  merchant_id  TEXT NOT NULL,
  sku          TEXT,
  attributes   TEXT,                              -- JSON: {size,color,...}
  price        REAL,
  currency     TEXT,
  was_price    REAL,                              -- only when a real discount
  unit         TEXT,                              -- each | kg | hour | service
  in_stock     INTEGER,                           -- NULL=unknown, 1=yes, 0=no
  quantity     INTEGER,
  tier_min_qty INTEGER,                           -- wholesale tier threshold
  created_at   TEXT NOT NULL,
  FOREIGN KEY (item_id) REFERENCES catalog_items(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_catalog_items_merchant ON catalog_items(merchant_id, status);
CREATE INDEX IF NOT EXISTS idx_catalog_variants_item ON catalog_variants(item_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_catalog_variant_sku ON catalog_variants(merchant_id, sku);

-- User feedback / feature suggestions. If a suggestion is useful AND not already
-- built, the operator flips status→'rewarded' and grants points to the user_id.
CREATE TABLE IF NOT EXISTS feedback (
  id          TEXT PRIMARY KEY,
  user_id     TEXT,
  kind        TEXT,                             -- suggestion | bug | praise | other
  text        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'new',      -- new | reviewed | built | rewarded
  created_at  TEXT NOT NULL
);

-- Retailer price-match policies — operator-curated, SOURCED facts (each carries
-- the official policy URL + the date recorded). Honest empty until seeded; we
-- never invent a retailer's policy (Art.8/Art.9). `matches` is the retailer's
-- own stated position, presented as evidence to "verify", not a guarantee.
CREATE TABLE IF NOT EXISTS price_match_policies (
  id         TEXT PRIMARY KEY,
  retailer   TEXT NOT NULL,      -- normalized key
  label      TEXT NOT NULL,      -- display name
  matches    INTEGER NOT NULL,   -- 1 = matches competitors, 0 = does not
  note       TEXT,
  url        TEXT,               -- official policy link (the source)
  country    TEXT,               -- NULL = global
  as_of      TEXT                -- date the policy was recorded
);

-- ── Server-authoritative plan + AI usage (anti-abuse; Ehsan P0) ──────────────
-- user_plans is written by IAP receipt validation (owner-side); defaults to
-- 'free' when absent, so the server ALWAYS enforces free limits authoritatively.
CREATE TABLE IF NOT EXISTS user_plans (
  user_id    TEXT PRIMARY KEY,
  plan       TEXT NOT NULL DEFAULT 'free',   -- 'free' | 'pro' | 'max' | 'max20x'
  updated_at TEXT
);

-- weekly_search_usage — the server-authoritative WEEKLY CAP counters (Ehsan
-- 2026-08-13). Local and online live searches are counted SEPARATELY as COUNTS.
-- There is NO monetary column: the cap is never money, never a balance, and no
-- dollar figure is stored per user anywhere. The cap REFILLS at the account's
-- staggered weekly boundary — used → 0, the same full cap available again —
-- nothing rolls over, expires, or is forfeited (hence window_start/refill_*,
-- never "spent"/"remaining_usd"). This REPLACES the old daily ai_usage table
-- (which stored a per-user compute dollar balance — removed on purpose).
CREATE TABLE IF NOT EXISTS weekly_search_usage (
  user_id       TEXT PRIMARY KEY,
  local_used    INTEGER NOT NULL DEFAULT 0,   -- live LOCAL (Google Places) searches used this window
  online_used   INTEGER NOT NULL DEFAULT 0,   -- live ONLINE (SerpApi) searches used this window
  window_start  INTEGER NOT NULL,             -- epoch ms: start of the current weekly window (last refill boundary)
  refill_dow    INTEGER NOT NULL,             -- 0-6: assigned reset weekday (staggered per account, from a hash of user_id)
  refill_minute INTEGER NOT NULL,             -- 0-1439: assigned reset minute-of-day (staggered)
  updated_at    TEXT
);

-- Retire the old per-user dollar-balance table if a previous deploy created it.
-- The cap model stores COUNTS only; no per-user dollar balance survives in D1.
DROP TABLE IF EXISTS ai_usage;

-- consumed_searches — makes a weekly CAP mean whole SEARCHES, not API calls
-- (Ehsan 2026-08-13, Part 1b). One user search fans out to Text + Nearby (+ a
-- few Photos); they share ONE client vz_sid and collapse into ONE slot here, so a
-- Pro user's "18 local" is 18 real searches, not 9. Also the sub-call ceiling:
-- photos_used bounds how many paid Photo fetches may ride under a single local
-- slot, so a tampered client can't pull unlimited photos for one consumed search.
-- Rows are scoped to window_start and pruned when the weekly window refills.
CREATE TABLE IF NOT EXISTS consumed_searches (
  user_id      TEXT NOT NULL,
  search_id    TEXT NOT NULL,                 -- client vz_sid, one per search bundle
  kind         TEXT NOT NULL,                 -- 'local' | 'online' (the slot this bundle took)
  window_start INTEGER NOT NULL,              -- the weekly window this slot belongs to
  photos_used  INTEGER NOT NULL DEFAULT 0,    -- paid Photo sub-calls ridden under this (local) slot
  created_at   TEXT NOT NULL,
  PRIMARY KEY (user_id, search_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_consumed_window ON consumed_searches(user_id, window_start);

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

-- Translation cache (P0.5): GLOBAL and identifier-free. Keyed by sha256(source_lang || query) —
-- the raw query is never stored, there is no user id and no IP. A query translation is a language
-- fact, not private user content; this caches for latency/cost only (same rule as Places).
CREATE TABLE IF NOT EXISTS translation_cache (
  k          TEXT PRIMARY KEY,   -- sha256(source_lang || ' ' || query)
  translated TEXT NOT NULL,
  at         INTEGER NOT NULL
);
