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

-- Merchant/influencer ads (submitted → AI-moderated → live). No adult ads.
CREATE TABLE IF NOT EXISTS ads (
  id TEXT PRIMARY KEY, user_id TEXT, title TEXT NOT NULL, body TEXT NOT NULL,
  category TEXT, cta_url TEXT, phone TEXT, scope TEXT, is_adult INTEGER NOT NULL DEFAULT 0,
  seller_type TEXT, country_code TEXT, latitude REAL, longitude REAL, luxury INTEGER NOT NULL DEFAULT 0,
  moderation_status TEXT NOT NULL DEFAULT 'pending', submitted_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_ads_geo ON ads(latitude, longitude);

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

-- Curated coupons + luxury offers (operator-seeded; GET reads live ones).
CREATE TABLE IF NOT EXISTS coupons (
  id TEXT PRIMARY KEY, store TEXT NOT NULL, code TEXT, title TEXT NOT NULL,
  discount_label TEXT, country TEXT, category TEXT, url TEXT, expires_at TEXT
);
CREATE TABLE IF NOT EXISTS luxury_offers (
  id TEXT PRIMARY KEY, brand TEXT NOT NULL, title TEXT NOT NULL, kind TEXT,
  discount_label TEXT, code TEXT, image_url TEXT, url TEXT, country TEXT, category TEXT, expires_at TEXT
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

-- ai_usage counts each user's compute-costing actions PER DAY, server-side, so a
-- tampered client can never grant itself free AI. One row per (user, UTC day).
CREATE TABLE IF NOT EXISTS ai_usage (
  user_id    TEXT NOT NULL,
  day        TEXT NOT NULL,                  -- YYYY-MM-DD (UTC)
  searches   INTEGER NOT NULL DEFAULT 0,     -- product searches used today
  used_usd   REAL NOT NULL DEFAULT 0,        -- compute $ spent today
  updated_at TEXT,
  PRIMARY KEY (user_id, day)
);

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
