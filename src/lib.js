/**
 * Shared primitives: crypto, JWT, responses, rate limiting.
 * Runs on the Cloudflare Workers runtime (WebCrypto only — no Node APIs).
 */

import { resolvePlan } from './usage.js';

export const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Max-Age': '86400',
};

export function json(status, body, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS, ...extra },
  });
}
export const ok = (body = {}) => json(200, { ok: true, ...body });
export const fail = (status, error, reason) => json(status, { ok: false, error, ...(reason ? { reason } : {}) });

// ── encoding ────────────────────────────────────────────────────────────────
const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64u(bytes) {
  let s = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64u(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
export function uid(prefix) {
  return `${prefix}_${b64u(crypto.getRandomValues(new Uint8Array(12)))}`;
}
export const nowIso = () => new Date().toISOString();

// ── password hashing (PBKDF2-SHA256, per-user salt) ──────────────────────────
// Plaintext passwords are never stored, logged, or returned.
//
// The Cloudflare Workers runtime HARD-CAPS PBKDF2 at 100,000 iterations:
//   "Pbkdf2 failed: iteration counts above 100000 are not supported"
// (verified empirically against the live runtime: 100000 ok, 100001 throws).
// That cap is below the OWASP-2023 guidance of 600,000 for PBKDF2-SHA256, so we
// CHAIN the derivation instead: each round feeds its output in as the next
// round's key material, giving 6 x 100,000 = 600,000 effective iterations while
// no single call exceeds the platform limit.
const PBKDF2_MAX_ITER = 100000;   // platform ceiling — do not raise
const PBKDF2_TOTAL = 600000;      // effective work factor (OWASP 2023)

export async function hashPassword(password, saltB64, totalIter = PBKDF2_TOTAL) {
  const salt = saltB64 ? unb64u(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const rounds = Math.max(1, Math.round(totalIter / PBKDF2_MAX_ITER));
  let material = enc.encode(password);
  for (let i = 0; i < rounds; i++) {
    const key = await crypto.subtle.importKey('raw', material, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: PBKDF2_MAX_ITER, hash: 'SHA-256' }, key, 256,
    );
    material = new Uint8Array(bits);
  }
  // `iter` records the EFFECTIVE total so verification reproduces the same chain.
  return { hash: b64u(material), salt: b64u(salt), iter: rounds * PBKDF2_MAX_ITER };
}

// Constant-time compare — never leak timing information about the hash.
export function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function verifyPassword(password, user) {
  const { hash } = await hashPassword(password, user.pw_salt, user.pw_iter || PBKDF2_TOTAL);
  return timingSafeEqual(hash, user.pw_hash);
}

export async function sha256(text) {
  return b64u(await crypto.subtle.digest('SHA-256', enc.encode(text)));
}

// ── JWT (HS256) ─────────────────────────────────────────────────────────────
async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function signJwt(payload, secret, ttlSeconds = 60 * 60 * 24 * 30) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + ttlSeconds };
  const data = `${b64u(enc.encode(JSON.stringify(header)))}.${b64u(enc.encode(JSON.stringify(body)))}`;
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(data));
  return `${data}.${b64u(sig)}`;
}

export async function verifyJwt(token, secret) {
  try {
    const [h, p, s] = String(token).split('.');
    if (!h || !p || !s) return null;
    const valid = await crypto.subtle.verify(
      'HMAC', await hmacKey(secret), unb64u(s), enc.encode(`${h}.${p}`),
    );
    if (!valid) return null;
    const payload = JSON.parse(dec.decode(unb64u(p)));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

export async function requireAuth(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  return verifyJwt(token, env.JWT_SECRET);
}

// ── identifiers ─────────────────────────────────────────────────────────────
export function normalizeIdentifier(raw) {
  const s = String(raw || '').trim().toLowerCase();
  if (!s) return null;
  if (s.includes('@')) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s) ? s : null;
  }
  const digits = s.replace(/[^\d+]/g, '');
  return digits.length >= 7 ? digits : null;
}
export const channelOf = id => (id.includes('@') ? 'email' : 'phone');

// EMAIL IS THE ONLY WAY IN, AT EVERY DOOR (Ehsan 2026-09-21).
//
// We send no SMS. There is no gateway, no per-country regulatory handling, and sendCode refuses anything that is
// not an email. An identifier we cannot deliver to is an account with no recovery path: the person signs in fine
// for months and is locked out permanently the first time they forget the password. The app has not launched, so
// there are no phone accounts to preserve, and there is no reason to offer a door we cannot open.
//
// This is ONE function called by every auth route rather than a check repeated in five places, because the last
// time a correct guard was written it was put on some of the paths and not the others. It returns the REASON so
// the caller can tell a malformed identifier ("that is not an address") apart from a well-formed phone number
// ("we cannot send you anything") — the person typing a phone number needs to be told which it is.
//
// WHEN SMS EXISTS, this function is the one place that changes.
export function emailOnly(identifier) {
  if (!identifier) return { ok: false, reason: 'identifier_invalid', message: 'Enter a valid email address.' };
  if (channelOf(identifier) !== 'email') {
    return {
      ok: false,
      reason: 'email_required',
      message: 'Sign in with an email address. We cannot send a phone a verification or reset code yet, and an account we cannot help you back into is worse than none.',
    };
  }
  return { ok: true };
}

// ── rate limiting (fixed window, D1-backed) ─────────────────────────────────
// RATE-LIMIT KEYS HOLD NO IDENTIFIER, AND EXPIRED COUNTERS ARE REMOVED (Ehsan 2026-09-15).
// The bucket name used to be stored as written — `login:<email>`, `otp:<phone>` — in plain text, and a row was only
// ever overwritten, never removed: a mistyped email stayed forever. Now the part after the LAST ':' is replaced by a
// keyed hash (the prefix stays readable), so no email, phone, account id or IP is stored here; and every window reset
// removes counters older than the longest window any caller uses. Rows written before this change are therefore gone
// within RATE_LIMIT_MAX_WINDOW_MS of the first reset after deploy.
export const RATE_LIMIT_MAX_WINDOW_MS = 24 * 60 * 60 * 1000;

export async function bucketSubject(subject, env) {
  return sha256(`rl:${subject}:${env.JWT_SECRET || ''}`);
}

async function storedBucket(bucket, env) {
  const i = bucket.lastIndexOf(':');
  if (i < 0) return `${bucket}:${await bucketSubject('', env)}`;
  return `${bucket.slice(0, i)}:${await bucketSubject(bucket.slice(i + 1), env)}`;
}

export async function rateLimit(env, bucketName, limit, windowMs) {
  if (windowMs > RATE_LIMIT_MAX_WINDOW_MS) throw new Error(`rateLimit window ${windowMs} exceeds RATE_LIMIT_MAX_WINDOW_MS — raise the purge bound first`);
  const bucket = await storedBucket(bucketName, env);
  const now = Date.now();
  const row = await env.DB.prepare('SELECT count, window_at FROM rate_limits WHERE bucket = ?')
    .bind(bucket).first();
  if (!row || now - row.window_at > windowMs) {
    await env.DB.prepare('DELETE FROM rate_limits WHERE window_at < ?').bind(now - RATE_LIMIT_MAX_WINDOW_MS).run();
    await env.DB.prepare(
      'INSERT INTO rate_limits (bucket, count, window_at) VALUES (?, 1, ?) ' +
      'ON CONFLICT(bucket) DO UPDATE SET count = 1, window_at = ?',
    ).bind(bucket, now, now).run();
    return { allowed: true, remaining: limit - 1 };
  }
  if (row.count >= limit) {
    return { allowed: false, retryAfterMs: windowMs - (now - row.window_at) };
  }
  await env.DB.prepare('UPDATE rate_limits SET count = count + 1 WHERE bucket = ?').bind(bucket).run();
  return { allowed: true, remaining: limit - row.count - 1 };
}

// Hash the client IP before storing — we need abuse control, not identities.
export async function ipHash(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
  return sha256(ip + (env.JWT_SECRET || ''));
}

export async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}

// Server-authoritative plan for a user. Reads user_plans (written owner-side by
// IAP receipt validation) and folds it onto a live tier; ABSENT ⇒ 'free', so the
// server always enforces free limits even before a paid plan is written. Shared
// by index.js (caps + moderation gate) and extract.js (paid-only gate).
// EXPIRY IS A SERVER FACT (ledger 1.2, fixed 2026-09-13). user_plans had no expiry and nothing compared
// dates, so a paid plan never expired on our side. Now a PAID row counts only while expires_at is present,
// parseable and in the future. An absent or unparseable expiry on a paid row is an UNKNOWN, and unknown
// resolves to 'free' — fail closed. `nowMs` is injectable so the rule is testable without a clock.
export async function planFor(env, userId, nowMs = Date.now()) {
  if (!userId) return 'free';
  const row = await env.DB.prepare('SELECT plan, expires_at FROM user_plans WHERE user_id = ?').bind(userId).first();
  const plan = resolvePlan(row?.plan);
  if (plan === 'free') return 'free';
  const expires = Date.parse(row?.expires_at ?? '');
  if (!Number.isFinite(expires) || expires <= nowMs) return 'free';
  return plan;
}
