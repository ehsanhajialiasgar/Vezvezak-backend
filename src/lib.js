/**
 * Shared primitives: crypto, JWT, responses, rate limiting.
 * Runs on the Cloudflare Workers runtime (WebCrypto only — no Node APIs).
 */

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
export const fail = (status, error) => json(status, { ok: false, error });

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

// ── rate limiting (fixed window, D1-backed) ─────────────────────────────────
export async function rateLimit(env, bucket, limit, windowMs) {
  const now = Date.now();
  const row = await env.DB.prepare('SELECT count, window_at FROM rate_limits WHERE bucket = ?')
    .bind(bucket).first();
  if (!row || now - row.window_at > windowMs) {
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
