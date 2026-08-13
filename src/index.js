/**
 * Vezvezak API — the real backend.
 *
 * Deliberately a SEPARATE Worker from `vezvezakproxy` (which holds the SerpApi /
 * Google keys and serves search). Search therefore carries zero risk from any
 * deploy here.
 *
 * Doctrine bindings enforced in code, not just prose:
 *   Art.4  no money moves through here — there is no payment endpoint, by design.
 *   Art.7  passwords are hashed (PBKDF2), IPs are hashed, and no income/expense
 *          or individual economic profile is ever accepted or stored.
 *   Art.3  merchants are introductions: `status` starts 'pending' and nothing
 *          here asserts a guarantee about any seller.
 *
 * Routes:
 *   POST /auth/signup          {name, identifier, password}      -> {ok, token, user}
 *   POST /auth/login           {identifier, password}            -> {ok, token, user}
 *   POST /auth/otp/request     {identifier, purpose}             -> {ok}
 *   POST /auth/otp/verify      {identifier, code, purpose}       -> {ok, token?, user?, resetToken?}
 *   POST /auth/password/reset  {identifier, resetToken, password}-> {ok, token}
 *   GET  /auth/me              (Bearer)                          -> {user}
 *   POST /reviews/submit       {subject, stars, text}            -> {ok, id}
 *   GET  /reviews?subject=...                                    -> {reviews, count, average}
 *   POST /reviews/app          {stars, text}                     -> {approved, verifiedByServer}
 *   GET  /reviews/app/approved                                   -> {reviews}
 *   POST /merchants/submit     {storeName, address, ...}         -> {ok, id, status}
 *   GET  /health                                                 -> {ok, ...}
 */

import {
  CORS, json, ok, fail, uid, nowIso, sha256, hashPassword, verifyPassword,
  signJwt, requireAuth, normalizeIdentifier, channelOf, rateLimit, ipHash, readJson, planFor,
} from './lib.js';
import { extractPublicPage } from './extract.js';
import { normalizeConversion, verifyPostbackSecret } from './affiliate.js';
import { normalizeItem, normalizeVariant, screenCatalogText } from './catalog.js';
import { merchantMatches } from './verified.js';
import {
  WEEKLY_CAPS, METERED_KINDS, PHOTO_PER_SEARCH, resolvePlan, planCaps, billableAiAllowed,
  refillSlot, windowStartFor, nextResetMs, shouldRefill, capReached,
} from './usage.js';

const OTP_TTL_MS = 10 * 60 * 1000;      // 10 minutes
const OTP_MAX_ATTEMPTS = 5;
const RESET_TTL_MS = 15 * 60 * 1000;

const publicUser = u => ({ id: u.id, name: u.name || undefined, identifier: u.identifier });

// ── auth ────────────────────────────────────────────────────────────────────

async function signup(request, env) {
  const body = await readJson(request);
  if (!body) return fail(400, 'Invalid request.');

  const identifier = normalizeIdentifier(body.identifier);
  if (!identifier) return fail(400, 'Enter a valid email address or phone number.');
  const password = String(body.password || '');
  if (password.length < 6) return fail(400, 'Password must be at least 6 characters.');

  const rl = await rateLimit(env, `signup:${await ipHash(request, env)}`, 10, 60 * 60 * 1000);
  if (!rl.allowed) return fail(429, 'Too many attempts. Please try again later.');

  const existing = await env.DB.prepare('SELECT id FROM users WHERE identifier = ?').bind(identifier).first();
  if (existing) return fail(409, 'An account with this email or phone already exists.');

  const { hash, salt, iter } = await hashPassword(password);
  const user = {
    id: uid('usr'),
    identifier,
    channel: channelOf(identifier),
    name: (body.name || '').trim() || null,
    created_at: nowIso(),
  };
  await env.DB.prepare(
    'INSERT INTO users (id, identifier, channel, name, pw_hash, pw_salt, pw_iter, verified, created_at) ' +
    'VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)',
  ).bind(user.id, user.identifier, user.channel, user.name, hash, salt, iter, user.created_at).run();

  // We issue the session immediately. OTP verification is offered separately
  // (/auth/otp/request) rather than blocking signup, because blocking on an
  // undeliverable code would lock every user out until email is configured.
  const token = await signJwt({ sub: user.id, identifier }, env.JWT_SECRET);
  return ok({ token, user: publicUser(user), needsOtp: false });
}

async function login(request, env) {
  const body = await readJson(request);
  if (!body) return fail(400, 'Invalid request.');
  const identifier = normalizeIdentifier(body.identifier);
  if (!identifier) return fail(400, 'Enter a valid email address or phone number.');

  // Throttle per identifier AND per IP — credential stuffing hits both.
  for (const bucket of [`login:${identifier}`, `loginip:${await ipHash(request, env)}`]) {
    const rl = await rateLimit(env, bucket, 10, 15 * 60 * 1000);
    if (!rl.allowed) return fail(429, 'Too many sign-in attempts. Please wait a few minutes.');
  }

  const user = await env.DB.prepare('SELECT * FROM users WHERE identifier = ?').bind(identifier).first();
  // Same message whether the account is missing or the password is wrong, so we
  // don't confirm which emails/phones are registered.
  const GENERIC = 'Incorrect email/phone or password.';
  if (!user) return fail(401, GENERIC);
  if (!(await verifyPassword(String(body.password || ''), user))) return fail(401, GENERIC);

  await env.DB.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').bind(nowIso(), user.id).run();
  const token = await signJwt({ sub: user.id, identifier }, env.JWT_SECRET);
  return ok({ token, user: publicUser(user) });
}

async function otpRequest(request, env) {
  const body = await readJson(request);
  if (!body) return fail(400, 'Invalid request.');
  const identifier = normalizeIdentifier(body.identifier);
  const purpose = String(body.purpose || '');
  if (!identifier) return fail(400, 'Enter a valid email address or phone number.');
  if (!['signup', 'signin', 'reset'].includes(purpose)) return fail(400, 'Invalid purpose.');

  const rl = await rateLimit(env, `otp:${identifier}`, 5, 60 * 60 * 1000);
  if (!rl.allowed) return fail(429, 'Too many codes requested. Please wait an hour.');

  const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
  await env.DB.prepare(
    'INSERT INTO otp_codes (id, identifier, purpose, code_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)',
  ).bind(uid('otp'), identifier, purpose, await sha256(code), Date.now() + OTP_TTL_MS, Date.now()).run();

  const sent = await sendCode(env, identifier, code, purpose);
  if (!sent.ok) {
    // Honest failure — never claim we sent something we didn't (Doctrine Art.8).
    return fail(503, sent.error);
  }
  return ok();
}

// Email delivery via Resend. SMS is intentionally not implemented: it needs a
// paid gateway and per-country regulatory handling (Doctrine Art.1).
async function sendCode(env, identifier, code, purpose) {
  if (channelOf(identifier) !== 'email') {
    return { ok: false, error: 'SMS codes are not available yet. Please use an email address.' };
  }
  if (!env.RESEND_API_KEY) {
    return { ok: false, error: 'Verification email is not configured yet. Please try again later.' };
  }
  const subject = purpose === 'reset' ? 'Your Vezvezak password reset code' : 'Your Vezvezak verification code';
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: env.MAIL_FROM || 'Vezvezak <noreply@vezvezak.com>',
        to: [identifier],
        subject,
        text: `Your Vezvezak code is ${code}\n\nIt expires in 10 minutes. If you didn't request it, ignore this email.`,
      }),
    });
    if (!res.ok) return { ok: false, error: 'Could not send the code. Please try again later.' };
    return { ok: true };
  } catch {
    return { ok: false, error: 'Could not send the code. Please try again later.' };
  }
}

async function otpVerify(request, env) {
  const body = await readJson(request);
  if (!body) return fail(400, 'Invalid request.');
  const identifier = normalizeIdentifier(body.identifier);
  const purpose = String(body.purpose || '');
  const code = String(body.code || '').trim();
  if (!identifier || !code) return fail(400, 'Enter the code we sent you.');

  const row = await env.DB.prepare(
    'SELECT * FROM otp_codes WHERE identifier = ? AND purpose = ? AND consumed_at IS NULL ' +
    'ORDER BY created_at DESC LIMIT 1',
  ).bind(identifier, purpose).first();

  if (!row) return fail(400, 'That code is not valid. Please request a new one.');
  if (row.expires_at < Date.now()) return fail(400, 'That code has expired. Please request a new one.');
  if (row.attempts >= OTP_MAX_ATTEMPTS) return fail(429, 'Too many wrong attempts. Please request a new code.');

  if (row.code_hash !== (await sha256(code))) {
    await env.DB.prepare('UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?').bind(row.id).run();
    return fail(400, 'That code is not correct.');
  }
  await env.DB.prepare('UPDATE otp_codes SET consumed_at = ? WHERE id = ?').bind(Date.now(), row.id).run();

  if (purpose === 'reset') {
    const resetToken = uid('rst');
    await env.DB.prepare('INSERT INTO reset_tokens (token, identifier, expires_at) VALUES (?, ?, ?)')
      .bind(resetToken, identifier, Date.now() + RESET_TTL_MS).run();
    return ok({ resetToken });
  }

  const user = await env.DB.prepare('SELECT * FROM users WHERE identifier = ?').bind(identifier).first();
  if (!user) return fail(404, 'No account found for this email or phone.');
  await env.DB.prepare('UPDATE users SET verified = 1 WHERE id = ?').bind(user.id).run();
  const token = await signJwt({ sub: user.id, identifier }, env.JWT_SECRET);
  return ok({ token, user: publicUser(user) });
}

async function passwordReset(request, env) {
  const body = await readJson(request);
  if (!body) return fail(400, 'Invalid request.');
  const identifier = normalizeIdentifier(body.identifier);
  const password = String(body.password || '');
  if (password.length < 6) return fail(400, 'Password must be at least 6 characters.');

  const row = await env.DB.prepare('SELECT * FROM reset_tokens WHERE token = ?')
    .bind(String(body.resetToken || '')).first();
  if (!row || row.used_at || row.identifier !== identifier || row.expires_at < Date.now()) {
    return fail(400, 'This reset link is no longer valid. Please start again.');
  }

  const user = await env.DB.prepare('SELECT * FROM users WHERE identifier = ?').bind(identifier).first();
  if (!user) return fail(404, 'No account found for this email or phone.');

  const { hash, salt, iter } = await hashPassword(password);
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET pw_hash = ?, pw_salt = ?, pw_iter = ? WHERE id = ?')
      .bind(hash, salt, iter, user.id),
    env.DB.prepare('UPDATE reset_tokens SET used_at = ? WHERE token = ?').bind(Date.now(), row.token),
  ]);
  const token = await signJwt({ sub: user.id, identifier }, env.JWT_SECRET);
  return ok({ token, user: publicUser(user) });
}

async function me(request, env) {
  const claims = await requireAuth(request, env);
  if (!claims) return fail(401, 'Not signed in.');
  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(claims.sub).first();
  if (!user) return fail(401, 'Not signed in.');
  return json(200, { user: publicUser(user) });
}

// ── account data rights: export + real erasure (Ehsan 2026-08-13) ────────────
// GDPR/CCPA + Apple's account-deletion requirement. The app tells the user their
// data is erased and cannot be undone, so this must be TRUE — not a cascade we
// can't rely on (D1 does not guarantee PRAGMA foreign_keys = ON per connection),
// but explicit statements per table, run as one atomic batch.
//
// FULL DELETION of everything the user created — reviews, app reviews and merchant
// listings included. Their free-text fields (a review body, a store address/notes)
// can carry personal detail that nulling a foreign key would leave behind, so "all
// your data is erased" must mean DELETED, not anonymised. (A future opt-in "keep my
// reviews anonymously" screen is the corpus-preserving path — a tracked follow-up.)
//
// NOT deletable here — named for the privacy policy, because none is attributable
// to the person: affiliate_clicks + conversions (a one-way device_hash, no user_id
// — commission settlement records), an INCOMING referred_hash (a device hash, not
// this account), and telemetry (PII-free by construction). We deliberately do NOT
// send a deviceId at deletion to reach them — creating a user↔device link at the
// moment of erasure is the wrong trade (Ehsan).
const DELETE_BY_USER_ID = ['reviews', 'app_reviews', 'merchants', 'catalog_items', 'jobs', 'ads', 'influencers', 'verifications', 'feedback', 'referral_codes', 'user_plans', 'weekly_search_usage', 'consumed_searches'];

export async function accountDelete(request, env) {
  const claims = await requireAuth(request, env);
  if (!claims?.sub) return fail(401, 'Sign in required.');
  const uid = claims.sub;
  // Success is reported ONLY when a real account is actually erased.
  const user = await env.DB.prepare('SELECT id, identifier FROM users WHERE id = ?').bind(uid).first();
  if (!user) return fail(404, 'Account not found.');
  const identifier = user.identifier;
  const codeRow = await env.DB.prepare('SELECT code FROM referral_codes WHERE user_id = ?').bind(uid).first();

  const P = (sql, ...b) => env.DB.prepare(sql).bind(...b);
  const stmts = [];
  // catalog_variants has no user_id — delete via the user's catalog_items FIRST
  // (the subquery must run before catalog_items itself is deleted).
  stmts.push(P('DELETE FROM catalog_variants WHERE item_id IN (SELECT id FROM catalog_items WHERE user_id = ?)', uid));
  for (const tbl of DELETE_BY_USER_ID) stmts.push(P(`DELETE FROM ${tbl} WHERE user_id = ?`, uid)); // tbl is a fixed const, never user input
  stmts.push(P('DELETE FROM otp_codes WHERE identifier = ?', identifier));
  stmts.push(P('DELETE FROM reset_tokens WHERE identifier = ?', identifier));
  if (codeRow?.code) stmts.push(P('DELETE FROM referrals WHERE referrer_code = ?', codeRow.code)); // the user's OUTBOUND invites only
  // Ephemeral abuse counters that embed the identifier / user id (they self-expire too).
  stmts.push(P('DELETE FROM rate_limits WHERE bucket LIKE ?', `%${identifier}%`));
  stmts.push(P('DELETE FROM rate_limits WHERE bucket LIKE ?', `%${uid}%`));
  // The account itself LAST.
  stmts.push(P('DELETE FROM users WHERE id = ?', uid));

  await env.DB.batch(stmts);   // one atomic transaction
  return ok({ deleted: true });
}

export async function accountExport(request, env) {
  const claims = await requireAuth(request, env);
  if (!claims?.sub) return fail(401, 'Sign in required.');
  const uid = claims.sub;
  // Never export password material (pw_hash / pw_salt / pw_iter).
  const account = await env.DB.prepare('SELECT id, identifier, channel, name, verified, created_at, last_login_at FROM users WHERE id = ?').bind(uid).first();
  if (!account) return fail(404, 'Account not found.');
  const q = async (sql) => (await env.DB.prepare(sql).bind(uid).all()).results || [];
  const data = {
    exportedAt: nowIso(),
    account,
    reviews: await q('SELECT id, subject, stars, text, lang, created_at FROM reviews WHERE user_id = ?'),
    appReviews: await q('SELECT id, stars, text, approved, created_at FROM app_reviews WHERE user_id = ?'),
    merchants: await q('SELECT id, store_name, category, biz_type, address, phone, website, status, submitted_at FROM merchants WHERE user_id = ?'),
    catalogItems: await q('SELECT id, merchant_id, title, brand, model, gtin, category, status, created_at FROM catalog_items WHERE user_id = ?'),
    jobs: await q('SELECT id, title, business, employment_type, address, phone, status, submitted_at FROM jobs WHERE user_id = ?'),
    ads: await q('SELECT id, title, body, category, cta_url, phone, moderation_status, submitted_at FROM ads WHERE user_id = ?'),
    influencers: await q('SELECT id, name, handle, offer, phone, website, status, submitted_at FROM influencers WHERE user_id = ?'),
    verifications: await q('SELECT id, kind, company_name, is_company, status, submitted_at FROM verifications WHERE user_id = ?'),
    feedback: await q('SELECT id, kind, text, status, created_at FROM feedback WHERE user_id = ?'),
    referralCode: await q('SELECT code, created_at FROM referral_codes WHERE user_id = ?'),
    plan: await q('SELECT plan, updated_at FROM user_plans WHERE user_id = ?'),
    usage: await q('SELECT local_used, online_used, window_start FROM weekly_search_usage WHERE user_id = ?'),
  };
  return ok({ export: data });
}

// ── reviews (L5 corpus) ─────────────────────────────────────────────────────

async function reviewSubmit(request, env) {
  const body = await readJson(request);
  if (!body) return fail(400, 'Invalid request.');
  const subject = String(body.subject || '').trim();
  const stars = Math.round(Number(body.stars));
  if (!subject) return fail(400, 'Missing subject.');
  if (!(stars >= 1 && stars <= 5)) return fail(400, 'Stars must be between 1 and 5.');

  const claims = await requireAuth(request, env);
  const rl = await rateLimit(env, `review:${claims?.sub || (await ipHash(request, env))}`, 30, 60 * 60 * 1000);
  if (!rl.allowed) return fail(429, 'Too many reviews submitted. Please slow down.');

  // SECURITY: id and created_at are SERVER-generated — never trust the client to
  // set them, or a caller could backdate/forward-date rows to control the
  // ORDER BY created_at DESC ordering, or collide ids.
  const id = uid('rev');
  await env.DB.prepare(
    'INSERT INTO reviews (id, user_id, subject, stars, text, lang, created_at, ip_hash) ' +
    'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  ).bind(
    id, claims?.sub || null, subject, stars,
    (body.text || '').trim() || null, body.lang || null,
    nowIso(), await ipHash(request, env),
  ).run();
  return ok({ id });
}

// Reviews shown back to buyers — this is what makes contributing feel worth it.
async function reviewsForSubject(request, env, url) {
  const subject = (url.searchParams.get('subject') || '').trim();
  if (!subject) return fail(400, 'Missing subject.');
  const { results } = await env.DB.prepare(
    'SELECT stars, text, created_at FROM reviews WHERE subject = ? ORDER BY created_at DESC LIMIT 50',
  ).bind(subject).all();
  const agg = await env.DB.prepare(
    'SELECT COUNT(*) AS c, AVG(stars) AS avg FROM reviews WHERE subject = ?',
  ).bind(subject).first();
  return json(200, {
    reviews: results || [],
    count: agg?.c || 0,
    average: agg?.avg ? Math.round(agg.avg * 10) / 10 : null,
  });
}

/**
 * App review + moderation gate for the one-time points reward.
 *
 * Doctrine Art.8: the reward is only paid for a genuine review, so the check
 * must be real. Without an AI key we apply a deterministic quality check and
 * report `verifiedByServer` honestly rather than rubber-stamping.
 */
async function appReview(request, env) {
  const body = await readJson(request);
  if (!body) return fail(400, 'Invalid request.');
  const stars = Math.round(Number(body.stars));
  const text = String(body.text || '').trim();
  if (!(stars >= 1 && stars <= 5)) return fail(400, 'Stars must be between 1 and 5.');

  const claims = await requireAuth(request, env);
  const rl = await rateLimit(env, `appreview:${claims?.sub || (await ipHash(request, env))}`, 5, 24 * 60 * 60 * 1000);
  if (!rl.allowed) return fail(429, 'Too many submissions today.');

  // Free (and anonymous) submissions never trigger a synchronous billable AI
  // call — the review is stored unmoderated (awaiting_moderation). Paid tiers get
  // live AI moderation. The gate lives inside moderateReview so env.AI is
  // structurally unreachable for a free plan.
  const plan = claims?.sub ? await planFor(env, claims.sub) : 'free';
  const verdict = await moderateReview(env, stars, text, plan);
  await env.DB.prepare(
    'INSERT INTO app_reviews (id, user_id, stars, text, approved, reject_note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).bind(uid('arv'), claims?.sub || null, stars, text, verdict.approved ? 1 : 0, verdict.note || null, nowIso()).run();

  return json(200, { ok: true, approved: verdict.approved, verifiedByServer: verdict.byModel });
}

export async function moderateReview(env, stars, text, plan) {
  // ZERO free-tier billable AI (Ehsan 2026-08-13): a free/anonymous submission is
  // stored unmoderated and never reaches env.AI. Fail-closed reward gate is
  // unchanged — unmoderated ⇒ not approved ⇒ no reward, no public wall.
  if (!billableAiAllowed(plan)) return { approved: false, byModel: false, note: 'awaiting_moderation' };

  const words = text.split(/\s+/).filter(Boolean);
  // Only 4-5★ qualify for the wall/reward (Ehsan's rule); anything else is
  // stored but not approved — we still want the signal.
  if (stars < 4) return { approved: false, byModel: false, note: 'below_4_stars' };
  if (text.length < 20 || words.length < 4) return { approved: false, byModel: false, note: 'too_short' };

  if (!env.AI) return { approved: false, byModel: false, note: 'moderation_unavailable' };
  try {
    // Workers AI — asks for a strict yes/no on genuineness.
    const r = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
      messages: [
        { role: 'system', content: 'You judge whether an app review is genuine and specific (not spam, not gibberish, not abusive). Answer with exactly one word: YES or NO.' },
        { role: 'user', content: `Review (${stars} stars): ${text}` },
      ],
      max_tokens: 5,
    });
    const said = String(r?.response || '').trim().toUpperCase();
    return { approved: said.startsWith('YES'), byModel: true, note: said.startsWith('YES') ? null : 'model_rejected' };
  } catch {
    // Fail CLOSED: if moderation can't run, do NOT approve — a reward must never
    // be granted without a genuine check.
    return { approved: false, byModel: false, note: 'model_error' };
  }
}

async function approvedAppReviews(request, env) {
  const { results } = await env.DB.prepare(
    'SELECT stars, text, created_at FROM app_reviews WHERE approved = 1 ORDER BY created_at DESC LIMIT 50',
  ).all();
  return json(200, { reviews: results || [] });
}

// ── merchants ───────────────────────────────────────────────────────────────

async function merchantSubmit(request, env) {
  const body = await readJson(request);
  if (!body) return fail(400, 'Invalid request.');
  const storeName = String(body.storeName || '').trim();
  const address = String(body.address || '').trim();
  if (!storeName || !address) return fail(400, 'Store name and address are required.');

  const claims = await requireAuth(request, env);
  const rl = await rateLimit(env, `merchant:${claims?.sub || (await ipHash(request, env))}`, 10, 24 * 60 * 60 * 1000);
  if (!rl.allowed) return fail(429, 'Too many submissions today.');

  const id = uid('mch');
  await env.DB.prepare(
    'INSERT INTO merchants (id, user_id, store_name, category, biz_type, address, latitude, longitude, ' +
    'phone, website, notes, services, wholesale, status, submitted_at) ' +
    'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ).bind(
    id, claims?.sub || null, storeName,
    (body.category || '').trim() || null, body.bizType || null, address,
    Number.isFinite(body.latitude) ? body.latitude : null,
    Number.isFinite(body.longitude) ? body.longitude : null,
    (body.phone || '').trim() || null, (body.website || '').trim() || null,
    (body.notes || '').trim() || null, (body.services || '').trim() || null,
    body.wholesale ? 1 : 0, 'pending', body.submittedAt || nowIso(),
  ).run();
  // 'pending' — listing is an introduction awaiting review, never a guarantee.
  return ok({ id, status: 'pending' });
}

// ── referrals ───────────────────────────────────────────────────────────────
// A short, human-shareable code, stable per user. Generated on first request.
function makeCode() {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no confusable 0/O/1/I
  let c = '';
  const r = crypto.getRandomValues(new Uint8Array(6));
  for (const b of r) c += A[b % A.length];
  return c;
}

async function referralCode(request, env) {
  const claims = await requireAuth(request, env);
  if (!claims) return fail(401, 'Sign in to get your referral code.');
  const existing = await env.DB.prepare('SELECT code FROM referral_codes WHERE user_id = ?').bind(claims.sub).first();
  if (existing) return ok({ code: existing.code });
  // Retry a few times in the unlikely event of a code collision.
  for (let i = 0; i < 5; i++) {
    const code = makeCode();
    try {
      await env.DB.prepare('INSERT INTO referral_codes (code, user_id, created_at) VALUES (?, ?, ?)')
        .bind(code, claims.sub, nowIso()).run();
      return ok({ code });
    } catch { /* collision — try again */ }
  }
  return fail(500, 'Could not create a referral code. Please try again.');
}

// A new device claims a referral. Credited ONCE per device (referred_hash is
// UNIQUE) and never for self-referral. Returns whether the referrer should be
// awarded — the client awards the points locally on the referrer's next open,
// keeping this money-free (Doctrine Art.4).
async function referralClaim(request, env) {
  const body = await readJson(request);
  if (!body) return fail(400, 'Invalid request.');
  const code = String(body.code || '').trim().toUpperCase();
  const deviceId = String(body.deviceId || '').trim();
  if (!code || !deviceId) return fail(400, 'Missing code or device id.');

  const rl = await rateLimit(env, `refclaim:${await ipHash(request, env)}`, 20, 24 * 60 * 60 * 1000);
  if (!rl.allowed) return fail(429, 'Too many attempts.');

  const owner = await env.DB.prepare('SELECT user_id FROM referral_codes WHERE code = ?').bind(code).first();
  if (!owner) return fail(404, 'That referral code is not valid.');

  // Self-referral guard: a signed-in claimer cannot be the code owner.
  const claims = await requireAuth(request, env);
  if (claims && claims.sub === owner.user_id) return json(200, { ok: true, credited: false, reason: 'self' });

  const referredHash = await sha256(deviceId + code);
  try {
    await env.DB.prepare('INSERT INTO referrals (id, referrer_code, referred_hash, created_at) VALUES (?, ?, ?, ?)')
      .bind(uid('ref'), code, referredHash, nowIso()).run();
    return json(200, { ok: true, credited: true });
  } catch {
    // UNIQUE violation = this device already claimed a referral. Never double-credit.
    return json(200, { ok: true, credited: false, reason: 'already' });
  }
}

// ── jobs / ads / verification / influencers / coupons / luxury ───────────────

// Haversine distance in miles (for "nearby" queries without PostGIS).
function milesBetween(lat1, lon1, lat2, lon2) {
  const R = 3958.8, toR = Math.PI / 180;
  const dLat = (lat2 - lat1) * toR, dLon = (lon2 - lon1) * toR;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * toR) * Math.cos(lat2 * toR) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.asin(Math.sqrt(a));
}

async function submitLimited(request, env, bucket, perDay = 10) {
  const claims = await requireAuth(request, env);
  const rl = await rateLimit(env, `${bucket}:${claims?.sub || (await ipHash(request, env))}`, perDay, 24 * 60 * 60 * 1000);
  return { claims, allowed: rl.allowed };
}

async function jobSubmit(request, env) {
  const b = await readJson(request); if (!b) return fail(400, 'Invalid request.');
  if (!String(b.title || '').trim() || !String(b.business || '').trim()) return fail(400, 'Title and business are required.');
  const { claims, allowed } = await submitLimited(request, env, 'job');
  if (!allowed) return fail(429, 'Too many submissions today.');
  const id = uid('job');
  await env.DB.prepare('INSERT INTO jobs (id,user_id,title,business,employment_type,description,address,phone,latitude,longitude,status,submitted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
    .bind(id, claims?.sub || null, b.title.trim(), b.business.trim(), b.employmentType || null,
      (b.description || '').trim() || null, (b.address || '').trim() || null, (b.phone || '').trim() || null,
      Number.isFinite(b.latitude) ? b.latitude : null, Number.isFinite(b.longitude) ? b.longitude : null,
      'live', b.submittedAt || nowIso()).run();
  return ok({ id });
}

async function jobsNearby(request, env) {
  // Coordinates come in the POST BODY, never the URL query (Ehsan 2026-08-11) — a
  // URL is captured by any request log; a body is not. Coordinates are already
  // coarse (~110m) on the device.
  const body = await readJson(request) || {};
  const lat = parseFloat(body.lat); const lng = parseFloat(body.lng);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return json(200, { jobs: [] });
  // Bounding box (~40mi) then exact distance — cheap and index-friendly.
  const d = 0.6;
  const { results } = await env.DB.prepare(
    "SELECT id,title,business,employment_type,description,address,phone,latitude,longitude FROM jobs " +
    'WHERE status = ? AND latitude BETWEEN ? AND ? AND longitude BETWEEN ? AND ? LIMIT 200',
  ).bind('live', lat - d, lat + d, lng - d, lng + d).all();
  const jobs = (results || []).map(r => ({
    id: r.id, title: r.title, business: r.business, employmentType: r.employment_type,
    description: r.description || undefined, address: r.address || undefined, phone: r.phone || undefined,
    distance: (r.latitude != null && r.longitude != null) ? Math.round(milesBetween(lat, lng, r.latitude, r.longitude) * 10) / 10 : undefined,
  })).filter(j => j.distance == null || j.distance <= 40).sort((a, b) => (a.distance ?? 999) - (b.distance ?? 999));
  return json(200, { jobs });
}

async function adSubmit(request, env) {
  const b = await readJson(request); if (!b) return fail(400, 'Invalid request.');
  if (!String(b.title || '').trim() || !String(b.body || '').trim()) return fail(400, 'Title and body are required.');
  if (b.isAdult) return fail(400, 'Adult content is not allowed.');   // policy
  const { claims, allowed } = await submitLimited(request, env, 'ad');
  if (!allowed) return fail(429, 'Too many submissions today.');
  const plan = claims?.sub ? await planFor(env, claims.sub) : 'free';
  const verdict = await moderateReview(env, 5, `${b.title}\n${b.body}`, plan);   // reuse the genuineness gate (free → awaiting_moderation, no AI)
  const status = verdict.approved ? 'approved' : 'pending';
  const id = uid('ad');
  await env.DB.prepare('INSERT INTO ads (id,user_id,title,body,category,cta_url,phone,scope,is_adult,seller_type,country_code,latitude,longitude,luxury,moderation_status,submitted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .bind(id, claims?.sub || null, b.title.trim(), b.body.trim(), b.category || null, (b.ctaUrl || '').trim() || null,
      (b.phone || '').trim() || null, b.scope || 'local', 0, b.sellerType || null, b.countryCode || null,
      Number.isFinite(b.latitude) ? b.latitude : null, Number.isFinite(b.longitude) ? b.longitude : null,
      b.luxury ? 1 : 0, status, b.submittedAt || nowIso()).run();
  return ok({ id, moderationStatus: status });
}

async function verificationStart(request, env) {
  const b = await readJson(request); if (!b) return fail(400, 'Invalid request.');
  const claims = await requireAuth(request, env);
  if (!claims) return fail(401, 'Sign in to start verification.');
  const kind = ['merchant', 'influencer', 'advertiser'].includes(b.kind) ? b.kind : 'merchant';
  await env.DB.prepare('INSERT INTO verifications (id,user_id,kind,company_name,is_company,passport_consent,status,submitted_at) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(user_id,kind) DO UPDATE SET status = ?, submitted_at = ?')
    .bind(uid('ver'), claims.sub, kind, (b.companyName || '').trim() || null, b.isCompany ? 1 : 0, b.passportConsent ? 1 : 0, 'pending', b.submittedAt || nowIso(), 'pending', b.submittedAt || nowIso()).run();
  return ok({ status: 'pending' });   // manual doc review flips it to verified/rejected
}

async function verificationStatus(request, env, url) {
  const claims = await requireAuth(request, env);
  if (!claims) return json(200, { status: 'unsubmitted' });
  const kind = url.searchParams.get('kind') || 'merchant';
  const row = await env.DB.prepare('SELECT status FROM verifications WHERE user_id = ? AND kind = ?').bind(claims.sub, kind).first();
  return json(200, { status: row?.status || 'unsubmitted' });
}

async function influencerSubmit(request, env) {
  const b = await readJson(request); if (!b) return fail(400, 'Invalid request.');
  if (!String(b.name || '').trim() || !String(b.handle || '').trim()) return fail(400, 'Name and handle are required.');
  const { claims, allowed } = await submitLimited(request, env, 'inf');
  if (!allowed) return fail(429, 'Too many submissions today.');
  const id = uid('inf');
  await env.DB.prepare('INSERT INTO influencers (id,user_id,name,handle,offer,phone,website,latitude,longitude,status,submitted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    .bind(id, claims?.sub || null, b.name.trim(), b.handle.trim(), (b.offer || '').trim() || null,
      (b.phone || '').trim() || null, (b.website || '').trim() || null,
      Number.isFinite(b.latitude) ? b.latitude : null, Number.isFinite(b.longitude) ? b.longitude : null,
      'pending', b.submittedAt || nowIso()).run();
  return ok({ id, status: 'pending' });
}

// Operator-curated retailer price-match policies. Honest empty until seeded —
// we never fabricate a retailer's policy (Art.8/9). Each carries the source url.
async function priceMatchPolicies(request, env, url) {
  const country = (url.searchParams.get('country') || '').toUpperCase();
  const { results } = await env.DB.prepare(
    'SELECT * FROM price_match_policies WHERE (country IS NULL OR country = ?) LIMIT 300',
  ).bind(country).all();
  return json(200, { policies: (results || []).map(r => ({
    retailer: r.retailer, label: r.label, matches: !!r.matches,
    note: r.note || undefined, url: r.url || undefined,
    country: r.country || undefined, asOf: r.as_of || undefined,
  })) });
}

// User feedback / feature suggestions. Stored for operator review; if a
// suggestion is useful and not already built, the operator rewards the user.
async function feedbackSubmit(request, env) {
  const b = await readJson(request);
  const text = String(b?.text || '').trim();
  if (!text) return fail(400, 'Say a little about your idea.');
  if (text.length > 4000) return fail(400, 'Too long.');
  const claims = await requireAuth(request, env);
  const rl = await rateLimit(env, `feedback:${claims?.sub || (await ipHash(request, env))}`, 20, 24 * 60 * 60 * 1000);
  if (!rl.allowed) return fail(429, 'Too many submissions today.');
  const kind = ['suggestion', 'bug', 'praise', 'other'].includes(b?.kind) ? b.kind : 'suggestion';
  await env.DB.prepare(
    'INSERT INTO feedback (id, user_id, kind, text, status, created_at) VALUES (?, ?, ?, ?, ?, ?)',
  ).bind(uid('fb'), claims?.sub || null, kind, text, 'new', nowIso()).run();
  return ok({ received: true });
}

async function couponsList(request, env, url) {
  const country = (url.searchParams.get('country') || '').toUpperCase();
  const now = nowIso();
  const { results } = await env.DB.prepare(
    'SELECT * FROM coupons WHERE (country IS NULL OR country = ?) AND (expires_at IS NULL OR expires_at > ?) LIMIT 100',
  ).bind(country, now).all();
  return json(200, { coupons: (results || []).map(r => ({
    id: r.id, store: r.store, code: r.code || undefined, title: r.title,
    discountLabel: r.discount_label || '', country: r.country || undefined,
    category: r.category || undefined, url: r.url || undefined, expiresAt: r.expires_at || undefined,
  })) });
}

async function luxuryList(request, env, url) {
  const country = (url.searchParams.get('country') || '').toUpperCase();
  const now = nowIso();
  const { results } = await env.DB.prepare(
    'SELECT * FROM luxury_offers WHERE (country IS NULL OR country = ?) AND (expires_at IS NULL OR expires_at > ?) LIMIT 100',
  ).bind(country, now).all();
  return json(200, { offers: (results || []).map(r => ({
    id: r.id, brand: r.brand, title: r.title, kind: r.kind || 'deal',
    discountLabel: r.discount_label || undefined, code: r.code || undefined, imageUrl: r.image_url || undefined,
    url: r.url || undefined, country: r.country || undefined, category: r.category || undefined, expiresAt: r.expires_at || undefined,
  })) });
}

// Human-verify: accept the token so abuse-prone submits can require it later.
async function humanVerify(request, env) {
  const b = await readJson(request); if (!b || !b.token) return fail(400, 'Missing token.');
  // A local nonce is accepted for now; when hCaptcha is wired, verify server-side
  // against hCaptcha's siteverify here before returning ok.
  return ok({ verified: true });
}

// ── commission attribution ───────────────────────────────────────────────────

// Register a tap-through so a later conversion postback can be matched to it.
// Anonymous by design: `deviceId` (if sent) is one-way hashed, never stored raw.
async function affiliateClick(request, env) {
  const b = await readJson(request);
  if (!b || !b.clickId) return fail(400, 'Missing clickId.');
  const rl = await rateLimit(env, `affclick:${await ipHash(request, env)}`, 120, 60 * 60 * 1000);
  if (!rl.allowed) return fail(429, 'Too many clicks.');

  const clickId = String(b.clickId).slice(0, 120);
  const seller = String(b.seller || '').slice(0, 120);
  const host = String(b.host || '').slice(0, 120);
  const deviceHash = b.deviceId ? await sha256(String(b.deviceId)) : null;
  // INSERT OR IGNORE: re-registering the same clickId is a harmless no-op.
  await env.DB.prepare(
    'INSERT OR IGNORE INTO affiliate_clicks (click_id, seller, host, device_hash, created_at) VALUES (?, ?, ?, ?, ?)',
  ).bind(clickId, seller, host, deviceHash, nowIso()).run();
  return ok({ registered: true });
}

// Server-to-server conversion postback from an affiliate network. Authenticated
// by shared secret (FAILS CLOSED), idempotent per (network, orderId). We only
// RECORD the sale/commission — money is settled by the network, never by us.
async function affiliatePostback(request, env, url) {
  const provided = url.searchParams.get('token') || request.headers.get('x-vez-postback') || '';
  if (!verifyPostbackSecret(provided, env.AFFILIATE_POSTBACK_SECRET)) {
    // 503 when unconfigured vs 401 when the token is wrong — but both reject.
    return fail(env.AFFILIATE_POSTBACK_SECRET ? 401 : 503, 'Postback not authorized.');
  }
  const rl = await rateLimit(env, `affpost:${await ipHash(request, env)}`, 600, 60 * 60 * 1000);
  if (!rl.allowed) return fail(429, 'Too many postbacks.');

  // Networks post as JSON body and/or query string — merge both.
  const body = request.method === 'POST' ? (await readJson(request)) || {} : {};
  const q = Object.fromEntries(url.searchParams.entries());
  const norm = normalizeConversion({ ...q, ...body });
  if (!norm.ok) return fail(400, norm.error);
  const c = norm.value;

  // Enrich seller/host from the original click when we have it.
  let seller = '', host = '';
  if (c.clickId) {
    const click = await env.DB.prepare('SELECT seller, host FROM affiliate_clicks WHERE click_id = ?').bind(c.clickId).first();
    if (click) { seller = click.seller || ''; host = click.host || ''; }
  }

  try {
    await env.DB.prepare(
      `INSERT INTO conversions (id, click_id, network, order_id, amount, currency, commission, status, seller, host, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(uid('conv'), c.clickId, c.network, c.orderId, c.amount, c.currency, c.commission, c.status, seller, host, nowIso()).run();
    // Confirmed sale → this is where a seller commission notification is queued
    // later (record-only; Art.4). Nothing to pay from here.
    return ok({ recorded: true, status: c.status });
  } catch {
    // UNIQUE(network, order_id) violation = the network already reported this
    // order. Idempotent: never double-count a commission.
    return ok({ recorded: false, duplicate: true });
  }
}

// Let a device reconcile which of its clicks have converted (for a future
// "confirmed purchases" view). Returns only clickIds — no amounts, no PII.
async function affiliateStatus(request, env) {
  // Device id in the POST BODY, never the URL query (Ehsan 2026-08-11) — it is
  // hashed here and never stored raw, but it must not sit in a loggable URL either.
  const body = await readJson(request) || {};
  const device = body.device || '';
  if (!device) return fail(400, 'Missing device.');
  const rl = await rateLimit(env, `affstatus:${await ipHash(request, env)}`, 120, 60 * 60 * 1000);
  if (!rl.allowed) return fail(429, 'Too many requests.');
  const deviceHash = await sha256(String(device));
  const { results } = await env.DB.prepare(
    `SELECT c.click_id AS clickId, c.status AS status
       FROM conversions c JOIN affiliate_clicks a ON a.click_id = c.click_id
      WHERE a.device_hash = ? AND c.status IN ('confirmed','rejected')
      ORDER BY c.created_at DESC LIMIT 200`,
  ).bind(deviceHash).all();
  return ok({ conversions: results || [] });
}

// ── seller catalog ───────────────────────────────────────────────────────────

// Moderate a catalog item → 'live' | 'rejected' | 'pending'. Deterministic
// prohibited-content screen first (instant reject); then AI approves clean items
// to live. FAILS CLOSED: no AI / AI error / model "NO" never auto-publishes —
// the item stays 'pending' (or rejected), never silently live (Art.8).
export async function moderateCatalogItem(env, it, plan) {
  const text = `${it.title}\n${it.description || ''}\n${it.brand || ''} ${it.model || ''}`.trim();
  if (screenCatalogText(text).prohibited) return 'rejected';
  // Free (and anonymous) sellers never trigger a synchronous billable AI call —
  // the item is stored 'pending' for batch review. Paid tiers get live AI
  // moderation. Deterministic prohibited-screen above still runs for everyone.
  if (!billableAiAllowed(plan)) return 'pending';
  if (!env.AI) return 'pending';
  try {
    const r = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
      messages: [
        { role: 'system', content: 'You moderate a product listing for a shopping app. Reject ONLY if it is clearly prohibited: weapons, illegal drugs, adult/explicit, counterfeit, stolen goods, or hateful content. Otherwise approve. Answer with exactly one word: YES to approve, NO to reject.' },
        { role: 'user', content: `Product listing: ${text}` },
      ],
      max_tokens: 5,
    });
    const said = String(r?.response || '').trim().toUpperCase();
    return said.startsWith('YES') ? 'live' : 'rejected';
  } catch {
    return 'pending'; // fail closed — needs manual review, never auto-live
  }
}

// Confirm the signed-in user owns this merchant before letting them touch its
// catalog. Anonymous merchants (no user_id) can't own a catalog.
async function ownedMerchant(env, merchantId, claims) {
  if (!merchantId || !claims?.sub) return null;
  const m = await env.DB.prepare('SELECT id, user_id FROM merchants WHERE id = ?').bind(merchantId).first();
  return m && m.user_id && m.user_id === claims.sub ? m : null;
}

async function insertVariants(env, itemId, merchantId, variants) {
  let n = 0;
  for (const v of Array.isArray(variants) ? variants.slice(0, 200) : []) {
    const nv = normalizeVariant(v).value;
    // INSERT OR IGNORE so re-uploading the same SKU doesn't duplicate a variant.
    await env.DB.prepare(
      `INSERT OR IGNORE INTO catalog_variants
        (id, item_id, merchant_id, sku, attributes, price, currency, was_price, unit, in_stock, quantity, tier_min_qty, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(uid('var'), itemId, merchantId, nv.sku, nv.attributes, nv.price, nv.currency, nv.wasPrice, nv.unit, nv.inStock, nv.quantity, nv.tierMinQty, nowIso()).run();
    n++;
  }
  return n;
}

// Create one catalog item (+ its variants). Item starts 'pending' — AI/operator
// review flips it 'live' (an introduction awaiting review, never a guarantee).
async function catalogItemCreate(request, env) {
  const body = await readJson(request);
  if (!body) return fail(400, 'Invalid request.');
  const claims = await requireAuth(request, env);
  if (!claims) return fail(401, 'Sign in to manage your catalog.');
  const merchant = await ownedMerchant(env, String(body.merchantId || ''), claims);
  if (!merchant) return fail(403, 'You do not own that store.');

  const norm = normalizeItem(body);
  if (!norm.ok) return fail(400, norm.error);
  const rl = await rateLimit(env, `catalog:${claims.sub}`, 300, 24 * 60 * 60 * 1000);
  if (!rl.allowed) return fail(429, 'Too many catalog updates today.');

  const it = norm.value;
  const id = uid('cit');
  const status = await moderateCatalogItem(env, it, await planFor(env, claims.sub));
  await env.DB.prepare(
    `INSERT INTO catalog_items
      (id, merchant_id, user_id, title, brand, model, gtin, category, condition, description, image_url, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(id, merchant.id, claims.sub, it.title, it.brand, it.model, it.gtin, it.category, it.condition, it.description, it.imageUrl, status, nowIso(), nowIso()).run();
  const variants = await insertVariants(env, id, merchant.id, body.variants);
  return ok({ id, status, variants });
}

// Bulk upload many items at once (spreadsheet / feed import). Same ownership +
// honesty rules; capped so one request can't be abusive.
async function catalogBulk(request, env) {
  const body = await readJson(request);
  if (!body || !Array.isArray(body.items)) return fail(400, 'items array required.');
  const claims = await requireAuth(request, env);
  if (!claims) return fail(401, 'Sign in to manage your catalog.');
  const merchant = await ownedMerchant(env, String(body.merchantId || ''), claims);
  if (!merchant) return fail(403, 'You do not own that store.');
  const rl = await rateLimit(env, `catalogbulk:${claims.sub}`, 20, 24 * 60 * 60 * 1000);
  if (!rl.allowed) return fail(429, 'Too many bulk uploads today.');

  let created = 0, skipped = 0, rejected = 0;
  for (const raw of body.items.slice(0, 500)) {
    const norm = normalizeItem(raw || {});
    if (!norm.ok) { skipped++; continue; }
    const it = norm.value;
    // Bulk uses only the deterministic screen (no per-item AI call for 500 rows):
    // prohibited → rejected, everything else → pending for batch review. Nothing
    // auto-goes-live in bulk.
    const text = `${it.title}\n${it.description || ''}\n${it.brand || ''}`;
    const status = screenCatalogText(text).prohibited ? 'rejected' : 'pending';
    if (status === 'rejected') rejected++;
    const id = uid('cit');
    await env.DB.prepare(
      `INSERT INTO catalog_items
        (id, merchant_id, user_id, title, brand, model, gtin, category, condition, description, image_url, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(id, merchant.id, claims.sub, it.title, it.brand, it.model, it.gtin, it.category, it.condition, it.description, it.imageUrl, status, nowIso(), nowIso()).run();
    await insertVariants(env, id, merchant.id, raw.variants);
    created++;
  }
  return ok({ created, skipped, rejected });
}

// "Verified on Vezvezak" check for a search result. Returns verified:true ONLY
// when a real, VERIFIED merchant matches by name AND is within ~150m of the
// result — never a faked badge (Art.8). Empty/no-match => verified:false.
async function merchantsVerified(request, env) {
  // Name + coordinates in the POST BODY, never the URL query (Ehsan 2026-08-11).
  const body = await readJson(request) || {};
  const name = body.name || '';
  const lat = parseFloat(body.lat);
  const lng = parseFloat(body.lng);
  if (!name || !Number.isFinite(lat) || !Number.isFinite(lng)) return ok({ verified: false });
  const d = 0.003; // ~300m bounding box; exact distance filtered in JS
  const { results } = await env.DB.prepare(
    `SELECT m.id, m.store_name, m.latitude, m.longitude
       FROM merchants m
       JOIN verifications v ON v.user_id = m.user_id AND v.kind = 'merchant' AND v.status = 'verified'
      WHERE m.latitude BETWEEN ? AND ? AND m.longitude BETWEEN ? AND ? LIMIT 50`,
  ).bind(lat - d, lat + d, lng - d, lng + d).all();
  const result = { name, lat, lng };
  const hit = (results || []).find(m => merchantMatches(result, m));
  return ok(hit ? { verified: true, merchantId: hit.id } : { verified: false });
}

// The signed-in user's own stores (so they can manage each store's catalog).
async function merchantsMine(request, env) {
  const claims = await requireAuth(request, env);
  if (!claims) return fail(401, 'Sign in to see your stores.');
  const { results } = await env.DB.prepare(
    `SELECT id, store_name AS storeName, category, biz_type AS bizType, status
       FROM merchants WHERE user_id = ? ORDER BY submitted_at DESC LIMIT 50`,
  ).bind(claims.sub).all();
  return ok({ merchants: results || [] });
}

// The catalog for a store. Buyers see only LIVE items; the store's OWNER (a
// valid token owning the merchant) additionally sees pending/rejected so they
// can manage them. Variants are nested under each item.
async function catalogList(request, env, url) {
  const merchantId = url.searchParams.get('merchant') || '';
  if (!merchantId) return fail(400, 'Missing merchant.');
  const claims = await requireAuth(request, env);
  const owner = claims ? await ownedMerchant(env, merchantId, claims) : null;
  const statusClause = owner ? '' : " AND status = 'live'";
  const { results: items } = await env.DB.prepare(
    `SELECT id, title, brand, model, gtin, category, condition, description, image_url AS imageUrl, status
       FROM catalog_items WHERE merchant_id = ?${statusClause} ORDER BY created_at DESC LIMIT 500`,
  ).bind(merchantId).all();
  const out = [];
  for (const it of items || []) {
    const { results: vars } = await env.DB.prepare(
      `SELECT sku, attributes, price, currency, was_price AS wasPrice, unit, in_stock AS inStock, quantity, tier_min_qty AS tierMinQty
         FROM catalog_variants WHERE item_id = ? LIMIT 200`,
    ).bind(it.id).all();
    out.push({ ...it, variants: vars || [] });
  }
  return ok({ items: out });
}


// ── Telemetry ingest ─────────────────────────────────────────────────────────
// Six event shapes, each with a fixed whitelist. NO PII can land: no query text,
// no user id, no location finer than country (the client never sends those, and
// this drops any key it does not recognise). Batches of envelopes → one row each.
const TELEMETRY_ALLOWED = {
  'search.performed': ['lang', 'script', 'resultCount', 'unknownCount'],
  'claim.shown': ['engine', 'certainty'],
  'claim.evidence': ['engine'],
  'offer.referred': ['sellerId', 'landedCost'],
  'watch.added': ['engine'],
  'purchase.referred': ['productFingerprint'],
};
async function telemetryIngest(request, env) {
  const body = (await readJson(request)) || {};
  const events = Array.isArray(body.events) ? body.events : [];
  if (!events.length) return ok({ accepted: 0 });
  // Cap a single batch so one request can't flood the table.
  const batch = events.slice(0, 200);
  const rows = [];
  for (const e of batch) {
    const allow = TELEMETRY_ALLOWED[e && e.name];
    if (!allow) continue;                 // unknown event name → drop
    const at = Number.isFinite(e.at) ? e.at : Date.now();
    const clean = {};
    for (const k of allow) if (e[k] !== undefined) clean[k] = e[k];   // whitelist
    rows.push({ name: e.name, at, data: clean });
  }
  if (!rows.length) return ok({ accepted: 0 });
  const stmt = env.DB.prepare(
    'INSERT INTO telemetry (name, at, lang, script, result_count, unknown_count, engine, certainty, seller_id, landed_cost, product_fingerprint) ' +
    'VALUES (?,?,?,?,?,?,?,?,?,?,?)'
  );
  const binds = rows.map(r => stmt.bind(
    r.name, r.at,
    r.data.lang ?? null, r.data.script ?? null,
    r.data.resultCount ?? null, r.data.unknownCount ?? null,
    r.data.engine ?? null, r.data.certainty ?? null,
    r.data.sellerId ?? null, r.data.landedCost ?? null,
    r.data.productFingerprint ?? null,
  ));
  await env.DB.batch(binds);
  return ok({ accepted: rows.length });
}

// ── router ──────────────────────────────────────────────────────────────────

// ── Server-authoritative WEEKLY SEARCH CAPS (anti-abuse; Ehsan 2026-08-13) ─────
// The client can be tampered with, so the cap is enforced HERE, at consume time,
// as a COUNT of live searches per week (local + online separately). There is NO
// monetary balance anywhere — no dollars stored or derived per user. Caps live in
// usage.js (WEEKLY_CAPS), mirroring the client's pricingStrategy.ts; the numbers
// refill (never expire) at each account's staggered weekly boundary.
//
// NOTE ON WHERE THE MONEY IS: the paid upstreams (Google Places, SerpApi) are
// spent by the SEPARATE `vezvezakproxy` Worker, which the app calls directly.
// Counting here is authoritative ONLY if the proxy refuses to spend without a
// successful consume. Option B (approved): the proxy forwards the caller's JWT to
// /search/consume and spends only on 200. See docs + the proxy worker.

// Load the account's weekly row, creating it (with a staggered refill slot) on
// first use and lazily REFILLING it when its weekly boundary has passed. Returns
// the current counts + the window. Never stores money.
async function weeklyRow(env, userId) {
  const now = Date.now();
  const row = await env.DB.prepare(
    'SELECT local_used, online_used, window_start, refill_dow, refill_minute FROM weekly_search_usage WHERE user_id = ?',
  ).bind(userId).first();

  if (!row) {
    const slot = refillSlot(userId);
    const ws = windowStartFor(now, slot.dow, slot.minute);
    await env.DB.prepare(
      'INSERT OR IGNORE INTO weekly_search_usage (user_id, local_used, online_used, window_start, refill_dow, refill_minute, updated_at) VALUES (?, 0, 0, ?, ?, ?, ?)',
    ).bind(userId, ws, slot.dow, slot.minute, nowIso()).run();
    return { local_used: 0, online_used: 0, window_start: ws, refill_dow: slot.dow, refill_minute: slot.minute };
  }

  if (shouldRefill(now, row.window_start, row.refill_dow, row.refill_minute)) {
    // REFILL — counts reset to 0 and the window advances to the boundary. Nothing
    // carried over, nothing forfeited; the same full cap is available again.
    const boundary = windowStartFor(now, row.refill_dow, row.refill_minute);
    await env.DB.prepare(
      'UPDATE weekly_search_usage SET local_used = 0, online_used = 0, window_start = ?, updated_at = ? WHERE user_id = ?',
    ).bind(boundary, nowIso(), userId).run();
    // Prune the previous window's per-search dedupe rows — they only matter within
    // the window they were consumed in.
    await env.DB.prepare('DELETE FROM consumed_searches WHERE user_id = ? AND window_start < ?').bind(userId, boundary).run();
    return { local_used: 0, online_used: 0, window_start: boundary, refill_dow: row.refill_dow, refill_minute: row.refill_minute };
  }
  return row;
}

function usedFor(row, kind) { return kind === 'local' ? row.local_used : row.online_used; }

// Atomic check-and-consume: refuse at/over cap WITHOUT incrementing, else bump the
// counter under a `< cap` guard (so a race can never push past the cap). A search
// bundle's sub-calls share ONE vz_sid (searchId) and DEDUPE into ONE slot, so the
// cap counts whole searches, not API calls. This is the ONLY endpoint that grants
// a live-search slot. kind 'photo' is a sub-call ceiling check (no slot).
export async function searchConsume(request, env) {
  const claims = await requireAuth(request, env);
  if (!claims?.sub) return fail(401, 'Sign in required.');
  const b = await readJson(request);
  const kind = String(b?.kind || '');
  const searchId = String(b?.searchId || '').slice(0, 80) || null;

  // A Photo is a sub-call of an already-consumed local search — bounded, not a slot.
  if (kind === 'photo') return photoConsume(env, claims.sub, searchId);

  // Only 'local' | 'online' are metered as slots. Accessibility (voice.*) is never
  // sent here and would be rejected as non-billable — never counted on any tier.
  if (!METERED_KINDS.has(kind)) return fail(400, 'kind must be "local", "online" or "photo".');

  const plan = await planFor(env, claims.sub);
  const cap = planCaps(plan)[kind];
  const row = await weeklyRow(env, claims.sub);
  const used = usedFor(row, kind);
  const resetAt = new Date(nextResetMs(row.window_start)).toISOString();
  const refuse = () => json(402, { allowed: false, reason: 'cap_reached', kind, plan, cap, used: Math.min(used, cap), remaining: 0, resetAt });

  // Fail CLOSED: clearly at/over cap → refuse, no increment, no dedupe row, no
  // fall-through to a billable call. Free local (cap 0) refuses every time.
  if (capReached(cap, used)) return refuse();

  // DEDUPE: the first sub-call of a bundle inserts its (user, vz_sid, kind) row and
  // takes the slot; later sub-calls of the SAME bundle find the row and are allowed
  // WITHOUT a second increment. Insert-first also closes the race between two
  // concurrent first-sub-calls of the same bundle (only one insert wins).
  if (searchId) {
    const ins = await env.DB.prepare(
      'INSERT OR IGNORE INTO consumed_searches (user_id, search_id, kind, window_start, photos_used, created_at) VALUES (?, ?, ?, ?, 0, ?)',
    ).bind(claims.sub, searchId, kind, row.window_start, nowIso()).run();
    if (!(ins?.meta?.changes)) {
      // Already consumed by this bundle this window → idempotent allow.
      return ok({ allowed: true, kind, plan, cap, used, remaining: Math.max(0, cap - used), resetAt, idempotent: true });
    }
  }

  const col = kind === 'local' ? 'local_used' : 'online_used';   // fixed identifiers, never user input
  const res = await env.DB.prepare(
    `UPDATE weekly_search_usage SET ${col} = ${col} + 1, updated_at = ? WHERE user_id = ? AND ${col} < ?`,
  ).bind(nowIso(), claims.sub, cap).run();
  if (!(res?.meta?.changes)) {
    // Lost the last slot to a concurrent bundle — undo the dedupe row we inserted so
    // a legitimate retry after refill isn't wrongly treated as already-consumed.
    if (searchId) await env.DB.prepare('DELETE FROM consumed_searches WHERE user_id = ? AND search_id = ? AND kind = ? AND window_start = ?').bind(claims.sub, searchId, kind, row.window_start).run();
    return refuse();
  }
  return ok({ allowed: true, kind, plan, cap, used: used + 1, remaining: cap - (used + 1), resetAt });
}

// Sub-call ceiling for Photos. A Photo consumes NO slot, but it must ride under a
// LOCAL search this account actually consumed (its vz_sid row exists) and only up
// to PHOTO_PER_SEARCH times — so a tampered client can't pull unlimited paid photos
// for one search, or photos with a made-up id that never cost a slot. Atomic: the
// bump only succeeds while a matching local row exists AND is under the ceiling.
export async function photoConsume(env, userId, searchId) {
  if (!searchId) return fail(400, 'A photo requires its search id.');
  const row = await weeklyRow(env, userId);
  const res = await env.DB.prepare(
    'UPDATE consumed_searches SET photos_used = photos_used + 1 WHERE user_id = ? AND search_id = ? AND kind = ? AND window_start = ? AND photos_used < ?',
  ).bind(userId, searchId, 'local', row.window_start, PHOTO_PER_SEARCH).run();
  if (res?.meta?.changes) return ok({ allowed: true, kind: 'photo', ceiling: PHOTO_PER_SEARCH });
  // No consumed local slot for this bundle, or the per-search photo ceiling is hit.
  return json(402, { allowed: false, reason: 'photo_ceiling_or_no_search', kind: 'photo', ceiling: PHOTO_PER_SEARCH });
}

// Read-only status for the client's plain weekly readout (used / cap / remaining
// / reset time, per kind). No money, no side effects (beyond the lazy refill).
async function usageStatus(request, env) {
  const claims = await requireAuth(request, env);
  if (!claims?.sub) return fail(401, 'Sign in required.');
  const plan = await planFor(env, claims.sub);
  const caps = planCaps(plan);
  const row = await weeklyRow(env, claims.sub);
  const resetAt = new Date(nextResetMs(row.window_start)).toISOString();
  return ok({
    plan,
    local:  { used: row.local_used,  cap: caps.local,  remaining: Math.max(0, caps.local  - row.local_used) },
    online: { used: row.online_used, cap: caps.online, remaining: Math.max(0, caps.online - row.online_used) },
    resetAt,
  });
}

// ── DEPRECATED backward-compat shims (removed in the Part 2 client migration) ──
// The un-migrated client still calls /usage/check and /usage/record with a single
// {kind:'search'|'compute'} and no local/online split. Keep them responding so the
// current build keeps working, but MONEY-FREE: they read the weekly model and
// never touch a dollar. They are advisory only (they cannot gate the proxy); the
// real slot grant is /search/consume. /usage/record no longer records anything —
// consume is the sole writer, so these can't double-count.
async function usageCheck(request, env) {
  const claims = await requireAuth(request, env);
  if (!claims?.sub) return fail(401, 'Sign in required.');
  const plan = await planFor(env, claims.sub);
  const caps = planCaps(plan);
  const row = await weeklyRow(env, claims.sub);
  const isFree = resolvePlan(plan) === 'free';
  const localLeft = caps.local - row.local_used;
  const onlineLeft = caps.online - row.online_used;
  return ok({ allowed: (localLeft > 0 || onlineLeft > 0), plan, isFree, deprecated: true, local: Math.max(0, localLeft), online: Math.max(0, onlineLeft) });
}
async function usageRecord(request, env) {
  const claims = await requireAuth(request, env);
  if (!claims?.sub) return fail(401, 'Sign in required.');
  return ok({ deprecated: true, note: 'recording moved to /search/consume' });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    const url = new URL(request.url);
    const p = url.pathname;
    const post = request.method === 'POST';
    const get = request.method === 'GET';

    try {
      if (!env.DB) return fail(500, 'Database is not configured.');
      if (!env.JWT_SECRET) return fail(500, 'Server is not configured.');

      if (get && p === '/health') return ok({ service: 'vezvezak-api', time: nowIso() });

      if (post && p === '/auth/signup') return signup(request, env);
      if (post && p === '/auth/login') return login(request, env);
      if (post && p === '/auth/otp/request') return otpRequest(request, env);
      if (post && p === '/auth/otp/verify') return otpVerify(request, env);
      if (post && p === '/auth/password/reset') return passwordReset(request, env);
      if (get && p === '/auth/me') return me(request, env);

      // Account data rights (GDPR/CCPA + Apple): real export + real erasure.
      if (post && p === '/account/export') return accountExport(request, env);
      if (post && p === '/account/delete') return accountDelete(request, env);

      // Product telemetry sink (Ehsan 2026-08-09). PII-free by construction: the
      // client whitelists keys, and telemetryIngest repeats the whitelist here
      // (defence in depth) — anything outside the fixed shape is dropped.
      if (post && p === '/t') return telemetryIngest(request, env);

      if (post && p === '/reviews/submit') return reviewSubmit(request, env);
      if (get && p === '/reviews') return reviewsForSubject(request, env, url);
      if (post && p === '/reviews/app') return appReview(request, env);
      if (get && p === '/reviews/app/approved') return approvedAppReviews(request, env);

      if (post && p === '/merchants/submit') return merchantSubmit(request, env);

      if (get && p === '/referral/code') return referralCode(request, env);
      if (post && p === '/referral/claim') return referralClaim(request, env);

      if (post && p === '/jobs/submit') return jobSubmit(request, env);
      if (post && p === '/jobs/nearby') return jobsNearby(request, env);
      if (post && p === '/ads/submit') return adSubmit(request, env);
      if (post && p === '/verification/start') return verificationStart(request, env);
      if (get && p === '/verification/status') return verificationStatus(request, env, url);
      if (post && p === '/influencers/submit') return influencerSubmit(request, env);
      if (get && p === '/deals/coupons') return couponsList(request, env, url);
      if (get && p === '/pricematch/policies') return priceMatchPolicies(request, env, url);
      if (post && p === '/feedback/submit') return feedbackSubmit(request, env);
      if (get && p === '/luxury/offers') return luxuryList(request, env, url);
      if (post && p === '/human/verify') return humanVerify(request, env);

      if (post && p === '/affiliate/click') return affiliateClick(request, env);
      if ((post || get) && p === '/affiliate/postback') return affiliatePostback(request, env, url);
      if (post && p === '/affiliate/status') return affiliateStatus(request, env);

      // Server-authoritative weekly search caps (anti-abuse; Ehsan 2026-08-13).
      // /search/consume is the ONLY endpoint that grants a live-search slot; the
      // proxy forwards the caller's JWT here and spends only on a 200 (Option B).
      if (post && p === '/search/consume') return searchConsume(request, env);
      if (post && p === '/usage/status') return usageStatus(request, env);
      // Deprecated advisory shims (removed in the Part 2 client migration).
      if (post && p === '/usage/check') return usageCheck(request, env);
      if (post && p === '/usage/record') return usageRecord(request, env);

      if (post && p === '/catalog/items') return catalogItemCreate(request, env);
      if (post && p === '/catalog/bulk') return catalogBulk(request, env);
      if (get && p === '/catalog') return catalogList(request, env, url);
      if (get && p === '/merchants/mine') return merchantsMine(request, env);
      if (post && p === '/merchants/verified') return merchantsVerified(request, env);

      // Reads ONE public page (robots.txt-obeying, self-identifying) and returns
      // published prices with confidence + provenance. See extract.js.
      if (post && p === '/extract') return extractPublicPage(request, env);

      return fail(404, 'Not found.');
    } catch (err) {
      // Never leak internals to the client; log for the operator.
      console.error('unhandled', p, err);
      return fail(500, 'Something went wrong. Please try again.');
    }
  },
};
