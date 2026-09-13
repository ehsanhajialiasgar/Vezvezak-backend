// COMP CODES, SERVER-SIDE — launch chain step 6 (Ehsan 2026-09-13).
//
// Until today both 90-day comp codes lived as plaintext in the app bundle (VezvezakNew/src/services/
// compCodes.ts), extractable by anyone who unpacks the .ipa, and redeemed LOCALLY with no account and no
// limit — redeemable again every time the local grant ran out.
//
// ── WHERE THE CODES LIVE NOW: NOWHERE IN ANY REPOSITORY ───────────────────────────────────────────────────
// They are read from the Worker secret COMP_CODES, a JSON object { "CODE": { "plan": "pro"|"max", "days": 90 } }
// set by the founder with `npx wrangler secret put COMP_CODES`. Not in the bundle, not in this repo, not as
// hashes in source (low-entropy codes are brute-forced offline from a hash), and never through an assistant
// transcript — "do not ask for the secret" applies to the secrets we create as much as to the ones we read.
// The OLD codes are in the app repo's git history. Choosing NEW codes when setting the secret retires them
// for free; that is a founder decision, recorded, not taken here.
//
// ── ONE CODE, ONCE, PER ACCOUNT — without a new table ─────────────────────────────────────────────────────
// The hashes of codes this account has redeemed are kept in user_plans.comp_redeemed, a column on a table
// that account deletion ALREADY removes and privacy §11 ALREADY names ("your subscription tier"). A separate
// comp_redemptions table would be new held data under a new name, and the disclosure gate's clause 4 would
// not even notice it: it drops any deleted table it has no needle for (recorded 2026-09-13). Keeping this in
// the row that is already disclosed and already deleted avoids widening either gap.
//
// ── FAIL CLOSED ON EVERY UNKNOWN ──────────────────────────────────────────────────────────────────────────
// No sign-in · no COMP_CODES secret · an unparseable secret · a malformed code · a code not in the secret · a
// code already redeemed by this account · an ACTIVE paid Apple subscription (a free grant must never overwrite,
// shorten or downgrade what someone paid for, nor detach its original_transaction_id) · rate limit exceeded.
import { json, fail, readJson, requireAuth, rateLimit, ipHash, sha256, nowIso } from './lib.js';

const CODE_RE = /^[A-Z0-9-]{4,40}$/;
const DAY_MS = 86_400_000;

// Parse the secret. Null on anything malformed — a secret we cannot read grants nothing.
export function compTable(env) {
  if (typeof env.COMP_CODES !== 'string' || !env.COMP_CODES.trim()) return null;
  let raw;
  try { raw = JSON.parse(env.COMP_CODES); } catch { return null; }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const table = {};
  for (const [code, g] of Object.entries(raw)) {
    const key = String(code).toUpperCase().trim();
    if (!CODE_RE.test(key)) return null;
    if (!g || (g.plan !== 'pro' && g.plan !== 'max')) return null;
    if (!Number.isInteger(g.days) || g.days < 1 || g.days > 366) return null;
    table[key] = { plan: g.plan, days: g.days };
  }
  return Object.keys(table).length ? table : null;
}

export const normalizeCode = code => String(code || '').toUpperCase().replace(/\s+/g, '').trim();

// PURE. Decide a redemption from the account's current row. Returns a grant, or a named refusal.
export function evaluateRedemption({ grant, codeHash, row, nowMs = Date.now() }) {
  const redeemed = String(row?.comp_redeemed || '').split(',').filter(Boolean);
  if (redeemed.includes(codeHash)) return { ok: false, reason: 'already_redeemed' };
  const active = row && Date.parse(row.expires_at ?? '') > nowMs;
  if (active && row.source === 'apple') return { ok: false, reason: 'active_subscription' };
  // A comp grant runs from NOW, or from the end of an unexpired comp grant OF THE SAME PLAN. It never
  // stacks onto a different plan's window, so redeeming Pro during Max cannot silently downgrade Max.
  if (active && row.source === 'comp' && row.plan !== grant.plan) return { ok: false, reason: 'different_comp_active' };
  const base = active && row.source === 'comp' ? Date.parse(row.expires_at) : nowMs;
  return {
    ok: true, plan: grant.plan, days: grant.days,
    expiresAt: new Date(base + grant.days * DAY_MS).toISOString(),
    comp_redeemed: [...redeemed, codeHash].join(','),
  };
}

export async function compRedeem(request, env) {
  const claims = await requireAuth(request, env);
  if (!claims?.sub) return fail(401, 'Sign in to redeem a code.', 'auth_required');

  // Throttle BEFORE touching the code: a guessable code is protected by the rate limit, not by secrecy alone.
  const ip = await ipHash(request, env);
  for (const bucket of [`comp:user:${claims.sub}`, `comp:ip:${ip}`]) {
    const rl = await rateLimit(env, bucket, 10, 60 * 60 * 1000);
    if (!rl.allowed) return fail(429, 'Too many attempts. Please try again later.', 'rate_limited');
  }

  const body = await readJson(request);
  const code = normalizeCode(body?.code);
  if (!CODE_RE.test(code)) return fail(400, 'That code couldn’t be applied.', 'bad_code');

  const table = compTable(env);
  if (!table) return fail(503, 'Code redemption is not configured.', 'comp_not_configured');

  const grant = table[code];
  // An unknown code is reported the same way a malformed one is — the response must not become an oracle.
  if (!grant) return fail(404, 'That code couldn’t be applied.', 'unknown_code');

  const codeHash = await sha256(`comp:${code}`);
  const row = await env.DB.prepare(
    'SELECT plan, expires_at, source, comp_redeemed FROM user_plans WHERE user_id = ?',
  ).bind(claims.sub).first();

  const verdict = evaluateRedemption({ grant, codeHash, row });
  if (!verdict.ok) return fail(409, 'That code can’t be applied to this account.', verdict.reason);

  await env.DB.prepare(
    `INSERT INTO user_plans (user_id, plan, expires_at, source, comp_redeemed, updated_at)
     VALUES (?, ?, ?, 'comp', ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET plan = excluded.plan, expires_at = excluded.expires_at,
       source = excluded.source, comp_redeemed = excluded.comp_redeemed, updated_at = excluded.updated_at`,
  ).bind(claims.sub, verdict.plan, verdict.expiresAt, verdict.comp_redeemed, nowIso()).run();

  return json(200, { ok: true, plan: verdict.plan, days: verdict.days, expiresAt: verdict.expiresAt });
}
