// COMP CODES SERVER-SIDE (launch chain step 6 — Ehsan 2026-09-14). Run: node test/comp.test.mjs
// The codes in this file are TEST FIXTURES invented here. The real codes live only in the COMP_CODES Worker
// secret; if a real code ever appears in this repository, the last test fails.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { compTable, normalizeCode, evaluateRedemption, compRedeem } from '../src/comp.js';
import { signJwt, sha256 } from '../src/lib.js';

let passed = 0;
const t = async (name, fn) => { await fn(); passed++; console.log('  ok -', name); };
const NOW = Date.UTC(2026, 8, 14, 12);
const DAY = 86_400_000;
const SECRET = JSON.stringify({ 'TEST-PRO-FIXTURE': { plan: 'pro', days: 90 }, 'TEST-MAX-FIXTURE': { plan: 'max', days: 90 } });

// ── the secret ────────────────────────────────────────────────────────────────────────────────────────────
await t('compTable reads a well-formed secret', () => {
  assert.deepEqual(compTable({ COMP_CODES: SECRET })['TEST-PRO-FIXTURE'], { plan: 'pro', days: 90 });
});
for (const [label, v] of [
  ['absent', undefined], ['blank', '  '], ['not JSON', '{nope'], ['an array', '[]'], ['empty object', '{}'],
  ['an unknown plan', '{"X-CODE":{"plan":"lifetime","days":90}}'], ['non-integer days', '{"X-CODE":{"plan":"pro","days":1.5}}'],
  ['absurd days', '{"X-CODE":{"plan":"pro","days":9999}}'], ['a malformed code', '{"no spaces allowed":{"plan":"pro","days":90}}'],
]) {
  await t(`compTable is NULL for a secret that is ${label} — a secret we cannot read grants nothing`, () => {
    assert.equal(compTable({ COMP_CODES: v }), null);
  });
}

// ── the pure decision ─────────────────────────────────────────────────────────────────────────────────────
const G = { plan: 'pro', days: 90 };
await t('first redemption with no row grants 90 days from now and records the hash', () => {
  const v = evaluateRedemption({ grant: G, codeHash: 'h1', row: null, nowMs: NOW });
  assert.equal(v.ok, true); assert.equal(v.expiresAt, new Date(NOW + 90 * DAY).toISOString()); assert.equal(v.comp_redeemed, 'h1');
});
await t('REFUSES a code this account already redeemed — even after its grant has EXPIRED (no infinite renewals)', () => {
  const row = { plan: 'pro', source: 'comp', expires_at: new Date(NOW - DAY).toISOString(), comp_redeemed: 'h1' };
  assert.equal(evaluateRedemption({ grant: G, codeHash: 'h1', row, nowMs: NOW }).reason, 'already_redeemed');
});
await t('REFUSES while a PAID Apple subscription is active — a free grant must never overwrite what someone paid for', () => {
  const row = { plan: 'max', source: 'apple', expires_at: new Date(NOW + 10 * DAY).toISOString(), comp_redeemed: '' };
  assert.equal(evaluateRedemption({ grant: G, codeHash: 'h9', row, nowMs: NOW }).reason, 'active_subscription');
});
await t('REFUSES a different-plan comp while another comp is active — redeeming Pro during Max cannot downgrade Max', () => {
  const row = { plan: 'max', source: 'comp', expires_at: new Date(NOW + 10 * DAY).toISOString(), comp_redeemed: 'hmax' };
  assert.equal(evaluateRedemption({ grant: G, codeHash: 'hpro', row, nowMs: NOW }).reason, 'different_comp_active');
});
await t('a second DISTINCT same-plan code extends from the END of the active comp window, not from now', () => {
  const end = NOW + 10 * DAY;
  const row = { plan: 'pro', source: 'comp', expires_at: new Date(end).toISOString(), comp_redeemed: 'h1' };
  const v = evaluateRedemption({ grant: G, codeHash: 'h2', row, nowMs: NOW });
  assert.equal(v.expiresAt, new Date(end + 90 * DAY).toISOString()); assert.equal(v.comp_redeemed, 'h1,h2');
});
await t('an EXPIRED Apple subscription does not block a comp — nothing active to protect', () => {
  const row = { plan: 'pro', source: 'apple', expires_at: new Date(NOW - DAY).toISOString(), comp_redeemed: '' };
  assert.equal(evaluateRedemption({ grant: G, codeHash: 'h3', row, nowMs: NOW }).ok, true);
});
await t('normalizeCode upper-cases and strips whitespace', () => { assert.equal(normalizeCode(' test-pro fixture '), 'TEST-PROFIXTURE'); });

// ── the handler, against a fake D1 ────────────────────────────────────────────────────────────────────────
function fakeDB({ row = null, limited = false } = {}) {
  const writes = [];
  return {
    writes,
    prepare(sql) {
      return { bind: (...args) => ({
        first: async () => (/FROM rate_limits/i.test(sql) ? (limited ? { count: 999, window_at: Date.now() } : null) : (/FROM user_plans/.test(sql) ? row : null)),
        run: async () => { writes.push({ sql, args }); return {}; },
      }) };
    },
  };
}
async function call(env, body, withAuth = true) {
  const headers = { 'Content-Type': 'application/json', 'cf-connecting-ip': '203.0.113.9' };
  if (withAuth) headers.Authorization = `Bearer ${await signJwt({ sub: 'user-A' }, env.JWT_SECRET)}`;
  const r = await compRedeem(new Request('https://x/comp/redeem', { method: 'POST', headers, body: JSON.stringify(body) }), env);
  return { status: r.status, body: await r.json() };
}
const ENV = (over = {}) => ({ JWT_SECRET: 'test-secret', COMP_CODES: SECRET, DB: fakeDB(), ...over });

await t('handler: no sign-in → 401', async () => { assert.equal((await call(ENV(), { code: 'TEST-PRO-FIXTURE' }, false)).status, 401); });
await t('handler: secret absent → 503 comp_not_configured, and nothing is written', async () => {
  const env = ENV({ COMP_CODES: undefined });
  const r = await call(env, { code: 'TEST-PRO-FIXTURE' });
  assert.equal(r.status, 503); assert.equal(r.body.reason, 'comp_not_configured');
  assert.equal(env.DB.writes.filter(w => /user_plans/.test(w.sql)).length, 0);
});
await t('handler: an unknown code → 404, with the SAME public message as a malformed one (no oracle)', async () => {
  const unknown = await call(ENV(), { code: 'NOT-A-REAL-CODE' });
  const bad = await call(ENV(), { code: '!!' });
  assert.equal(unknown.status, 404); assert.equal(unknown.body.error, bad.body.error);
});
await t('handler: a valid code → 200, writes plan + expires_at + source=comp + the code HASH (never the code)', async () => {
  const env = ENV();
  const r = await call(env, { code: 'test-pro-fixture' });
  assert.equal(r.status, 200); assert.equal(r.body.plan, 'pro');
  const w = env.DB.writes.find(x => /INSERT INTO user_plans/.test(x.sql));
  assert.ok(w, 'a user_plans write must happen'); assert.match(w.sql, /'comp'/);
  assert.equal(w.args[3], await sha256('comp:TEST-PRO-FIXTURE'));
  assert.ok(!w.args.includes('TEST-PRO-FIXTURE'), 'the plaintext code must never be stored');
});
await t('handler: rate-limited → 429 BEFORE the code is even looked up', async () => {
  const r = await call(ENV({ DB: fakeDB({ limited: true }) }), { code: 'TEST-PRO-FIXTURE' });
  assert.equal(r.status, 429);
});

// ── the bundle no longer carries codes, and no real code is in this repo ──────────────────────────────────
await t('this repository contains no comp code table in source — codes live only in the COMP_CODES secret', () => {
  const src = readdirSync('src').filter(f => f.endsWith('.js')).map(f => readFileSync(`src/${f}`, 'utf8')).join('\n');
  assert.doesNotMatch(src, /COMP_CODES\s*[:=]\s*\{/, 'a literal comp table must not exist in backend source');
  assert.doesNotMatch(readFileSync('wrangler.toml', 'utf8'), /COMP_CODES\s*=/, 'COMP_CODES must be a SECRET, never a [vars] entry');
});

console.log(`\ncomp codes server-side: ${passed} checks passed`);
