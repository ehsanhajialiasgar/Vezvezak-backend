// IAP VALIDATION + SERVER-SIDE EXPIRY (launch chain step 5, ledger 1.2 — Ehsan 2026-09-14).
// Behavioural where it can be: a real P-256 key signs a real JWT that is verified with its public key; a fake
// Apple returns real JWS-shaped bodies; a fake D1 records what is written. The one thing NOT testable here is
// Apple itself — there is no App Store Connect account yet — and that is stated, not faked.
// Run: node test/iap.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  PRODUCT_PLANS, appleConfig, signAppleJwt, decodeJwsPayload, fetchTransaction, evaluateTransaction, iapValidate,
} from '../src/iap.js';
import { planFor, signJwt, b64u, unb64u } from '../src/lib.js';

let passed = 0;
const t = async (name, fn) => { await fn(); passed++; console.log('  ok -', name); };
const enc = new TextEncoder();
const NOW = Date.UTC(2026, 8, 14, 12, 0, 0);
const DAY = 86_400_000;

// ── a real ES256 key, exported as the PKCS8 PEM Apple issues as a .p8 ─────────────────────────────────────
const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
const PEM = `-----BEGIN PRIVATE KEY-----\n${btoa(String.fromCharCode(...pkcs8)).match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
const ENV_OK = { APPLE_ISSUER_ID: 'issuer-1', APPLE_KEY_ID: 'KEY123', APPLE_PRIVATE_KEY: PEM, APPLE_BUNDLE_ID: 'com.vezvezak.app', JWT_SECRET: 'test-secret' };
const CFG = appleConfig(ENV_OK);

const jws = obj => `${b64u(enc.encode('{"alg":"ES256"}'))}.${b64u(enc.encode(JSON.stringify(obj)))}.c2ln`;
const goodTx = (over = {}) => ({
  bundleId: 'com.vezvezak.app', productId: 'vez_pro_monthly', type: 'Auto-Renewable Subscription',
  expiresDate: NOW + 30 * DAY, originalTransactionId: '2000000123456789', ...over,
});

// ── configuration ─────────────────────────────────────────────────────────────────────────────────────────
await t('appleConfig is NULL unless every credential is present — a partial config is an unknown', () => {
  assert.ok(CFG);
  for (const k of ['APPLE_ISSUER_ID', 'APPLE_KEY_ID', 'APPLE_PRIVATE_KEY', 'APPLE_BUNDLE_ID']) {
    assert.equal(appleConfig({ ...ENV_OK, [k]: undefined }), null, `missing ${k} must yield null`);
    assert.equal(appleConfig({ ...ENV_OK, [k]: '   ' }), null, `blank ${k} must yield null`);
  }
});

await t('product map covers exactly the four ids the app defines, and nothing else grants', () => {
  const app = readFileSync('../VezvezakNew/src/services/iapService.ts', 'utf8');
  const ids = [...app.matchAll(/'(vez_[a-z_]+)'/g)].map(m => m[1]).sort();
  assert.deepEqual(Object.keys(PRODUCT_PLANS).sort(), ids, 'backend PRODUCT_PLANS must match the app PRODUCT_IDS exactly');
});

// ── the JWT to Apple is real ES256 ────────────────────────────────────────────────────────────────────────
await t('signAppleJwt produces an ES256 JWT that VERIFIES with the public key, with Apple’s required claims', async () => {
  const token = await signAppleJwt(CFG, NOW / 1000);
  const [h, p, s] = token.split('.');
  const header = JSON.parse(new TextDecoder().decode(unb64u(h)));
  const payload = JSON.parse(new TextDecoder().decode(unb64u(p)));
  assert.deepEqual(header, { alg: 'ES256', kid: 'KEY123', typ: 'JWT' });
  assert.equal(payload.aud, 'appstoreconnect-v1');
  assert.equal(payload.iss, 'issuer-1');
  assert.equal(payload.bid, 'com.vezvezak.app');
  assert.ok(payload.exp - payload.iat <= 3600, 'Apple rejects tokens living longer than 60 minutes');
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, unb64u(s), enc.encode(`${h}.${p}`));
  assert.equal(ok, true, 'the signature must verify');
});

// ── evaluateTransaction: every refusal branch ─────────────────────────────────────────────────────────────
await t('a valid, unexpired, unrevoked Pro subscription for our bundle GRANTS pro with Apple’s expiry', () => {
  const v = evaluateTransaction(goodTx(), CFG, NOW);
  assert.equal(v.ok, true); assert.equal(v.plan, 'pro');
  assert.equal(v.expiresAt, new Date(NOW + 30 * DAY).toISOString());
});
for (const [label, over, reason] of [
  ['another app’s bundle', { bundleId: 'com.evil.app' }, 'bundle_mismatch'],
  ['an unknown product', { productId: 'vez_lifetime_free' }, 'unknown_product'],
  ['a non-subscription purchase', { type: 'Non-Consumable' }, 'not_a_subscription'],
  ['a REVOKED (refunded) transaction', { revocationDate: NOW - DAY }, 'revoked'],
  ['an EXPIRED subscription', { expiresDate: NOW - 1 }, 'expired'],
  ['a missing expiry', { expiresDate: undefined }, 'no_expiry'],
  ['a missing original transaction id', { originalTransactionId: undefined }, 'no_original_transaction_id'],
]) {
  await t(`REFUSES ${label} (${reason})`, () => {
    const v = evaluateTransaction(goodTx(over), CFG, NOW);
    assert.equal(v.ok, false); assert.equal(v.reason, reason);
  });
}

await t('decodeJwsPayload throws on anything that is not a three-part JWS with an object payload', () => {
  for (const bad of [null, 'abc', 'a.b', 'a..c', `a.${b64u(enc.encode('"str"'))}.c`]) assert.throws(() => decodeJwsPayload(bad));
});

// ── fetchTransaction: every Apple response shape ──────────────────────────────────────────────────────────
const res = (status, body) => ({ status, json: async () => body });
await t('Production 200 → uses Production', async () => {
  const seen = [];
  const r = await fetchTransaction('123', CFG, async url => { seen.push(url); return res(200, { signedTransactionInfo: jws(goodTx()) }); }, NOW / 1000);
  assert.equal(r.ok, true); assert.equal(r.environment, 'Production'); assert.equal(seen.length, 1);
});
await t('Production 404 → falls back to Sandbox (Apple’s documented order)', async () => {
  const r = await fetchTransaction('123', CFG, async url => url.includes('sandbox') ? res(200, { signedTransactionInfo: jws(goodTx()) }) : res(404, {}), NOW / 1000);
  assert.equal(r.ok, true); assert.equal(r.environment, 'Sandbox');
});
for (const [label, impl, reason] of [
  ['Apple 401 (bad key)', async () => res(401, {}), 'apple_http_401'],
  ['Apple 500', async () => res(500, {}), 'apple_http_500'],
  ['network failure', async () => { throw new Error('down'); }, 'apple_unreachable'],
  ['200 with no signedTransactionInfo', async () => res(200, {}), 'apple_no_signed_transaction'],
  ['404 in BOTH environments', async () => res(404, {}), 'apple_not_found'],
]) {
  await t(`FAILS CLOSED on ${label}`, async () => {
    const r = await fetchTransaction('123', CFG, impl, NOW / 1000);
    assert.equal(r.ok, false); assert.equal(r.reason, reason);
  });
}

// ── the handler end to end, against a fake D1 ─────────────────────────────────────────────────────────────
function fakeDB(existingBinding = null) {
  const writes = [];
  return {
    writes,
    prepare(sql) {
      return {
        bind: (...args) => ({
          first: async () => (/original_transaction_id = \?/.test(sql) ? existingBinding : null),
          run: async () => { writes.push({ sql, args }); return {}; },
        }),
      };
    },
  };
}
async function call(env, body, fetchImpl, withAuth = true) {
  const headers = { 'Content-Type': 'application/json' };
  if (withAuth) headers.Authorization = `Bearer ${await signJwt({ sub: 'user-A' }, env.JWT_SECRET)}`;
  const r = await iapValidate(new Request('https://x/iap/validate', { method: 'POST', headers, body: JSON.stringify(body) }), env, fetchImpl);
  return { status: r.status, body: await r.json() };
}
const appleOk = async () => res(200, { signedTransactionInfo: jws(goodTx({ expiresDate: Date.now() + 30 * DAY })) });

await t('handler: no sign-in → 401, and Apple is never called', async () => {
  let called = false;
  const r = await call({ ...ENV_OK, DB: fakeDB() }, { transactionId: '123' }, async () => { called = true; }, false);
  assert.equal(r.status, 401); assert.equal(called, false);
});
await t('handler: a non-numeric transaction id → 400 before Apple is called', async () => {
  let called = false;
  const r = await call({ ...ENV_OK, DB: fakeDB() }, { transactionId: '../../etc' }, async () => { called = true; });
  assert.equal(r.status, 400); assert.equal(called, false);
});
await t('handler: credentials missing → 503 iap_not_configured, before Apple is called', async () => {
  let called = false;
  const r = await call({ JWT_SECRET: 'test-secret', DB: fakeDB() }, { transactionId: '123' }, async () => { called = true; });
  assert.equal(r.status, 503); assert.equal(r.body.reason, 'iap_not_configured'); assert.equal(called, false);
});
await t('handler: valid purchase → 200, writes plan + expires_at + source=apple for THIS account', async () => {
  const DB = fakeDB();
  const r = await call({ ...ENV_OK, DB }, { transactionId: '123' }, appleOk);
  assert.equal(r.status, 200); assert.equal(r.body.plan, 'pro');
  assert.equal(DB.writes.length, 1);
  const [userId, plan, expiresAt] = DB.writes[0].args;
  assert.equal(userId, 'user-A'); assert.equal(plan, 'pro'); assert.ok(Date.parse(expiresAt) > Date.now());
  assert.match(DB.writes[0].sql, /'apple'/);
});
await t('handler: a purchase already bound to ANOTHER account → 409, and NOTHING is written (replay guard)', async () => {
  const DB = fakeDB({ user_id: 'user-B' });
  const r = await call({ ...ENV_OK, DB }, { transactionId: '123' }, appleOk);
  assert.equal(r.status, 409); assert.equal(r.body.reason, 'transaction_bound_elsewhere'); assert.equal(DB.writes.length, 0);
});
await t('handler: Apple says expired → 402, and NOTHING is written', async () => {
  const DB = fakeDB();
  const r = await call({ ...ENV_OK, DB }, { transactionId: '123' },
    async () => res(200, { signedTransactionInfo: jws(goodTx({ expiresDate: Date.now() - DAY })) }));
  assert.equal(r.status, 402); assert.equal(r.body.reason, 'expired'); assert.equal(DB.writes.length, 0);
});

// ── ledger 1.2: planFor refuses an expired, absent or unparseable expiry on a paid row ────────────────────
const dbWithRow = row => ({ prepare: () => ({ bind: () => ({ first: async () => row }) }) });
await t('planFor: a paid row with a FUTURE expiry is that plan', async () => {
  assert.equal(await planFor({ DB: dbWithRow({ plan: 'max', expires_at: new Date(NOW + DAY).toISOString() }) }, 'u', NOW), 'max');
});
for (const [label, row] of [
  ['a PAST expiry', { plan: 'pro', expires_at: new Date(NOW - 1).toISOString() }],
  ['NO expiry (a row predating the migration)', { plan: 'pro', expires_at: null }],
  ['an UNPARSEABLE expiry', { plan: 'pro', expires_at: 'forever' }],
  ['no row at all', null],
]) {
  await t(`planFor: a paid plan with ${label} resolves to FREE — a paid plan cannot outlive its expiry`, async () => {
    assert.equal(await planFor({ DB: dbWithRow(row) }, 'u', NOW), 'free');
  });
}

// ── the reachability consequence, stated in the test so it cannot be forgotten ────────────────────────────
await t('this endpoint makes plan gates reachable — MODERATION_ENABLED still holds moderation closed', () => {
  const toml = readFileSync('wrangler.toml', 'utf8');
  assert.match(toml, /MODERATION_ENABLED\s*=\s*"0"/, 'with a real paid writer, the flag is the ONLY thing holding moderation closed');
});

console.log(`\niap validation + server expiry: ${passed} checks passed`);
