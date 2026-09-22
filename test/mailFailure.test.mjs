// A PASSWORD RESET THAT NEVER ARRIVES, AND NOTHING ANYWHERE SAYING WHY (Ehsan 2026-09-22).
//
// Measured on the live Worker: `/auth/otp/request` answered 503 "Verification email is not configured yet. Please
// try again later." for every address and every purpose, because RESEND_API_KEY was never set — `wrangler secret
// list` held only COMP_CODES and JWT_SECRET. Every "Forgot password" since the app existed was a locked door, and
// the sentence on it invited people to wait for something waiting could not deliver.
//
// The other half: when a key IS set and Resend refuses — a domain it has not verified is the likely next failure,
// since vezvezak.com's SPF authorises Zoho only — the code discarded Resend's response and said "Could not send
// the code. Please try again later." An unset key and an unverified domain were indistinguishable, to the person
// locked out and to us.
//
// Run: node test/mailFailure.test.mjs
import assert from 'node:assert/strict';
import { MAIL_FAIL, MAIL_MESSAGE, classifyMailStatus, mailFailure } from '../src/mail.js';

let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

await t('every reason has a sentence, and no sentence is shared between two reasons', () => {
  const reasons = Object.values(MAIL_FAIL);
  assert.ok(reasons.length >= 5, `expected the full vocabulary, got ${reasons.length}`);
  for (const r of reasons) assert.ok(MAIL_MESSAGE[r], `no sentence for ${r}`);
  assert.equal(new Set(reasons.map(r => MAIL_MESSAGE[r])).size, reasons.length, 'two reasons sharing one sentence is one reason');
});

await t('a fault that waiting cannot fix never says "try again later"', () => {
  // THE BUG, in one line. These two are configuration faults on our side; time does not touch them.
  for (const r of [MAIL_FAIL.notConfigured, MAIL_FAIL.providerRejected]) {
    assert.doesNotMatch(MAIL_MESSAGE[r], /try again later/i, `${r}: "${MAIL_MESSAGE[r]}"`);
  }
  // NEGATIVE: the reasons where waiting IS the right advice must still say so, or this check proves nothing.
  for (const r of [MAIL_FAIL.rateLimited, MAIL_FAIL.unreachable]) {
    assert.match(MAIL_MESSAGE[r], /wait|try again/i, `${r} should tell the person to try again: "${MAIL_MESSAGE[r]}"`);
  }
});

await t('a person locked out is told the door that DOES open', () => {
  assert.match(MAIL_MESSAGE[MAIL_FAIL.notConfigured], /password/i, 'if no code can be sent, say what can be used');
  assert.match(MAIL_MESSAGE[MAIL_FAIL.providerRejected], /password/i);
  assert.match(MAIL_MESSAGE[MAIL_FAIL.providerRejected], /our side|not something you can fix/i, "do not imply the user misconfigured our email");
});

await t("Resend's MEASURED 401 is classified as ours to fix, not the user's", () => {
  // Real response, https://api.resend.com/emails, 2026-09-22, with no key and with a bad key:
  //   {"statusCode":401,"name":"validation_error","message":"API key is invalid"}
  assert.equal(classifyMailStatus(401), MAIL_FAIL.providerRejected);
  assert.equal(classifyMailStatus(403), MAIL_FAIL.providerRejected, 'an unverified sending domain is also ours');
  assert.equal(classifyMailStatus(500), MAIL_FAIL.providerRejected, "the provider's own outage is still not the user's fault");
  assert.equal(classifyMailStatus(429), MAIL_FAIL.rateLimited);
  assert.equal(classifyMailStatus(422), MAIL_FAIL.recipientRefused);
  assert.equal(classifyMailStatus(400), MAIL_FAIL.recipientRefused);
  // NEGATIVE: a refused recipient must NOT be reported as our configuration, or a typo looks like an outage.
  assert.notEqual(classifyMailStatus(422), MAIL_FAIL.providerRejected);
});

await t('the provider detail is machine-readable and carries no prose for a person to read', () => {
  const f = mailFailure(MAIL_FAIL.providerRejected, { provider: 'resend', status: 401, name: 'validation_error' });
  assert.equal(f.ok, false);
  assert.equal(f.reason, MAIL_FAIL.providerRejected);
  assert.equal(f.error, MAIL_MESSAGE[MAIL_FAIL.providerRejected]);
  assert.equal(f.detail.status, 401);
  assert.equal(f.detail.name, 'validation_error');
  assert.equal(JSON.stringify(f).includes('API key is invalid'), false, "Resend's prose is for a developer, not for the person locked out");
  assert.equal(mailFailure(MAIL_FAIL.notConfigured).detail, undefined, 'no detail where there was no provider call');
});

// ── and the route actually answers with it ───────────────────────────────────
let DatabaseSync;
try { ({ DatabaseSync } = await import('node:sqlite')); }
catch {
  console.log('\nNOTICE: node:sqlite unavailable — the /auth/otp/request integration check was SKIPPED.');
  console.log(`\nVERDICT: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const HERE = dirname(fileURLToPath(import.meta.url));
const worker = (await import('../src/index.js')).default;
const db = new DatabaseSync(':memory:');
db.exec(readFileSync(resolve(HERE, '..', 'schema.sql'), 'utf8'));
const makeD1 = database => ({
  prepare(sql) {
    const stmt = database.prepare(sql);
    let bound = [];
    const api = {
      bind(...a) { bound = a; return api; },
      async first() { const r = stmt.get(...bound); return r === undefined ? null : r; },
      async run() { const r = stmt.run(...bound); return { meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid) } }; },
      async all() { return { results: stmt.all(...bound) }; },
    };
    return api;
  },
});
const call = async env => {
  const res = await worker.fetch(new Request('https://api.test/auth/otp/request', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier: 'ehsan@vezvezak.com', purpose: 'reset' }),
  }), env);
  return { status: res.status, body: await res.json() };
};

await t('THE LIVE STATE: with no RESEND_API_KEY the route says so, by name', async () => {
  const r = await call({ DB: makeD1(db), JWT_SECRET: 't' });
  assert.equal(r.status, 503);
  assert.equal(r.body.reason, MAIL_FAIL.notConfigured, `the app must be able to act on this: ${JSON.stringify(r.body)}`);
  assert.doesNotMatch(r.body.error, /try again later/i);
});

await t('with a key, a provider refusal is reported as a refusal — not as "not configured"', async () => {
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ statusCode: 401, name: 'validation_error', message: 'API key is invalid' }), { status: 401, headers: { 'content-type': 'application/json' } });
  try {
    const r = await call({ DB: makeD1(db), JWT_SECRET: 't', RESEND_API_KEY: 're_whatever' });
    assert.equal(r.status, 503);
    assert.equal(r.body.reason, MAIL_FAIL.providerRejected, `these two must not look the same: ${JSON.stringify(r.body)}`);
  } finally { globalThis.fetch = real; }
});

await t('a send that SUCCEEDS is not reported as a failure', async () => {
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ id: 'em_1' }), { status: 200, headers: { 'content-type': 'application/json' } });
  try {
    const r = await call({ DB: makeD1(db), JWT_SECRET: 't', RESEND_API_KEY: 're_whatever' });
    assert.equal(r.status, 200, `a working send must be a 200: ${JSON.stringify(r.body)}`);
    assert.equal(db.prepare("SELECT COUNT(*) c FROM otp_codes WHERE identifier = 'ehsan@vezvezak.com'").get().c > 0, true, 'and the code must be stored to verify against');
  } finally { globalThis.fetch = real; }
});

console.log(`\nVERDICT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
