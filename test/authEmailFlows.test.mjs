// THE THREE THINGS THAT COME THROUGH THE EMAIL PIPE, WALKED END TO END (Ehsan 2026-09-22).
//
// RESEND_API_KEY existed for the first time on 2026-09-22, so until that day none of these had ever completed:
// a password reset, an emailed sign-up code, and a one-time code sign-in. They share one sender, so they share
// one failure and one fix — and they were never run together.
//
// Every step here runs the REAL route code in src/index.js against a REAL SQLite database built from schema.sql.
// The only thing intercepted is the outbound HTTPS call to Resend, which is how the six-digit code is read: it is
// generated and hashed server-side and cannot be recovered from the database, so the message body is the only
// place it exists. That is the same place a person reads it from.
// Self-skips where node:sqlite is unavailable. Run: node test/authEmailFlows.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

let DatabaseSync;
try { ({ DatabaseSync } = await import('node:sqlite')); }
catch { console.log('\nNOTICE: node:sqlite unavailable — the auth email flows were NOT run.'); console.log('\nVERDICT: 0 passed, 0 failed'); process.exit(0); }

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
  async batch(list) { return Promise.all(list.map(s => s.run())); },
});
const env = { DB: makeD1(db), JWT_SECRET: 'test-secret', RESEND_API_KEY: 're_test' };

// THE INBOX. Every message the Worker hands to Resend lands here, whole — the same bytes a mail client receives.
const inbox = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  if (String(url).startsWith('https://api.resend.com/')) {
    inbox.push({ ...JSON.parse(init.body), _headers: init.headers });
    return new Response(JSON.stringify({ id: `em_${inbox.length}` }), { status: 200, headers: { 'content-type': 'application/json' } });
  }
  return realFetch(url, init);
};
const lastMail = () => inbox[inbox.length - 1];
// The code, read the way a person reads it: out of the message, not out of the database.
const codeFromMail = m => (m.text.match(/^\s*(\d{4,8})\s*$/m) || [])[1];

const post = async (path, body, token) => {
  const res = await worker.fetch(new Request(`https://api.test${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  }), env);
  return { status: res.status, body: await res.json() };
};

let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

const WHO = 'reset-proof@vezvezak.com';
const FIRST = 'firstpass2609';
const SECOND = 'secondpass2609';

// ── 1 · an account exists ────────────────────────────────────────────────────
await t('an account is created, and it is not usable until its address is confirmed', async () => {
  const r = await post('/auth/signup', { identifier: WHO, password: FIRST });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.needsOtp, true, 'since 2026-09-22 sign-up sends a code and withholds the session');
  assert.equal(r.body.token, undefined);
  const locked = await post('/auth/login', { identifier: WHO, password: FIRST });
  assert.equal(locked.status, 403, JSON.stringify(locked.body));
  assert.equal(locked.body.reason, 'email_unverified');
});

await t('confirming the address is what makes the password work', async () => {
  const v = await post('/auth/otp/verify', { identifier: WHO, code: codeFromMail(lastMail()), purpose: 'signup' });
  assert.equal(v.status, 200, JSON.stringify(v.body));
  const r = await post('/auth/login', { identifier: WHO, password: FIRST });
  assert.equal(r.status, 200, JSON.stringify(r.body));
});

// ── 2 · PASSWORD RESET, every step ───────────────────────────────────────────
let resetToken;
await t('RESET 1/4 — a code is requested and an email is actually composed and sent', async () => {
  const before = inbox.length;
  const r = await post('/auth/otp/request', { identifier: WHO, purpose: 'reset' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(inbox.length, before + 1, 'a 200 with no message sent is the exact lie this pipe used to tell');
  const m = lastMail();
  assert.deepEqual(m.to, [WHO]);
  assert.match(m.subject, /password reset/i);
  assert.ok(m.html && m.text, 'both parts must go — a text-only client must lose nothing');
  assert.equal(m.reply_to, 'support@vezvezak.com');
});

await t('RESET 2/4 — a WRONG code is refused, and the real one still works after it', async () => {
  const bad = await post('/auth/otp/verify', { identifier: WHO, code: '000000', purpose: 'reset' });
  assert.notEqual(bad.status, 200, 'any six digits must not open the door');
  assert.equal(bad.body.resetToken, undefined);
});

await t('RESET 3/4 — the code from the EMAIL returns a reset token', async () => {
  const code = codeFromMail(lastMail());
  assert.ok(code, `no code could be read from the message:\n${lastMail().text}`);
  const r = await post('/auth/otp/verify', { identifier: WHO, code, purpose: 'reset' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  resetToken = r.body.resetToken;
  assert.ok(resetToken, 'a reset purpose must hand back the token the next step spends');
});

await t('RESET 4/4 — the new password is set, the OLD one stops working, the new one signs in', async () => {
  const r = await post('/auth/password/reset', { identifier: WHO, resetToken, password: SECOND });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.token, 'a completed reset signs you in');
  const old = await post('/auth/login', { identifier: WHO, password: FIRST });
  assert.notEqual(old.status, 200, 'the old password must be dead — this is the whole point of a reset');
  const now = await post('/auth/login', { identifier: WHO, password: SECOND });
  assert.equal(now.status, 200, JSON.stringify(now.body));
});

await t('a spent reset token cannot be spent twice', async () => {
  const again = await post('/auth/password/reset', { identifier: WHO, resetToken, password: 'thirdpass2609' });
  assert.notEqual(again.status, 200, 'a used token is a key left in a door');
  const still = await post('/auth/login', { identifier: WHO, password: SECOND });
  assert.equal(still.status, 200, 'and the password must not have changed');
});

await t('a code already used cannot be replayed', async () => {
  const code = codeFromMail(lastMail());
  const r = await post('/auth/otp/verify', { identifier: WHO, code, purpose: 'reset' });
  assert.notEqual(r.status, 200, 'consumed means consumed');
});

// ── 3 · SIGN-UP CODE ─────────────────────────────────────────────────────────
await t('SIGN-UP — a verification code is sent, and it is a DIFFERENT email from the reset one', async () => {
  // The signup code VERIFIES an address on an account that already exists — otpVerify's non-reset branch looks
  // the user up and refuses when there is none. So the account is created first, exactly as SignUpScreen does.
  const NEW = 'signup-proof@vezvezak.com';
  assert.equal((await post('/auth/signup', { identifier: NEW, password: 'signuppass26' })).status, 200);
  const r = await post('/auth/otp/request', { identifier: NEW, purpose: 'signup' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const m = lastMail();
  assert.deepEqual(m.to, [NEW]);
  assert.match(m.subject, /verification code/i);
  assert.doesNotMatch(m.subject, /password reset/i, 'a sign-up must not arrive wearing the reset subject');
  assert.match(m.text, /finish creating your account/i);
  const v = await post('/auth/otp/verify', { identifier: NEW, code: codeFromMail(m), purpose: 'signup' });
  assert.equal(v.status, 200, JSON.stringify(v.body));
  assert.equal(db.prepare('SELECT verified FROM users WHERE identifier = ?').get(NEW).verified, 1,
    'verifying the address is the only thing this purpose does that signin does not');
});

await t('and the app now HAS a journey that asks for it — the note this replaced said it did not', () => {
  // /auth/signup answered needsOtp:false until 2026-09-22, so SignUpScreen's code branch was unreachable and
  // no sign-up email was ever sent to anyone. The founder reversed that the day email began to send.
  const src = readFileSync(resolve(HERE, '..', 'src', 'index.js'), 'utf8');
  assert.doesNotMatch(src, /needsOtp: false/, 'sign-up must not hand back a session again');
  assert.match(src, /needsOtp: true/);
});

// ── 4 · ONE-TIME CODE SIGN-IN ────────────────────────────────────────────────
await t('SIGN-IN BY CODE — the code signs the person in and returns a session', async () => {
  const r = await post('/auth/otp/request', { identifier: WHO, purpose: 'signin' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const m = lastMail();
  assert.match(m.subject, /sign-in code/i);
  assert.match(m.text, /Sign in to Vezvezak/i);
  const v = await post('/auth/otp/verify', { identifier: WHO, code: codeFromMail(m), purpose: 'signin' });
  assert.equal(v.status, 200, JSON.stringify(v.body));
  assert.ok(v.body.token, 'a sign-in code must hand back a session, not a reset token');
  assert.equal(v.body.resetToken, undefined, 'a sign-in must NOT hand out a password-reset token');
});

await t('a code issued for SIGN-IN cannot be spent as a RESET', async () => {
  const r = await post('/auth/otp/request', { identifier: WHO, purpose: 'signin' });
  assert.equal(r.status, 200);
  const code = codeFromMail(lastMail());
  const wrong = await post('/auth/otp/verify', { identifier: WHO, code, purpose: 'reset' });
  assert.notEqual(wrong.status, 200, 'purposes must not be interchangeable — that would turn a sign-in into a takeover');
});

await t('every message sent in this run carried both parts and no tracking', () => {
  // NAME THE SET, don't score it. These are exactly the sends this file asks for, in order; a count on its own
  // would pass just as happily if two of them had silently stopped going out.
  const expected = ['verification', 'password reset', 'verification', 'verification', 'sign-in', 'sign-in'];
  assert.equal(inbox.length, expected.length, `sent ${inbox.length} messages, expected ${expected.length}: ${inbox.map(m => m.subject).join(' | ')}`);
  inbox.forEach((m, i) => assert.ok(m.subject.toLowerCase().includes(expected[i]),
    `message ${i + 1} should be the ${expected[i]} one, was "${m.subject}"`));
  for (const m of inbox) {
    assert.ok(m.html && m.text, 'a message went out with only one part');
    assert.doesNotMatch(m.html, /<img\b|<a\b/i, 'an image or a link reached a real send path');
  }
});

globalThis.fetch = realFetch;
console.log(`\n  (${inbox.length} messages composed and sent through the real route code)`);
console.log(`\nVERDICT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
