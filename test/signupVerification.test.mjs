// EVERY NEW ACCOUNT CONFIRMS ITS EMAIL ADDRESS (Ehsan 2026-09-22, decided).
//
// It was off for one written-down reason: blocking sign-up on a code that could not be delivered would have
// locked every new user out while RESEND_API_KEY did not exist. The key exists as of today, so the reason
// expired and the decision was reversed.
//
// The dangerous half is not the gate, it is WHO IT CATCHES. All nine accounts in production are verified = 0 —
// the founder's included — because otpVerify was the only writer of that column and nothing could reach it.
// Turning the requirement on without grandfathering would lock out every existing account, which is not a
// security improvement but a punishment for a door we never opened.
// Self-skips where node:sqlite is unavailable. Run: node test/signupVerification.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { verificationState, mayUseAccount, waitPhrase, VERIFY_REQUIRED_FROM } from '../src/verification.js';

const HERE = dirname(fileURLToPath(import.meta.url));
let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

// ── the rule, every branch ───────────────────────────────────────────────────
await t('the three states are kept apart, and an unreadable row is neither verified nor locked out', () => {
  assert.equal(verificationState({ verified: 1, created_at: '2099-01-01T00:00:00.000Z' }), 'verified');
  assert.equal(verificationState({ verified: 0, created_at: '2026-09-21T00:00:00.000Z' }), 'grandfathered');
  assert.equal(verificationState({ verified: 0, created_at: '2026-09-23T00:00:00.000Z' }), 'unverified');
  assert.equal(verificationState(null), 'unknown');
  assert.equal(verificationState({ verified: 0 }), 'unknown', 'no date is not a date in the past');
  assert.equal(mayUseAccount(null), false, 'unknown must not open the door');
  assert.equal(mayUseAccount({ verified: 0 }), false);
});

await t('THE FOUR ACCOUNTS THE FOUNDER NAMED still work — by name, not by arithmetic', () => {
  // Their real created_at values, read from production on 2026-09-22. Every one is verified = 0.
  const live = {
    'signoutproof@vez.test': '2026-09-20T19:33:16.023Z',
    'test2@vez.test': '2026-09-21T09:42:28.090Z',
    'moozoonf@vez.test': '2026-09-22T09:59:20.124Z',
    'shiva@vez.test': '2026-09-22T09:59:23.020Z',
  };
  for (const [who, created_at] of Object.entries(live)) {
    assert.equal(mayUseAccount({ verified: 0, created_at }), true, `${who} would be locked out`);
    assert.equal(verificationState({ verified: 0, created_at }), 'grandfathered', who);
  }
  // And the founder's own, and the oldest rows.
  for (const created_at of ['2026-09-16T16:20:51.774Z', '2026-07-17T13:24:38.278Z']) {
    assert.equal(mayUseAccount({ verified: 0, created_at }), true);
  }
  // NEGATIVE: the cutoff must actually bite, or the four assertions above prove only that it never refuses.
  assert.equal(mayUseAccount({ verified: 0, created_at: VERIFY_REQUIRED_FROM }), false, 'an account created AT the cutoff is a new account');
});

await t('the cutoff is in the PAST and after every account that already existed', () => {
  const at = Date.parse(VERIFY_REQUIRED_FROM);
  assert.ok(Number.isFinite(at), `not a date: ${VERIFY_REQUIRED_FROM}`);
  // A cutoff in the FUTURE grandfathers everything made before it arrives — including the accounts made to
  // prove the gate works, which would sign in freely and show the opposite of what was being proved.
  assert.ok(at < Date.now(), `the cutoff has not happened yet (${VERIFY_REQUIRED_FROM}) — nothing is gated until it does`);
  // And after the newest row that existed when the decision was taken, or an existing account gets locked out.
  assert.ok(at > Date.parse('2026-09-22T09:59:23.020Z'), 'the cutoff predates shiva@vez.test, which would lock it out');
});

await t('how long to wait is said in the words a person uses, and never as a constant hour', () => {
  assert.equal(waitPhrase(4 * 60000), '4 minutes');
  assert.equal(waitPhrase(59 * 60000), '59 minutes');
  assert.equal(waitPhrase(60 * 60000), 'an hour');
  assert.equal(waitPhrase(3 * 60 * 60000), '3 hours');
  assert.equal(waitPhrase(30000), 'a minute');
  assert.equal(waitPhrase(0), 'a moment');
  assert.equal(waitPhrase(undefined), 'a moment', 'an unknown wait must not become "0 minutes"');
  assert.notEqual(waitPhrase(4 * 60000), waitPhrase(59 * 60000), 'two different waits must not read the same');
});

// ── one sender, not two ──────────────────────────────────────────────────────
await t('every code this server sends goes through ONE function — signup did not grow its own ceilings', () => {
  const src = readFileSync(resolve(HERE, '..', 'src', 'index.js'), 'utf8').split('\n').filter(l => !l.trim().startsWith('//')).join('\n');
  const senders = [...src.matchAll(/await sendCode\(/g)];
  assert.equal(senders.length, 1, `sendCode is called from ${senders.length} places — the ceilings would have to be kept in step`);
  const issuers = [...src.matchAll(/issueCode\(request, env,/g)];
  assert.ok(issuers.length >= 3, `expected the definition plus both callers, found ${issuers.length}`);
  // The chokepoint must still hold all three ceilings, or it is a chokepoint with nothing in it.
  const fn = src.slice(src.indexOf('async function issueCode'), src.indexOf('async function otpRequest'));
  for (const b of ['otp:global', 'otpip:', 'otp:${identifier}']) assert.ok(fn.includes(b), `the ${b} ceiling left the chokepoint`);
});

await t('no token is signed for an account that has not confirmed — counted at the call site', () => {
  const src = readFileSync(resolve(HERE, '..', 'src', 'index.js'), 'utf8').split('\n').filter(l => !l.trim().startsWith('//')).join('\n');
  const signings = [...src.matchAll(/signJwt\(\{ sub:/g)];
  assert.equal(signings.length, 3, `${signings.length} places sign a session — each one must be accounted for below`);
  assert.match(src, /if \(!mayUseAccount\(user\)\)/, 'login must refuse an unconfirmed account');
  assert.match(src, /SET pw_hash = \?, pw_salt = \?, pw_iter = \?, verified = 1/, 'a completed reset proves the address');
  assert.match(src, /UPDATE users SET verified = 1 WHERE id = \?/, 'otpVerify marks it');
  assert.doesNotMatch(src.slice(src.indexOf('async function signup'), src.indexOf('async function login')), /signJwt/, 'signup must not hand out a session any more');
});

// ── the routes ───────────────────────────────────────────────────────────────
let DatabaseSync;
try { ({ DatabaseSync } = await import('node:sqlite')); }
catch { console.log('\nNOTICE: node:sqlite unavailable — the route checks were SKIPPED (the rule checks above ran).'); console.log(`\nVERDICT: ${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0); }

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

const inbox = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  if (String(url).startsWith('https://api.resend.com/')) { inbox.push(JSON.parse(init.body)); return new Response('{"id":"em"}', { status: 200, headers: { 'content-type': 'application/json' } }); }
  return realFetch(url, init);
};
const codeOf = m => (m.text.match(/^\s*(\d{6})\s*$/m) || [])[1];
const post = async (path, body) => {
  const res = await worker.fetch(new Request(`https://api.test${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }), env);
  return { status: res.status, body: await res.json() };
};

const NEW = 'brand-new@vezvezak.com';
const PW = 'newuserpass26';

await t('SIGN-UP sends the code and hands back NO session', async () => {
  const before = inbox.length;
  const r = await post('/auth/signup', { identifier: NEW, password: PW, name: 'New User' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.needsOtp, true);
  assert.equal(r.body.token, undefined, 'a token here WOULD BE the account working, which is what must wait');
  assert.equal(inbox.length, before + 1, 'the code must actually be sent');
  assert.match(inbox[inbox.length - 1].subject, /verification code/i);
  assert.equal(db.prepare('SELECT verified FROM users WHERE identifier = ?').get(NEW).verified, 0);
});

await t('and the account CANNOT be signed into until it is confirmed — with its own reason, not "wrong password"', async () => {
  const r = await post('/auth/login', { identifier: NEW, password: PW });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(r.body.reason, 'email_unverified');
  assert.doesNotMatch(r.body.error, /incorrect/i, 'the password was right — saying otherwise sends them to reset it for nothing');
});

await t('a WRONG code is refused, and says so', async () => {
  const r = await post('/auth/otp/verify', { identifier: NEW, code: '000000', purpose: 'signup' });
  assert.notEqual(r.status, 200);
  assert.match(r.body.error, /not correct/i);
  assert.equal(db.prepare('SELECT verified FROM users WHERE identifier = ?').get(NEW).verified, 0);
});

await t('RESEND gives a new code, and the OLD one is then refused', async () => {
  const first = codeOf(inbox[inbox.length - 1]);
  const r = await post('/auth/otp/request', { identifier: NEW, purpose: 'signup' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const second = codeOf(inbox[inbox.length - 1]);
  assert.notEqual(first, second, 'a resend that returns the same code is not a resend');
  const old = await post('/auth/otp/verify', { identifier: NEW, code: first, purpose: 'signup' });
  assert.notEqual(old.status, 200, 'only the newest code may work');
});

await t('the code CONFIRMS the account, and only then does the password work', async () => {
  const r = await post('/auth/otp/verify', { identifier: NEW, code: codeOf(inbox[inbox.length - 1]), purpose: 'signup' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.token, 'confirming is what hands over the session sign-up withheld');
  assert.equal(db.prepare('SELECT verified FROM users WHERE identifier = ?').get(NEW).verified, 1);
  const login = await post('/auth/login', { identifier: NEW, password: PW });
  assert.equal(login.status, 200, JSON.stringify(login.body));
});

await t('a code already used cannot be reused', async () => {
  const used = codeOf(inbox[inbox.length - 1]);
  const r = await post('/auth/otp/verify', { identifier: NEW, code: used, purpose: 'signup' });
  assert.notEqual(r.status, 200);
});

await t('an EXPIRED code is refused, and says it expired rather than that it is wrong', async () => {
  const WHO = 'expiry@vezvezak.com';
  await post('/auth/signup', { identifier: WHO, password: 'expirypass26' });
  const code = codeOf(inbox[inbox.length - 1]);
  db.prepare('UPDATE otp_codes SET expires_at = ? WHERE identifier = ?').run(Date.now() - 1000, WHO);
  const r = await post('/auth/otp/verify', { identifier: WHO, code, purpose: 'signup' });
  assert.notEqual(r.status, 200);
  assert.match(r.body.error, /expired/i, `an expired code must not read as a wrong one: "${r.body.error}"`);
});

await t('RESENDING TOO OFTEN is refused with the REAL wait, not a constant hour', async () => {
  const WHO = 'ratelimit@vezvezak.com';
  await post('/auth/signup', { identifier: WHO, password: 'ratepass2609' });   // 1st of 5
  let last;
  for (let i = 0; i < 6; i++) last = await post('/auth/otp/request', { identifier: WHO, purpose: 'signup' });
  assert.equal(last.status, 429, JSON.stringify(last.body));
  assert.equal(last.body.reason, 'otp_rate_identifier');
  assert.ok(Number.isFinite(last.body.retryAfterMs) && last.body.retryAfterMs > 0, 'the app cannot count down what it is not told');
  assert.match(last.body.error, /wait \d+ minutes|wait an hour|wait a minute/i, `a real wait, not a constant: "${last.body.error}"`);

  // THE PROOF THAT IT IS COMPUTED, not merely correct once. Asking again immediately gives ~an hour, which is
  // also what the old constant said — so the window is wound forward and the sentence must MOVE with it. Without
  // this, "Please wait an hour" would pass while still being a constant.
  const firstWait = last.body.retryAfterMs;
  db.prepare("UPDATE rate_limits SET window_at = window_at - ? WHERE bucket LIKE '%'").run(50 * 60 * 1000);
  const later = await post('/auth/otp/request', { identifier: WHO, purpose: 'signup' });
  assert.equal(later.status, 429, JSON.stringify(later.body));
  assert.ok(later.body.retryAfterMs < firstWait - 40 * 60 * 1000,
    `the wait did not shrink as time passed: ${firstWait}ms then ${later.body.retryAfterMs}ms`);
  assert.match(later.body.error, /wait \d+ minutes/i, `after 50 minutes it must read in minutes, not "an hour": "${later.body.error}"`);
  assert.notEqual(later.body.error, last.body.error, 'two different waits must not read the same');
});

await t('A GRANDFATHERED account signs in with nothing asked of it', async () => {
  const OLD = 'grandfathered@vezvezak.com';
  const iso = '2026-09-01T00:00:00.000Z';
  const { hash, salt, iter } = await (await import('../src/lib.js')).hashPassword('oldpass2609');
  db.prepare('INSERT INTO users (id, identifier, channel, pw_hash, pw_salt, pw_iter, verified, created_at) VALUES (?,?,?,?,?,?,0,?)')
    .run('usr_old', OLD, 'email', hash, salt, iter, iso);
  const r = await post('/auth/login', { identifier: OLD, password: 'oldpass2609' });
  assert.equal(r.status, 200, `an account that existed before we asked must not be locked out: ${JSON.stringify(r.body)}`);
  assert.ok(r.body.token);
});

await t('a password RESET also confirms the address — no session past a gate that then closes', async () => {
  const WHO = 'resetconfirms@vezvezak.com';
  await post('/auth/signup', { identifier: WHO, password: 'firstpass2609' });
  await post('/auth/otp/request', { identifier: WHO, purpose: 'reset' });
  const v = await post('/auth/otp/verify', { identifier: WHO, code: codeOf(inbox[inbox.length - 1]), purpose: 'reset' });
  assert.ok(v.body.resetToken, JSON.stringify(v.body));
  const r = await post('/auth/password/reset', { identifier: WHO, resetToken: v.body.resetToken, password: 'secondpass2609' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(db.prepare('SELECT verified FROM users WHERE identifier = ?').get(WHO).verified, 1,
    'they read a code we sent to that address — that IS the proof verification asks for');
  const login = await post('/auth/login', { identifier: WHO, password: 'secondpass2609' });
  assert.equal(login.status, 200, 'and the next sign-in must not refuse what the reset just proved');
});

await t('an account left unconfirmed is NOT deleted — there is no job that could', () => {
  const src = readFileSync(resolve(HERE, '..', 'src', 'index.js'), 'utf8');
  const toml = readFileSync(resolve(HERE, '..', 'wrangler.toml'), 'utf8');
  assert.doesNotMatch(src, /async scheduled\s*\(/, 'if a scheduled handler appears, what it deletes must be described before it runs');
  assert.doesNotMatch(toml, /\[triggers\]|crons\s*=/, 'no cron is configured, so no promise about "after N days" could be kept');
  // So the copy must not make one. Checked in the app's dictionary by the client-side test.
});

globalThis.fetch = realFetch;
console.log(`\nVERDICT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
