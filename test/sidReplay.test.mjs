// ONE vz_sid MUST NOT BUY AN UNBOUNDED WEEK (Ehsan 2026-09-19).
//
// searchId arrives in the request body and the client builds it unsigned. Once a bundle's row existed, every later
// call with that id returned allowed:true — the comment said "cap or no cap" and meant it — and the global daily
// ceiling sits BELOW that return, so neither guard was on the path. A client holding one id constant got unlimited
// billable searches for the rest of the week. That is the free tier's entire cap, bypassed by a loop.
//
// The idempotent allow itself is correct and must survive here: removing it is what served the last search of
// every week half (a bundle's second sub-call arrived with used === cap and was refused). These tests pin BOTH —
// a granted bundle still finishes, and it cannot finish forever.
// Self-skips where node:sqlite is unavailable. Run: node test/sidReplay.test.mjs
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

let DatabaseSync;
try { ({ DatabaseSync } = await import('node:sqlite')); }
catch { console.log('\nNOTICE: node:sqlite unavailable — vz_sid replay test skipped.'); process.exit(0); }

const { signJwt } = await import('../src/lib.js');
const { SEARCH_SUBCALLS_PER_SLOT, SEARCH_BUNDLE_TTL_MS, WEEKLY_CAPS } = await import('../src/usage.js');
const worker = (await import('../src/index.js')).default;
const HERE = dirname(fileURLToPath(import.meta.url));

function fresh() {
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync(resolve(HERE, '..', 'schema.sql'), 'utf8'));
  const d1 = {
    prepare(sql) {
      const stmt = db.prepare(sql);
      let bound = [];
      const api = {
        bind(...a) { bound = a; return api; },
        async first() { const r = stmt.get(...bound); return r === undefined ? null : r; },
        async run() { const r = stmt.run(...bound); return { meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid) } }; },
        async all() { return { results: stmt.all(...bound) }; },
      };
      return api;
    },
  };
  db.prepare('INSERT INTO users (id, identifier, channel, pw_hash, pw_salt, created_at) VALUES (?,?,?,?,?,?)')
    .run('usr_r1', 'r@x.co', 'email', 'h', 's', new Date().toISOString());
  return { db, env: { DB: d1, JWT_SECRET: 'test-secret' } };
}

const consume = async (env, token, body) => worker.fetch(new Request('https://api/search/consume', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
  body: JSON.stringify(body),
}), env);

const tokenFor = env => signJwt({ sub: 'usr_r1' }, env.JWT_SECRET, 3600);

test('a granted bundle still finishes — the half-served-search fix is not undone', async () => {
  const { env } = fresh();
  const t = await tokenFor(env);
  // Free is 1 local. The FIRST sub-call takes the only slot; the SECOND must still be served.
  assert.equal(WEEKLY_CAPS.free.local, 1, 'this test is written against a 1-local free tier');
  const a = await consume(env, t, { kind: 'local', searchId: 'sid-A' });
  assert.equal(a.status, 200);
  assert.equal((await a.json()).allowed, true);
  const b = await consume(env, t, { kind: 'local', searchId: 'sid-A' });
  assert.equal(b.status, 200, 'the second sub-call of a granted bundle must not be refused');
  const jb = await b.json();
  assert.equal(jb.allowed, true);
  assert.equal(jb.idempotent, true);
});

test('THE HOLE: one id replayed cannot buy an unbounded week', async () => {
  const { env } = fresh();
  const t = await tokenFor(env);
  await consume(env, t, { kind: 'local', searchId: 'sid-B' });   // takes the slot
  let allowed = 1;
  let refusal = null;
  for (let i = 0; i < 200; i++) {
    const r = await consume(env, t, { kind: 'local', searchId: 'sid-B' });
    if (r.status === 200 && (await r.json()).allowed) { allowed++; continue; }
    refusal = r;
    break;
  }
  assert.ok(refusal, `replay was never refused — ${allowed} billable calls granted on ONE slot`);
  // Bounded, and bounded SMALL: the slot itself plus the sub-call allowance, nothing more.
  assert.ok(allowed <= 1 + SEARCH_SUBCALLS_PER_SLOT,
    `${allowed} calls rode one slot; the bound is ${1 + SEARCH_SUBCALLS_PER_SLOT}`);
  const body = await refusal.json();
  assert.ok(/subcalls_exhausted|bundle_closed/.test(body.reason || ''), `unexpected refusal: ${JSON.stringify(body)}`);
});

test('a refused replay does NOT take the slot away — the user keeps what they paid for', async () => {
  const { db, env } = fresh();
  const t = await tokenFor(env);
  await consume(env, t, { kind: 'local', searchId: 'sid-C' });
  for (let i = 0; i < SEARCH_SUBCALLS_PER_SLOT + 3; i++) await consume(env, t, { kind: 'local', searchId: 'sid-C' });
  const row = db.prepare('SELECT COUNT(*) AS n FROM consumed_searches WHERE user_id = ? AND search_id = ?').get('usr_r1', 'sid-C');
  assert.equal(row.n, 1, 'the bundle row must survive a refusal — undoing it would give the slot back for free');
  const usage = db.prepare('SELECT local_used FROM weekly_search_usage WHERE user_id = ?').get('usr_r1');
  assert.equal(usage.local_used, 1, 'exactly one slot was spent');
});

test('a stale bundle is closed for good — a replayer cannot come back to it tomorrow', async () => {
  const { db, env } = fresh();
  const t = await tokenFor(env);
  await consume(env, t, { kind: 'local', searchId: 'sid-D' });
  // Age the bundle past the TTL, exactly as a clock would.
  const old = new Date(Date.now() - SEARCH_BUNDLE_TTL_MS - 60_000).toISOString();
  db.prepare('UPDATE consumed_searches SET created_at = ? WHERE search_id = ?').run(old, 'sid-D');
  const r = await consume(env, t, { kind: 'local', searchId: 'sid-D' });
  assert.notEqual(r.status, 200, 'a bundle older than the TTL must not ride on');
  assert.equal((await r.json()).reason, 'search_bundle_closed');
});

test('an unreadable timestamp fails CLOSED, not open', async () => {
  const { db, env } = fresh();
  const t = await tokenFor(env);
  await consume(env, t, { kind: 'local', searchId: 'sid-E' });
  db.prepare('UPDATE consumed_searches SET created_at = ? WHERE search_id = ?').run('not-a-date', 'sid-E');
  const r = await consume(env, t, { kind: 'local', searchId: 'sid-E' });
  assert.notEqual(r.status, 200, 'an age we cannot verify is not evidence of freshness');
});

test('a NEW id still costs a slot, so replay has no cheaper cousin', async () => {
  const { env } = fresh();
  const t = await tokenFor(env);
  await consume(env, t, { kind: 'local', searchId: 'sid-F1' });
  const second = await consume(env, t, { kind: 'local', searchId: 'sid-F2' });
  assert.equal(second.status, 402, 'a second bundle on a 1-local plan must hit the cap');
  assert.equal((await second.json()).reason, 'cap_reached');
});
