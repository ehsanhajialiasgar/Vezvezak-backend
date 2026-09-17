// Part 1b behavioral proof (Ehsan 2026-08-13): a weekly CAP counts whole SEARCHES,
// not API calls. Runs the REAL searchConsume against an in-memory SQLite loaded
// from schema.sql, so "a Pro 18-cap is 18 real searches, not 9" is proven, not
// asserted from source. Self-skips where node:sqlite isn't available (e.g. Node 22
// CI without --experimental-sqlite) — the source/schema gates in weeklyCaps cover
// the structure there.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

let DatabaseSync;
try { ({ DatabaseSync } = await import('node:sqlite')); }
catch { console.log('\nNOTICE: node:sqlite unavailable — dedupe integration test skipped (structure covered by weeklyCaps.test.mjs).'); process.exit(0); }

const { signJwt, bucketSubject } = await import('../src/lib.js');
const { SEARCH_DAILY_CEILING } = await import('../src/usage.js');
const { searchConsume } = await import('../src/index.js');

const HERE = dirname(fileURLToPath(import.meta.url));
const db = new DatabaseSync(':memory:');
db.exec(readFileSync(resolve(HERE, '..', 'schema.sql'), 'utf8'));

// Thin D1 shim over node:sqlite: prepare().bind().first()/run() with a D1-shaped result.
function makeD1(database) {
  return {
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
  };
}

const env = { DB: makeD1(db), JWT_SECRET: 'test-secret' };
const iso = new Date().toISOString();
// A PAID ROW NOW NEEDS A FUTURE EXPIRY (ledger 1.2, fixed 2026-09-14). This fixture used to insert
// ('usr_pro', 'pro') with no expiry, and it went RED the moment planFor() started refusing paid rows without
// one — correctly: a paid plan with no expiry is exactly the never-expiring plan 1.2 described. The fixture
// recorded the defect as a normal Pro user. It now carries a real expiry, and a second, EXPIRED Pro user is
// added so the rule is asserted behaviourally against the real schema, not only in iap.test.mjs's fake DB.
const future = new Date(Date.now() + 30 * 86_400_000).toISOString();
const past = new Date(Date.now() - 86_400_000).toISOString();
db.prepare('INSERT INTO user_plans (user_id, plan, expires_at, source, updated_at) VALUES (?,?,?,?,?)').run('usr_pro', 'pro', future, 'apple', iso);
db.prepare('INSERT INTO user_plans (user_id, plan, expires_at, source, updated_at) VALUES (?,?,?,?,?)').run('usr_pro_expired', 'pro', past, 'apple', iso);
db.prepare('INSERT INTO user_plans (user_id, plan, updated_at) VALUES (?,?,?)').run('usr_free', 'free', iso);

async function call(token, body) {
  const req = {
    headers: { get: (k) => (k.toLowerCase() === 'authorization' ? (token ? `Bearer ${token}` : null) : null) },
    json: async () => body,
  };
  const res = await searchConsume(req, env);
  return { status: res.status, body: await res.json() };
}
const localUsed = (uid) => db.prepare('SELECT local_used FROM weekly_search_usage WHERE user_id=?').get(uid)?.local_used ?? 0;
const onlineUsed = (uid) => db.prepare('SELECT online_used FROM weekly_search_usage WHERE user_id=?').get(uid)?.online_used ?? 0;

let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

const pro = await signJwt({ sub: 'usr_pro', identifier: 'x' }, env.JWT_SECRET);
const free = await signJwt({ sub: 'usr_free', identifier: 'y' }, env.JWT_SECRET);
const expiredPro = await signJwt({ sub: 'usr_pro_expired', identifier: 'z' }, env.JWT_SECRET);

await t('an EXPIRED Pro subscription gets FREE caps, not paid ones, against the real schema', async () => {
  // Was "refused a local slot" — true only while the free local cap was 0. The rule being asserted is not
  // "refused", it is "treated as free": since 2026-09-17 free has 1 local search a week, so an expired Pro gets
  // exactly that one and is refused the second. A test that read the old number would have quietly become a test
  // that an expired plan gets nothing at all, which is not the rule.
  const first = await call(expiredPro, { kind: 'local', searchId: 'sid-expired-1' });
  assert.equal(first.status, 200, 'an expired Pro is a free user, and a free user has one local search');
  assert.equal(first.body.plan, 'free', 'the plan reported must be free, never the expired paid one');
  assert.equal(first.body.cap, 1, 'and the cap must be the FREE cap, not Pro\'s 18');
  const second = await call(expiredPro, { kind: 'local', searchId: 'sid-expired-2' });
  assert.equal(second.status, 402, 'the second must be refused — an expired plan never gets paid caps');
  assert.equal(localUsed('usr_pro_expired'), 1, 'exactly one slot counted against the expired account');
});

console.log('\nOne search bundle collapses into ONE slot (Text + Nearby share a vz_sid)');
await t('two sub-calls of the same vz_sid consume exactly one local slot', async () => {
  const a = await call(pro, { kind: 'local', searchId: 'S1' });   // Text
  const b = await call(pro, { kind: 'local', searchId: 'S1' });   // Nearby (same bundle)
  assert.equal(a.body.allowed, true);
  assert.equal(a.body.used, 1);
  assert.equal(b.body.allowed, true);
  assert.equal(b.body.idempotent, true, 'the second sub-call must be idempotent');
  assert.equal(localUsed('usr_pro'), 1, 'ONE bundle = ONE slot (not two)');
});
await t('a distinct vz_sid consumes a second slot', async () => {
  await call(pro, { kind: 'local', searchId: 'S2' });
  assert.equal(localUsed('usr_pro'), 2);
});

console.log('\nThe Pro 18 local cap is 18 real searches — then refused');
await t('searches 3..18 allowed, the 19th distinct search is refused', async () => {
  for (let i = 3; i <= 18; i++) {
    const r = await call(pro, { kind: 'local', searchId: 'S' + i });
    assert.equal(r.body.allowed, true, `search ${i} should be allowed`);
  }
  assert.equal(localUsed('usr_pro'), 18, 'exactly 18 slots used across 18 bundles');
  const over = await call(pro, { kind: 'local', searchId: 'S19' });
  assert.equal(over.status, 402);
  assert.equal(over.body.reason, 'cap_reached');
  assert.equal(localUsed('usr_pro'), 18, 'a refused search must NOT increment');
});

console.log('\nPhoto sub-call ceiling (6 per search, and only under a consumed slot)');
await t('up to 6 photos ride under a consumed local bundle; the 7th is refused', async () => {
  for (let i = 1; i <= 6; i++) {
    const p = await call(pro, { kind: 'photo', searchId: 'S1' });
    assert.equal(p.body.allowed, true, `photo ${i} should be allowed`);
  }
  const p7 = await call(pro, { kind: 'photo', searchId: 'S1' });
  assert.equal(p7.status, 402);
  assert.equal(p7.body.reason, 'photo_ceiling_or_no_search');
});
await t('a photo for a made-up search id (no consumed slot) is refused', async () => {
  const p = await call(pro, { kind: 'photo', searchId: 'NEVER_SEARCHED' });
  assert.equal(p.status, 402);
});

console.log('\nFree tier: a REAL weekly searches, and a real wall at the end of it (1 local + 5 online, 2026-09-17)');
await t('free gets its one local search, and the second is refused', async () => {
  const first = await call(free, { kind: 'local', searchId: 'F1' });
  assert.equal(first.status, 200, 'free must get its one live local search');
  assert.equal(first.body.remaining, 0, 'and it is the only one this week');
  const second = await call(free, { kind: 'local', searchId: 'F2' });
  assert.equal(second.status, 402, 'the second local search of the week must be refused');
  assert.equal(second.body.reason, 'cap_reached');
});
await t('free gets five online searches, and the sixth is refused', async () => {
  for (let i = 1; i <= 5; i++) {
    const r = await call(free, { kind: 'online', searchId: `FO${i}` });
    assert.equal(r.status, 200, `free online search ${i} must be allowed`);
    assert.equal(r.body.remaining, 5 - i, `remaining after online search ${i}`);
  }
  const sixth = await call(free, { kind: 'online', searchId: 'FO6' });
  assert.equal(sixth.status, 402, 'the sixth online search of the week must be refused');
  assert.equal(sixth.body.reason, 'cap_reached');
});
await t('a free bundle still dedupes: the same vz_sid does not spend a second slot', async () => {
  const again = await call(free, { kind: 'local', searchId: 'F1' });
  assert.equal(again.status, 200, 'the same bundle must be allowed through');
  assert.equal(again.body.idempotent, true, 'and must not take a second slot');
});
console.log('\nGLOBAL DAILY CEILING — the blast brake that ships with the free weekly count (2026-09-17)');
await t('at the global daily ceiling the search is refused 429, no slot spent, no row left behind', async () => {
  // Seed the global bucket at its ceiling — the same row rateLimit() would have written after
  // SEARCH_DAILY_CEILING.online searches in 24h, for every account together.
  const bucket = `search:online:${await bucketSubject('global', env)}`;
  db.prepare('INSERT OR REPLACE INTO rate_limits (bucket, count, window_at) VALUES (?, ?, ?)')
    .run(bucket, SEARCH_DAILY_CEILING.online, Date.now());
  const before = onlineUsed('usr_pro');
  const r = await call(pro, { kind: 'online', searchId: 'CEIL1' });
  assert.equal(r.status, 429, 'over the global ceiling the answer is 429, not the user cap 402');
  assert.equal(r.body.reason, 'search_ceiling_global', 'and it says the SERVICE is busy, not that the user is out');
  assert.equal(onlineUsed('usr_pro'), before, 'no slot may be counted for a search that never happened');
  const rows = db.prepare('SELECT COUNT(*) c FROM consumed_searches WHERE search_id = ?').get('CEIL1');
  assert.equal(rows.c, 0, 'the dedupe row must be undone, or a retry after the window reads as already-consumed');
  db.prepare('DELETE FROM rate_limits WHERE bucket = ?').run(bucket);
});
await t('with the ceiling cleared the same search goes through', async () => {
  const r = await call(pro, { kind: 'online', searchId: 'CEIL1' });
  assert.equal(r.status, 200, 'the refusal must not have poisoned the bundle id');
  assert.equal(r.body.idempotent, undefined, 'and it takes its slot now, for the first time');
});

await t('unauthenticated consume is refused (401)', async () => {
  const r = await call(null, { kind: 'online', searchId: 'Z1' });
  assert.equal(r.status, 401);
});

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
