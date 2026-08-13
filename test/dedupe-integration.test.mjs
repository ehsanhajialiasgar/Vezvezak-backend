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

const { signJwt } = await import('../src/lib.js');
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
db.prepare('INSERT INTO user_plans (user_id, plan, updated_at) VALUES (?,?,?)').run('usr_pro', 'pro', iso);
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

let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

const pro = await signJwt({ sub: 'usr_pro', identifier: 'x' }, env.JWT_SECRET);
const free = await signJwt({ sub: 'usr_free', identifier: 'y' }, env.JWT_SECRET);

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

console.log('\nFree tier: zero local (Google Places), online allowed up to 3');
await t('free local is always refused (cap 0); free online is allowed', async () => {
  const l = await call(free, { kind: 'local', searchId: 'F1' });
  assert.equal(l.status, 402, 'free local must be refused — no Google Places');
  const o = await call(free, { kind: 'online', searchId: 'F1' });
  assert.equal(o.body.allowed, true, 'free online (SerpApi) is allowed within the cap');
});
await t('unauthenticated consume is refused (401)', async () => {
  const r = await call(null, { kind: 'online', searchId: 'Z1' });
  assert.equal(r.status, 401);
});

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
