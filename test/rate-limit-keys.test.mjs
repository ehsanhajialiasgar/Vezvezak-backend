// RATE-LIMIT KEYS HOLD NO IDENTIFIER; EXPIRED COUNTERS ARE REMOVED (Ehsan 2026-09-15).
// rate_limits stored `login:<email>` / `otp:<phone>` in plain text, rows were never removed (only overwritten), and the
// accountDelete comment claimed they "self-expire". Proven here against the real rateLimit with a recording DB.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { rateLimit, bucketSubject, RATE_LIMIT_MAX_WINDOW_MS } from '../src/lib.js';

let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

function recordingDb() {
  const rows = new Map(); const log = [];
  return {
    rows, log,
    prepare(sql) {
      let b = [];
      const api = {
        bind(...a) { b = a; return api; },
        async first() { log.push([sql, b]); const r = rows.get(b[0]); return r ? { ...r } : null; },
        async run() {
          log.push([sql, b]);
          if (/^DELETE FROM rate_limits WHERE window_at < \?/.test(sql)) { for (const [k, r] of rows) if (r.window_at < b[0]) rows.delete(k); }
          else if (/^INSERT INTO rate_limits/.test(sql)) rows.set(b[0], { count: 1, window_at: b[1] });
          else if (/^UPDATE rate_limits SET count = count \+ 1/.test(sql)) rows.get(b[0]).count++;
          return {};
        },
      };
      return api;
    },
  };
}
const env = (db) => ({ DB: db, JWT_SECRET: 'test-secret' });

await t('no email, phone or id is ever bound into a rate_limits statement', async () => {
  const db = recordingDb();
  await rateLimit(env(db), 'login:alice.smith@example.com', 10, 15 * 60 * 1000);
  await rateLimit(env(db), 'otp:+15551234567', 5, 60 * 60 * 1000);
  await rateLimit(env(db), 'comp:user:usr_123', 10, 60 * 60 * 1000);
  const bound = db.log.flatMap(([, b]) => b).filter(v => typeof v === 'string').join(' ');
  assert.ok(!/alice|5551234567|usr_123/.test(bound), `plaintext bound: ${bound}`);
  assert.ok([...db.rows.keys()].includes('login:' + await bucketSubject('alice.smith@example.com', env(db))), 'prefix kept, subject hashed');
  assert.ok([...db.rows.keys()].includes('comp:user:' + await bucketSubject('usr_123', env(db))), 'split at the LAST colon');
});

await t('a window reset removes counters older than the longest window; fresh ones stay', async () => {
  const db = recordingDb();
  db.rows.set('login:OLD', { count: 3, window_at: Date.now() - RATE_LIMIT_MAX_WINDOW_MS - 1000 });
  db.rows.set('login:FRESH', { count: 3, window_at: Date.now() - 60_000 });
  await rateLimit(env(db), 'signup:x', 10, 60 * 60 * 1000);
  assert.ok(!db.rows.has('login:OLD'), 'expired counter removed');
  assert.ok(db.rows.has('login:FRESH'), 'live counter kept');
});

await t('the limit still limits', async () => {
  const db = recordingDb();
  for (let i = 0; i < 3; i++) assert.equal((await rateLimit(env(db), 'otp:p', 3, 60_000)).allowed, true);
  assert.equal((await rateLimit(env(db), 'otp:p', 3, 60_000)).allowed, false);
});

await t('every rateLimit caller uses a window within RATE_LIMIT_MAX_WINDOW_MS (derived from source)', async () => {
  const src = ['src/index.js', 'src/comp.js'].map(f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8')).join('\n');
  const consts = Object.fromEntries([...src.matchAll(/const ([A-Z_]+) = ([\d_ *]+);/g)].map(m => [m[1], m[2]]));
  const calls = [...src.matchAll(/rateLimit\(env,[^;]*?,\s*[\w.]+\s*,\s*([^)]+)\)/g)].map(m => m[1].trim());
  assert.ok(calls.length >= 10, `COULD NOT VERIFY — ${calls.length} calls derived`);
  for (const w of calls) {
    const expr = (consts[w] ?? w).replace(/_/g, '');
    assert.match(expr, /^[\d *]+$/, `window not a numeric literal: ${w}`);
    const ms = Function(`return (${expr})`)();
    assert.ok(ms > 0 && ms <= RATE_LIMIT_MAX_WINDOW_MS, `window ${w} = ${ms} exceeds the purge bound`);
  }
  console.log(`     field of view: ${calls.length} rateLimit calls`);
});

await t('rateLimit refuses a window longer than the purge bound', async () => {
  await assert.rejects(() => rateLimit(env(recordingDb()), 'x:y', 1, RATE_LIMIT_MAX_WINDOW_MS + 1), /exceeds RATE_LIMIT_MAX_WINDOW_MS/);
});

await t('the false "self-expire" comment is gone', () => {
  assert.ok(!/self-expire too/.test(readFileSync(new URL('../src/index.js', import.meta.url), 'utf8')));
});

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
