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
  // usage.js JOINED THE FIELD OF VIEW (Ehsan 2026-09-19). A window passed as a named constant declared in
  // another module read as "not a numeric literal" and failed the build — the gate could not SEE the value, so it
  // ruled on an absence. It resolves the constant instead: still no unknown expression is ever accepted, and a
  // window that genuinely exceeds the purge bound still fails, wherever its constant lives.
  const FILES = ['src/index.js', 'src/comp.js', 'src/usage.js'];
  const src = FILES.map(f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8')).join('\n');
  const consts = Object.fromEntries([...src.matchAll(/(?:export )?const ([A-Z_]+) = ([\d_ *]+);/g)].map(m => [m[1], m[2]]));
  const calls = [...src.matchAll(/rateLimit\(env,[^;]*?,\s*[\w.]+\s*,\s*([^)]+)\)/g)].map(m => m[1].trim());
  assert.ok(calls.length >= 10, `COULD NOT VERIFY — ${calls.length} calls derived`);
  for (const w of calls) {
    const expr = (consts[w] ?? w).replace(/_/g, '');
    assert.match(expr, /^[\d *]+$/, `window not a numeric literal: ${w}`);
    const ms = Function(`return (${expr})`)();
    assert.ok(ms > 0 && ms <= RATE_LIMIT_MAX_WINDOW_MS, `window ${w} = ${ms} exceeds the purge bound`);
  }
  console.log(`     field of view: ${calls.length} rateLimit calls over ${FILES.length} files`);
});

await t('no rateLimit BUCKET puts an identifier before its last colon (derived from every call site)', async () => {
  // THE TEST ABOVE DID NOT CATCH THIS, and it was written to (Ehsan 2026-09-19). "no email, phone or id is ever
  // bound" drives rateLimit with three hand-written buckets and proves the MECHANISM hashes a subject. It says
  // nothing about the buckets the code actually builds — and storedBucket splits at the LAST colon, so a key like
  // `sid:${userId}:${searchId}:${kind}` hashes only "local" and writes the account id and the raw search id into
  // rate_limits in plaintext. That is precisely the defect removed from login:/otp: on 2026-09-15, and it came
  // back the moment a new key looked tidier with colons in it.
  //
  // Derived from every call site, so a future key cannot reintroduce it: everything an interpolation could
  // identify must sit AFTER the last colon, where storedBucket hashes it.
  const src = ['src/index.js', 'src/comp.js'].map(f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8')).join('\n');
  const usage = readFileSync(new URL('../src/usage.js', import.meta.url), 'utf8');

  // NOT AN EXCEPTION LIST. One real key interpolates before its last colon — `search:${kind}:global` — and it is
  // not a leak, because `kind` can only ever be one of two fixed words. Rather than writing that key down as an
  // allowed instance, the rule asks the question that makes it safe: is this variable's RANGE a closed vocabulary
  // of literals, and is it checked against that vocabulary before use? Anything whose range we cannot bound that
  // way is treated as identifying, which is the safe reading for a value we cannot see.
  const closed = new Set();
  for (const m of usage.matchAll(/export const (\w+) = new Set\(\[([^\]]*)\]\)/g)) {
    if (/^[\s'\w,]*$/.test(m[2])) closed.add(m[1]);      // a set of plain string literals
  }
  const boundedNames = new Set();
  for (const name of closed) {
    for (const m of src.matchAll(new RegExp(`${name}\\.has\\((\\w+)\\)`, 'g'))) boundedNames.add(m[1]);
  }

  const buckets = [...src.matchAll(/rateLimit\(env,\s*(`[^`]+`|'[^']+')/g)].map(m => m[1]);
  assert.ok(buckets.length >= 10, `COULD NOT VERIFY — ${buckets.length} buckets derived`);
  const leaking = [];
  for (const b of buckets) {
    const body = b.slice(1, -1);
    const at = body.lastIndexOf(':');
    if (at < 0) { leaking.push(`${b} — no colon at all, so storedBucket hashes the whole key as one subject`); continue; }
    const prefix = body.slice(0, at);
    for (const m of prefix.matchAll(/\$\{([^}]+)\}/g)) {
      const expr = m[1].trim();
      if (boundedNames.has(expr)) continue;               // range proven closed, and checked against it
      leaking.push(`${b} — \${${expr}} sits before the last colon and is stored in PLAINTEXT`);
    }
  }
  assert.deepEqual(leaking, [], `a rate_limits key would store an identifier in the clear:\n${leaking.join('\n')}`);
  console.log(`     field of view: ${buckets.length} rateLimit buckets; ${boundedNames.size} name(s) proven closed-vocabulary`);
});

await t('rateLimit refuses a window longer than the purge bound', async () => {
  await assert.rejects(() => rateLimit(env(recordingDb()), 'x:y', 1, RATE_LIMIT_MAX_WINDOW_MS + 1), /exceeds RATE_LIMIT_MAX_WINDOW_MS/);
});

await t('the false "self-expire" comment is gone', () => {
  assert.ok(!/self-expire too/.test(readFileSync(new URL('../src/index.js', import.meta.url), 'utf8')));
});

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
