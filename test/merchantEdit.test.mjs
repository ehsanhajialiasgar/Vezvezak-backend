// A MERCHANT MUST BE ABLE TO CORRECT WHAT THEY TYPED, AND A REFUSAL MUST NAME ITS REASON (Ehsan 2026-09-22).
//
// Found by walking the seller flow on a device, not by reading code:
//   1. "Business info" (Merchant Hub → Settings) opened an EMPTY creation wizard. There was no edit path at all,
//      so an address with a typo in it was permanent. /merchants/mine did not even return the address, so no
//      screen could have shown it back.
//   2. Re-submitting the same store name hit the UNIQUE index added by D2. The worker threw, Cloudflare answered
//      HTTP 500 `error code: 1101` with no JSON, and the app told the merchant "That couldn't be saved on this
//      device. Please try again" — the device blamed for a server rule, and a retry that can never succeed.
//   3. D1 made the writer bind 'live', but the column DEFAULT is still 'pending'. An INSERT that omits the column
//      would quietly bring the dead state back, so the source is checked, not just the behaviour.
// Self-skips where node:sqlite is unavailable. Run: node test/merchantEdit.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = readFileSync(resolve(HERE, '..', 'src', 'index.js'), 'utf8');

let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

// ── 0 · the predicate, both directions ───────────────────────────────────────
const { isDuplicateStoreName } = await import('../src/index.js');
await t('a duplicate store name is recognised — and nothing else is', () => {
  const real = new Error('D1_ERROR: UNIQUE constraint failed: merchants.user_id, merchants.store_name: SQLITE_CONSTRAINT');
  assert.equal(isDuplicateStoreName(real), true, 'the error D1 actually returns must be recognised');
  assert.equal(isDuplicateStoreName({ cause: { message: real.message } }), true, 'including when it arrives wrapped in a cause');
  // NEGATIVE: another table's conflict must not be reported to the merchant as "you already have a store".
  assert.equal(isDuplicateStoreName(new Error('UNIQUE constraint failed: users.identifier')), false);
  assert.equal(isDuplicateStoreName(new Error('UNIQUE constraint failed: catalog_items.merchant_id, catalog_items.gtin')), false);
  assert.equal(isDuplicateStoreName(new Error('no such column: store_name')), false);
  assert.equal(isDuplicateStoreName(undefined), false);
});

// ── 1 · no INSERT may leave status to the DEFAULT ────────────────────────────
await t("no INSERT INTO merchants may omit status — the column's default is still the dead 'pending'", () => {
  const inserts = SRC.match(/INSERT INTO merchants[\s\S]*?VALUES/g) || [];
  assert.ok(inserts.length >= 1, 'there must be at least one INSERT to check — if this is 0 the check is blind');
  for (const ins of inserts) assert.match(ins, /\bstatus\b/, `an INSERT that omits status writes 'pending' again:\n${ins}`);
});

let DatabaseSync;
try { ({ DatabaseSync } = await import('node:sqlite')); }
catch {
  console.log('\nNOTICE: node:sqlite unavailable — the edit/duplicate integration checks were SKIPPED (the source checks above ran).');
  console.log(`\nVERDICT: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

const { signJwt } = await import('../src/lib.js');
const worker = (await import('../src/index.js')).default;

const db = new DatabaseSync(':memory:');
db.exec(readFileSync(resolve(HERE, '..', 'schema.sql'), 'utf8'));
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
db.prepare('INSERT INTO users (id, identifier, channel, pw_hash, pw_salt, created_at) VALUES (?,?,?,?,?,?)').run('usr_e1', 'a@x.co', 'email', 'h', 's', iso);
db.prepare('INSERT INTO users (id, identifier, channel, pw_hash, pw_salt, created_at) VALUES (?,?,?,?,?,?)').run('usr_e2', 'b@x.co', 'email', 'h', 's', iso);
const tokA = await signJwt({ sub: 'usr_e1', identifier: 'a@x.co' }, env.JWT_SECRET);
const tokB = await signJwt({ sub: 'usr_e2', identifier: 'b@x.co' }, env.JWT_SECRET);

const post = async (path, body, tok) => {
  const res = await worker.fetch(new Request(`https://api.test${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: `Bearer ${tok}` } : {}) },
    body: JSON.stringify(body),
  }), env);
  return { status: res.status, body: await res.json() };
};
const mine = async (tok) => (await (await worker.fetch(new Request('https://api.test/merchants/mine', { headers: { Authorization: `Bearer ${tok}` } }), env)).json()).merchants;

const BASE = { storeName: 'Moozoonf', address: '2855 Stevens Creek Blvd, Santa Clara, CA 95050', phone: '+1 408 555 0142', category: 'Electronics', sellerType: 'Retailer', saleChannel: 'both', radiusMiles: 28 };
let id;
await t('a first submission is created live', async () => {
  const r = await post('/merchants/submit', BASE, tokA);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  id = r.body.id;
  assert.equal(db.prepare('SELECT status FROM merchants WHERE id = ?').get(id).status, 'live');
});

await t('the merchant can READ BACK the address and phone they typed', async () => {
  const m = (await mine(tokA)).find(x => x.id === id);
  assert.ok(m, 'their own store must come back');
  assert.equal(m.address, BASE.address, 'the address was not returned at all before this change');
  assert.equal(m.phone, BASE.phone);
  assert.equal(m.radiusMiles, 28);
});

await t('submitting the same name again is refused with the REASON, not a 500', async () => {
  const r = await post('/merchants/submit', BASE, tokA);
  assert.equal(r.status, 409, `expected a named refusal, got ${r.status}: ${JSON.stringify(r.body)}`);
  assert.match(String(r.body.error), /already have a store with that name/i);
  assert.equal(db.prepare('SELECT COUNT(*) c FROM merchants WHERE user_id = ?').get('usr_e1').c, 1, 'and nothing may be written');
});

await t('a DIFFERENT owner may use the same name — the rule is one name per owner', async () => {
  const r = await post('/merchants/submit', BASE, tokB);
  assert.equal(r.status, 200, JSON.stringify(r.body));
});

await t('an owned merchantId EDITS the row instead of creating a second one', async () => {
  const fixed = { ...BASE, merchantId: id, address: '2855 Stevens Creek Blvd, Santa Clara, CA 95051', phone: '+1 408 555 0199' };
  const r = await post('/merchants/submit', fixed, tokA);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.id, id, 'the same store, not a new one');
  assert.equal(db.prepare('SELECT COUNT(*) c FROM merchants WHERE user_id = ?').get('usr_e1').c, 1, 'still exactly one store');
  const row = db.prepare('SELECT address, phone, status FROM merchants WHERE id = ?').get(id);
  assert.equal(row.address, fixed.address, 'the correction must land');
  assert.equal(row.phone, fixed.phone);
  assert.equal(row.status, 'live', 'and an edit must not knock a live store back to a state nothing can leave');
});

await t('an edit may rename the store', async () => {
  const r = await post('/merchants/submit', { ...BASE, merchantId: id, storeName: 'Moozoonf Electronics' }, tokA);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(db.prepare('SELECT store_name FROM merchants WHERE id = ?').get(id).store_name, 'Moozoonf Electronics');
  await post('/merchants/submit', { ...BASE, merchantId: id, storeName: 'Moozoonf' }, tokA);   // put it back
});

await t('a merchantId belonging to SOMEONE ELSE is refused — an edit is not a way into another store', async () => {
  const before = db.prepare('SELECT address FROM merchants WHERE id = ?').get(id).address;
  const r = await post('/merchants/submit', { ...BASE, merchantId: id, address: 'stolen' }, tokB);
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(db.prepare('SELECT address FROM merchants WHERE id = ?').get(id).address, before, 'and nothing may change');
});

await t('an edit that collides with the owner\'s OTHER store is refused by name, not by 500', async () => {
  const second = await post('/merchants/submit', { ...BASE, storeName: 'Moozoonf Outlet' }, tokA);
  assert.equal(second.status, 200, JSON.stringify(second.body));
  const r = await post('/merchants/submit', { ...BASE, merchantId: second.body.id, storeName: 'Moozoonf' }, tokA);
  assert.equal(r.status, 409, `expected a named refusal, got ${r.status}: ${JSON.stringify(r.body)}`);
  assert.equal(db.prepare('SELECT store_name FROM merchants WHERE id = ?').get(second.body.id).store_name, 'Moozoonf Outlet');
});

await t('an unknown merchantId is refused — it must not silently fall through to creating a store', async () => {
  const before = db.prepare('SELECT COUNT(*) c FROM merchants').get().c;
  const r = await post('/merchants/submit', { ...BASE, merchantId: 'mch_does_not_exist', storeName: 'Ghost Shop' }, tokA);
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(db.prepare('SELECT COUNT(*) c FROM merchants').get().c, before, 'no row may appear');
});

console.log(`\nVERDICT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
