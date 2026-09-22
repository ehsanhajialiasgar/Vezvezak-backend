// EVERY WAY A MERCHANT ADDS A PRODUCT MUST END IN THE SAME PLACE (Ehsan 2026-09-22).
//
// Found on production, by counting rather than by reading: the seller test uploaded a CSV through the app's own
// Files picker, the app said "Uploaded 3 item(s); 0 rejected by review", and D1 held 14 items of which 11 were
// live. The three from the CSV were 'pending'. The 2026-09-18 correction — a listing is an introduction, live on
// submit, labelled listed-by-the-merchant-unverified, and only the deterministic prohibited screen can stop it —
// had been applied to catalogItemCreate and not to catalogBulk, whose comment still said "pending for batch
// review". There is no batch, and no reviewer: those rows were invisible to every buyer, permanently.
//
// This is the guard-not-on-every-path class, so the check COUNTS PRODUCERS. A third way to add a product that
// forgets the rule fails here, without anyone having to remember to extend a list.
// Self-skips where node:sqlite is unavailable. Run: node test/catalogLivePaths.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = readFileSync(resolve(HERE, '..', 'src', 'index.js'), 'utf8');

let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

await t('no path writes a catalogue row into a state nothing can leave', () => {
  // Every literal assigned to a status that an INSERT INTO catalog_items binds.
  const producers = [...SRC.matchAll(/INSERT INTO catalog_items[\s\S]{0,600}?\.bind\([^;]*?\)\.run\(\)/g)];
  assert.ok(producers.length >= 2, `expected at least the two known producers, found ${producers.length} — if this is 0 the check is blind`);
  // 'pending' must not appear as a status a catalogue INSERT can carry. The word is allowed elsewhere (a
  // merchant row, a verification) — it is this table it must never enter.
  const region = SRC.slice(SRC.indexOf('async function catalogItemCreate'), SRC.indexOf('// "Verified on Vezvezak"'));
  assert.ok(region.length > 500, 'the catalogue region was not found — the check would be vacuous');
  const bad = [...region.matchAll(/status\s*=\s*[^;\n]*'pending'/g)];
  assert.equal(bad.length, 0, `a catalogue path still writes 'pending', which no reviewer can ever clear:\n     ${bad.map(m => m[0]).join('\n     ')}`);
});

await t('every producer decides its status from a screen, and a refusal is the only non-live answer', () => {
  const region = SRC.slice(SRC.indexOf('async function catalogItemCreate'), SRC.indexOf('// "Verified on Vezvezak"'));
  // Each producer assigns `status` exactly once. Both assignments must come from something that SCREENS the
  // text — directly (bulk) or through moderateCatalogItem, which begins with that same screen (single).
  const assignments = [...region.matchAll(/const status = ([^;\n]+)/g)].map(m => m[1]);
  assert.ok(assignments.length >= 2, `expected one status decision per producer, found ${assignments.length}`);
  for (const a of assignments) {
    assert.match(a, /screenCatalogText\(|moderateCatalogItem\(/, `a status decided by neither screen: ${a}`);
    // NEGATIVE: 'pending' must not be reachable from any of those decisions.
    assert.doesNotMatch(a, /'pending'/, `a producer can still write 'pending': ${a}`);
  }
  // And moderateCatalogItem's own first act must still be that screen, or the single path's chain is broken.
  const mod = SRC.slice(SRC.indexOf('export async function moderateCatalogItem'), SRC.indexOf('// Confirm the signed-in user owns this merchant'));
  assert.match(mod, /screenCatalogText\(text\)\.prohibited\) return 'rejected'/, 'the single path reaches the screen through here');
});

let DatabaseSync;
try { ({ DatabaseSync } = await import('node:sqlite')); }
catch {
  console.log('\nNOTICE: node:sqlite unavailable — the live bulk/single integration check was SKIPPED (the source checks above ran).');
  console.log(`\nVERDICT: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

const { signJwt } = await import('../src/lib.js');
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
const env = { DB: makeD1(db), JWT_SECRET: 'test-secret' };
const iso = new Date().toISOString();
db.prepare('INSERT INTO users (id, identifier, channel, pw_hash, pw_salt, created_at) VALUES (?,?,?,?,?,?)').run('usr_c1', 'c@x.co', 'email', 'h', 's', iso);
const tok = await signJwt({ sub: 'usr_c1', identifier: 'c@x.co' }, env.JWT_SECRET);
const post = async (path, body) => {
  const res = await worker.fetch(new Request(`https://api.test${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tok}` }, body: JSON.stringify(body),
  }), env);
  return { status: res.status, body: await res.json() };
};
const store = await post('/merchants/submit', { storeName: 'Shiva Talent', address: 'Al Quoz 1, Dubai' });
const merchantId = store.body.id;

await t('a single item added through the form is live', async () => {
  const r = await post('/catalog/items', { merchantId, title: 'Brass Incense Burner, Small', variants: [{ sku: 'ST-INC-S', price: 175, currency: 'AED', inStock: true }] });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.status, 'live');
});

await t('THE BUG: items uploaded in bulk are live too — not invisible for ever', async () => {
  const r = await post('/catalog/bulk', { merchantId, items: [
    { title: 'Beaded Wall Hanging, Medium', price: 340, currency: 'AED', sku: 'ST-WAL-M-NAT' },
    { title: 'Terracotta Planter, Set of 3', price: 295, currency: 'AED', sku: 'ST-PLA-03-TER' },
  ] });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.created, 2);
  const rows = db.prepare("SELECT status, COUNT(*) c FROM catalog_items WHERE merchant_id = ? GROUP BY status").all(merchantId);
  const pending = rows.find(x => x.status === 'pending');
  assert.equal(pending, undefined, `bulk still parks rows where no reviewer can reach them: ${JSON.stringify(rows)}`);
  assert.equal(rows.find(x => x.status === 'live').c, 3);
});

await t('a buyer can actually SEE what bulk uploaded — the whole point of the state', async () => {
  const res = await worker.fetch(new Request(`https://api.test/catalog?merchant=${merchantId}`), env);   // no token: a buyer
  const body = await res.json();
  const titles = (body.items || []).map(i => i.title);
  assert.ok(titles.includes('Beaded Wall Hanging, Medium'), `a buyer must see the bulk rows; saw ${JSON.stringify(titles)}`);
  assert.ok(titles.includes('Brass Incense Burner, Small'));
});

await t('and the prohibited screen still refuses, on the bulk path too', async () => {
  const before = db.prepare("SELECT COUNT(*) c FROM catalog_items WHERE merchant_id = ? AND status = 'live'").get(merchantId).c;
  const r = await post('/catalog/bulk', { merchantId, items: [{ title: 'Cocaine for sale', price: 10, currency: 'AED' }] });
  assert.equal(r.body.rejected, 1, `the deterministic screen must still be able to refuse: ${JSON.stringify(r.body)}`);
  assert.equal(db.prepare("SELECT COUNT(*) c FROM catalog_items WHERE merchant_id = ? AND status = 'live'").get(merchantId).c, before,
    'and a refused row must not be live');
});

console.log(`\nVERDICT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
