// THE FIELDS A MERCHANT FILLS IN MUST SURVIVE THE TRIP, AND A LISTING MUST BE REACHABLE (Ehsan 2026-09-18).
//
// Two findings from the founder walkthrough, proven here against the REAL schema and the REAL router:
//   1. Eight fields the app has always sent had no columns — sellerType, offerType, saleChannel, showcase,
//      radiusMiles, commissionAgreed, luxuryBrand, luxuryCert. SQLite says nothing about values you never bind,
//      so they vanished on arrival. commissionAgreed is the one that mattered: a merchant agreed to pay a
//      commission and nothing recorded that they had.
//   2. No catalogue row ever became 'live' — the only writer was an AI branch that is off in production — so no
//      buyer could see any product a merchant added. A listing is an introduction, not a guarantee: it goes
//      live labelled "listed by the merchant · unverified", and only the deterministic screen can refuse it.
// Self-skips where node:sqlite is unavailable. Run: node test/merchantFields.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

let DatabaseSync;
try { ({ DatabaseSync } = await import('node:sqlite')); }
catch { console.log('\nNOTICE: node:sqlite unavailable — merchant-fields integration test skipped.'); process.exit(0); }

const { signJwt } = await import('../src/lib.js');
const worker = (await import('../src/index.js')).default;

const HERE = dirname(fileURLToPath(import.meta.url));
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
// MODERATION_ENABLED is deliberately ABSENT here — the production state, where it used to decide everything.
const env = { DB: makeD1(db), JWT_SECRET: 'test-secret' };
const iso = new Date().toISOString();
db.prepare('INSERT INTO users (id, identifier, channel, pw_hash, pw_salt, created_at) VALUES (?,?,?,?,?,?)').run('usr_m1', 'm@x.co', 'email', 'h', 's', iso);
const token = await signJwt({ sub: 'usr_m1', identifier: 'm@x.co' }, env.JWT_SECRET);

const call = async (path, body, tok = token) => {
  const req = new Request(`https://api.test${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: `Bearer ${tok}` } : {}) },
    body: JSON.stringify(body),
  });
  const res = await worker.fetch(req, env);
  return { status: res.status, body: await res.json() };
};

let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

// ── 1 · the eight fields ──────────────────────────────────────────────────────
const SENT = {
  storeName: 'Shirin Electronics', address: '12 Valiasr St, Tehran', category: 'Electronics', bizType: 'retail',
  sellerType: 'Distributor', offerType: 'both', saleChannel: 'both', showcase: 'https://example.com/portfolio',
  radiusMiles: 25, commissionAgreed: true, luxuryBrand: 'n/a', luxuryCert: 'ISO-9001-ref-88213',
};
let merchantId;
await t('a submission keeps every field the app sent — none is dropped in silence', async () => {
  const r = await call('/merchants/submit', SENT);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  merchantId = r.body.id;
  const row = db.prepare('SELECT * FROM merchants WHERE id = ?').get(merchantId);
  assert.equal(row.seller_type, 'Distributor', 'the 13-option seller taxonomy the merchant actually chose');
  assert.equal(row.offer_type, 'both');
  assert.equal(row.sale_channel, 'both');
  assert.equal(row.showcase, 'https://example.com/portfolio');
  assert.equal(row.radius_miles, 25);
  assert.equal(row.luxury_brand, 'n/a');
  assert.equal(row.luxury_cert, 'ISO-9001-ref-88213');
});

await t('the commission the merchant agreed to is RECORDED — the worst of the eight to lose', async () => {
  const row = db.prepare('SELECT commission_agreed FROM merchants WHERE id = ?').get(merchantId);
  assert.equal(row.commission_agreed, 1, 'consent to a commercial term must exist somewhere after they give it');
  const r = await call('/merchants/submit', { ...SENT, storeName: 'No Commission Shop', commissionAgreed: false });
  const row2 = db.prepare('SELECT commission_agreed FROM merchants WHERE id = ?').get(r.body.id);
  assert.equal(row2.commission_agreed, 0, 'and a merchant who did NOT agree must not be recorded as having agreed');
});

await t('the merchant can read back what they told us (/merchants/mine)', async () => {
  const req = new Request('https://api.test/merchants/mine', { headers: { Authorization: `Bearer ${token}` } });
  const res = await worker.fetch(req, env);
  const body = await res.json();
  const mine = body.merchants.find(m => m.id === merchantId);
  assert.ok(mine, 'the store must come back');
  assert.equal(mine.sellerType, 'Distributor');
  assert.equal(mine.commissionAgreed, 1);
  assert.equal(mine.radiusMiles, 25);
});

await t('hostile input is bounded, not trusted', async () => {
  const r = await call('/merchants/submit', {
    ...SENT, storeName: 'Edge Case Store', sellerType: 'x'.repeat(500), radiusMiles: 99999, commissionAgreed: 'yes-please',
  });
  const row = db.prepare('SELECT seller_type, radius_miles, commission_agreed FROM merchants WHERE id = ?').get(r.body.id);
  assert.equal(row.seller_type.length, 60, 'a long seller type is truncated, never stored whole');
  assert.equal(row.radius_miles, 500, 'the radius is clamped');
  assert.equal(row.commission_agreed, 1, 'a truthy value is recorded as consent (1), never as the raw string');
});

// ── 2 · the listing is reachable ──────────────────────────────────────────────
await t('a submitted product goes LIVE with no AI, with MODERATION_ENABLED absent', async () => {
  const r = await call('/catalog/items', {
    merchantId, title: 'Samsung Galaxy A54 5G 128GB', brand: 'Samsung',
    variants: [{ sku: 'A54-128', price: 18500000, currency: 'IRR', inStock: true }],
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.status, 'live', 'the seller must not be filed into a queue nobody reads');
});

await t('the deterministic screen still refuses what it always refused', async () => {
  const r = await call('/catalog/items', {
    merchantId, title: 'Replica watch — Swiss movement copy', variants: [{ sku: 'R1', price: 100, currency: 'USD' }],
  });
  assert.equal(r.body.status, 'rejected', 'going live on submit must not let a prohibited listing through');
});

await t('a BUYER can now see the live item, and never the rejected one', async () => {
  const res = await worker.fetch(new Request(`https://api.test/catalog?merchant=${merchantId}`), env);   // no token = a buyer
  const body = await res.json();
  const titles = body.items.map(i => i.title);
  assert.ok(titles.some(x => x.startsWith('Samsung Galaxy A54')), `a buyer must see the live item, got: ${JSON.stringify(titles)}`);
  assert.ok(!titles.some(x => x.startsWith('Replica')), 'and must never see a rejected one');
});

await t('MODERATION_ENABLED is no longer load-bearing: flag ON changes nothing for a free seller', async () => {
  const flagged = { ...env, MODERATION_ENABLED: '1' };   // no AI binding, free plan — the old 'pending' triple
  const req = new Request('https://api.test/catalog/items', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ merchantId, title: 'A perfectly ordinary blue mug', variants: [{ sku: 'M1', price: 9, currency: 'USD' }] }),
  });
  const body = await (await worker.fetch(req, flagged)).json();
  assert.equal(body.status, 'live', 'with the flag on and no AI available the item must still reach the buyer');
});

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
