// Seller-catalog normalizer tests (pure). Run: node test/catalog.test.mjs
import assert from 'node:assert/strict';
import { normalizeItem, normalizeVariant, normalizeGtin, normalizeCondition, screenCatalogText } from '../src/catalog.js';

let pass = 0;
const t = (name, fn) => { try { fn(); console.log('  ✅', name); pass++; } catch (e) { console.log('  ❌', name, '\n     ', e.message); process.exitCode = 1; } };

console.log('\nItem');
t('title is required', () => {
  assert.equal(normalizeItem({}).ok, false);
  assert.equal(normalizeItem({ title: '  ' }).ok, false);
  assert.equal(normalizeItem({ title: 'Widget' }).ok, true);
});
t('invalid GTIN is dropped, valid kept', () => {
  assert.equal(normalizeGtin('12345'), null);          // wrong length
  assert.equal(normalizeGtin('0123456789012'), '0123456789012'); // EAN-13
  assert.equal(normalizeItem({ title: 'X', gtin: 'abc-123' }).value.gtin, null);
});
t('condition whitelisted', () => {
  assert.equal(normalizeCondition('New'), 'new');
  assert.equal(normalizeCondition('brand-new'), null);
  assert.equal(normalizeItem({ title: 'X', condition: 'refurbished' }).value.condition, 'refurbished');
});
t('non-http image url is dropped', () => {
  assert.equal(normalizeItem({ title: 'X', imageUrl: 'javascript:alert(1)' }).value.imageUrl, null);
  assert.equal(normalizeItem({ title: 'X', imageUrl: 'https://x.com/a.jpg' }).value.imageUrl, 'https://x.com/a.jpg');
});

console.log('\nVariant honesty');
t('stock is NULL unless explicitly stated (never faked)', () => {
  assert.equal(normalizeVariant({}).value.inStock, null);
  assert.equal(normalizeVariant({ inStock: true }).value.inStock, 1);
  assert.equal(normalizeVariant({ inStock: false }).value.inStock, 0);
  assert.equal(normalizeVariant({ inStock: 'yes' }).value.inStock, null); // not a boolean => unknown
});
t('was_price kept ONLY when a real markdown above price', () => {
  assert.equal(normalizeVariant({ price: 80, wasPrice: 100 }).value.wasPrice, 100); // real discount
  assert.equal(normalizeVariant({ price: 100, wasPrice: 90 }).value.wasPrice, null); // fake "discount" rejected
  assert.equal(normalizeVariant({ price: 100, wasPrice: 100 }).value.wasPrice, null); // equal => no discount
  assert.equal(normalizeVariant({ wasPrice: 100 }).value.wasPrice, null); // no price => can't claim
});
t('negative / junk prices become null', () => {
  assert.equal(normalizeVariant({ price: '-5' }).value.price, null);
  assert.equal(normalizeVariant({ price: 'abc' }).value.price, null);
  assert.equal(normalizeVariant({ price: '49.9', currency: 'usd' }).value.price, 49.9);
  assert.equal(normalizeVariant({ price: '49.9', currency: 'usd' }).value.currency, 'USD');
});
t('attributes object is JSON-stringified', () => {
  const v = normalizeVariant({ attributes: { color: 'red', size: 'M' } }).value;
  assert.equal(typeof v.attributes, 'string');
  assert.ok(v.attributes.includes('red'));
});

console.log('\nProhibited-content screen');
t('clearly-prohibited listings are caught by keyword', () => {
  assert.equal(screenCatalogText('Glock 19 pistol with ammo').prohibited, true);
  assert.equal(screenCatalogText('counterfeit Rolex replica watch').prohibited, true);
  assert.equal(screenCatalogText('cocaine for sale').prohibited, true);
});
t('normal products pass the screen', () => {
  assert.equal(screenCatalogText('Travel power bank 20000mAh, USB-C').prohibited, false);
  assert.equal(screenCatalogText('Nike running shoes size 42').prohibited, false);
  assert.equal(screenCatalogText('').prohibited, false);
});
t('screen returns a reason for audit', () => {
  assert.equal(screenCatalogText('rifle for hunting').reason, 'weapons');
});

console.log(`\n${pass} catalog tests passed.`);
