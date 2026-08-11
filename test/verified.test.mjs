// Verified-badge match-logic tests. Run: node test/verified.test.mjs
import assert from 'node:assert/strict';
import { nameTokens, nameMatches, haversineM, merchantMatches } from '../src/verified.js';

let pass = 0;
const t = (name, fn) => { try { fn(); console.log('  ✅', name); pass++; } catch (e) { console.log('  ❌', name, '\n     ', e.message); process.exitCode = 1; } };

console.log('\nName matching');
t('normalizes + drops generic suffixes', () => {
  assert.deepEqual(nameTokens("Joe's Pizza Co."), ['joes', 'pizza']);
  assert.deepEqual(nameTokens('THE Coffee Shop'), ['coffee']);
});
t('matches near-identical names, not different ones', () => {
  assert.equal(nameMatches("Joe's Pizza", 'Joes Pizza Co'), true);
  assert.equal(nameMatches('Blue Bottle Coffee', 'Blue Bottle'), true); // 2/3 overlap
  assert.equal(nameMatches('Joe Pizza', 'Mario Sushi'), false);
  assert.equal(nameMatches('', 'x'), false);
});

console.log('\nDistance');
t('haversine ~ correct + guards bad input', () => {
  assert.ok(Math.abs(haversineM(40.0, -74.0, 40.0, -74.0)) < 1);       // same point
  assert.ok(haversineM(40.0, -74.0, 40.001, -74.0) > 100);            // ~111m
  assert.ok(haversineM(40.0, -74.0, 40.001, -74.0) < 130);
  assert.equal(haversineM(40, -74, undefined, -74), Infinity);
});

console.log('\nMerchant match (name AND proximity)');
const store = { name: "Joe's Pizza", lat: 40.7128, lng: -74.0060 };
t('same name + within 150m => match', () => {
  assert.equal(merchantMatches(store, { store_name: 'Joes Pizza', latitude: 40.7129, longitude: -74.0060 }), true);
});
t('same name but far away => NO match (not the same storefront)', () => {
  assert.equal(merchantMatches(store, { store_name: 'Joes Pizza', latitude: 40.80, longitude: -74.0060 }), false);
});
t('nearby but different name => NO match', () => {
  assert.equal(merchantMatches(store, { store_name: 'Sushi World', latitude: 40.7128, longitude: -74.0060 }), false);
});
t('missing merchant coords => NO match (never guess a badge)', () => {
  assert.equal(merchantMatches(store, { store_name: 'Joes Pizza', latitude: null, longitude: null }), false);
});

console.log(`\n${pass} verified-match tests passed.`);
