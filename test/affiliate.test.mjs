// Commission-attribution logic tests (pure — no D1). Run: node test/affiliate.test.mjs
import assert from 'node:assert/strict';
import { normalizeConversion, normalizeStatus, verifyPostbackSecret } from '../src/affiliate.js';

let pass = 0;
const t = (name, fn) => { try { fn(); console.log('  ✅', name); pass++; } catch (e) { console.log('  ❌', name, '\n     ', e.message); process.exitCode = 1; } };

console.log('\nStatus mapping');
t('known confirmed states => confirmed', () => {
  for (const s of ['confirmed', 'APPROVED', 'Sale', 'paid', 'completed']) assert.equal(normalizeStatus(s), 'confirmed');
});
t('known rejected states => rejected', () => {
  for (const s of ['rejected', 'REVERSED', 'cancelled', 'returned', 'void']) assert.equal(normalizeStatus(s), 'rejected');
});
t('unknown/empty => pending (never bank unknown money)', () => {
  for (const s of ['', undefined, 'weird_event', 'maybe']) assert.equal(normalizeStatus(s), 'pending');
});

console.log('\nConversion normalization');
t('missing network or orderId is rejected', () => {
  assert.equal(normalizeConversion({ orderId: 'X' }).ok, false);
  assert.equal(normalizeConversion({ network: 'amazon' }).ok, false);
});
t('valid payload normalizes, lowercases network, parses amounts', () => {
  const r = normalizeConversion({ network: 'Amazon', order_id: 'A-1', amount: '49.90', commission: '2.50', currency: 'usd', status: 'approved' });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value, { network: 'amazon', orderId: 'A-1', clickId: null, amount: 49.9, commission: 2.5, currency: 'USD', status: 'confirmed' });
});
t('click id aliases (subid) are accepted', () => {
  const r = normalizeConversion({ network: 'ebay', oid: 'O9', subid: 'vz-abc' });
  assert.equal(r.value.clickId, 'vz-abc');
  assert.equal(r.value.orderId, 'O9');
});
t('negative / non-numeric amounts become null (never negative money)', () => {
  const r = normalizeConversion({ network: 'x', orderId: 'y', amount: '-5', commission: 'abc' });
  assert.equal(r.value.amount, null);
  assert.equal(r.value.commission, null);
});
t('unknown status defaults to pending', () => {
  assert.equal(normalizeConversion({ network: 'x', orderId: 'y' }).value.status, 'pending');
});

console.log('\nPostback secret (fails closed)');
t('unconfigured secret rejects everything', () => {
  assert.equal(verifyPostbackSecret('anything', ''), false);
  assert.equal(verifyPostbackSecret('anything', undefined), false);
});
t('wrong secret rejected, correct accepted', () => {
  assert.equal(verifyPostbackSecret('nope', 's3cret'), false);
  assert.equal(verifyPostbackSecret('', 's3cret'), false);
  assert.equal(verifyPostbackSecret('s3cret', 's3cret'), true);
});

console.log(`\n${pass} affiliate tests passed.`);
