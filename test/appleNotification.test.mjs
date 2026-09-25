// APP STORE SERVER NOTIFICATIONS v2 — a refunded customer must lose the plan within seconds (Ehsan 2026-09-25).
//
// Without this route a refund leaves a paid plan running until its expiry date: we give away the service AND
// the money back. With it, the entitlement follows Apple's own view of the purchase.
//
// THE ASYMMETRY THIS ENCODES: revoking on the notification alone costs a customer one refresh if the
// notification were ever forged; NOT revoking on a real refund costs us the service and the money. So a
// revocation is immediate and a GRANT is never taken on the notification's word — it is re-asked of Apple over
// the authenticated Server API, the same door iapValidate uses.
// Run: node test/appleNotification.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readNotification, REVOKING_TYPES } from '../src/iap.js';

let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

const b64u = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const jws = o => `${b64u({ alg: 'ES256' })}.${b64u(o)}.sig`;
const notif = (type, txn, extra = {}) => jws({
  notificationType: type, notificationUUID: 'uuid-1', ...extra,
  data: { signedTransactionInfo: jws({ transactionId: txn, originalTransactionId: txn, productId: 'vez_pro_monthly' }) },
});

await t('the payload is READ, never trusted — type, uuid and the transaction come out', () => {
  const n = readNotification(notif('REFUND', '2000000012345678'));
  assert.equal(n.type, 'REFUND');
  assert.equal(n.uuid, 'uuid-1');
  assert.equal(n.originalTransactionId, '2000000012345678');
  assert.equal(n.transactionId, '2000000012345678');
});

await t('an unreadable payload is a REFUSAL, not a crash — the sender is not authenticated', () => {
  for (const bad of ['', 'not-a-jws', 'a.b.c', jws({ notificationType: 'REFUND' }), jws({ notificationUUID: 'x' })]) {
    assert.equal(readNotification(bad), null, `${String(bad).slice(0, 20)} must be refused`);
  }
});

await t('a transaction id that is not digits is dropped — never passed on to Apple or SQL', () => {
  const n = readNotification(notif('REFUND', "'; DROP TABLE user_plans; --"));
  assert.equal(n.originalTransactionId, null);
  assert.equal(n.transactionId, null);
});

await t('every type that ENDS an entitlement is in the revoking set', () => {
  for (const type of ['REFUND', 'REVOKE', 'EXPIRED', 'GRACE_PERIOD_EXPIRED']) {
    assert.ok(REVOKING_TYPES.has(type), `${type} must revoke`);
  }
  // NEGATIVE: a renewal must NOT be in it, or every renewal would cancel the plan it renews.
  for (const type of ['DID_RENEW', 'SUBSCRIBED', 'OFFER_REDEEMED']) {
    assert.ok(!REVOKING_TYPES.has(type), `${type} must not revoke`);
  }
});

await t('THE ASYMMETRY IS IN THE CODE: revoke on the notification, grant only after asking Apple', () => {
  const src = readFileSync('src/iap.js', 'utf8');
  const fn = src.slice(src.indexOf('export async function appleNotification'));
  const revokeAt = fn.indexOf('REVOKING_TYPES.has');
  const askAt = fn.indexOf('fetchTransaction(askAbout');
  assert.ok(revokeAt > 0 && askAt > revokeAt, 'the revoke branch returns BEFORE any grant path is reached');
  assert.match(fn, /INSERT OR IGNORE INTO apple_notifications/, 'the insert is the idempotency lock');
  assert.match(fn, /evaluateTransaction\(/, 'a grant is taken from Apple\'s answer, not the notification');
});

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
