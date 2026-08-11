// Real tests for the security primitives — run on Node's WebCrypto, the same
// API the Workers runtime provides.
import assert from 'node:assert/strict';
import {
  hashPassword, verifyPassword, signJwt, verifyJwt, normalizeIdentifier,
  channelOf, timingSafeEqual, sha256, b64u, unb64u,
} from '../src/lib.js';

let pass = 0;
const t = async (name, fn) => {
  try { await fn(); console.log('  ✅', name); pass++; }
  catch (e) { console.log('  ❌', name, '\n     ', e.message); process.exitCode = 1; }
};

console.log('\nPassword hashing');
await t('same password + same salt => same hash', async () => {
  const a = await hashPassword('correct horse battery');
  const b = await hashPassword('correct horse battery', a.salt, a.iter);
  assert.equal(a.hash, b.hash);
});
await t('different salt => different hash (no rainbow tables)', async () => {
  const a = await hashPassword('samepass');
  const b = await hashPassword('samepass');
  assert.notEqual(a.salt, b.salt);
  assert.notEqual(a.hash, b.hash);
});
await t('verifyPassword accepts the right password', async () => {
  const { hash, salt, iter } = await hashPassword('s3cret!');
  assert.equal(await verifyPassword('s3cret!', { pw_hash: hash, pw_salt: salt, pw_iter: iter }), true);
});
await t('verifyPassword rejects the wrong password', async () => {
  const { hash, salt, iter } = await hashPassword('s3cret!');
  assert.equal(await verifyPassword('s3cret?', { pw_hash: hash, pw_salt: salt, pw_iter: iter }), false);
});
await t('plaintext never appears in the stored hash', async () => {
  const { hash, salt } = await hashPassword('MyPlaintextPassword');
  assert.ok(!hash.includes('MyPlaintext') && !salt.includes('MyPlaintext'));
});

console.log('\nJWT');
await t('sign -> verify round trip', async () => {
  const tok = await signJwt({ sub: 'usr_1', identifier: 'a@b.com' }, 'secret-key');
  const c = await verifyJwt(tok, 'secret-key');
  assert.equal(c.sub, 'usr_1');
});
await t('wrong secret is rejected', async () => {
  const tok = await signJwt({ sub: 'usr_1' }, 'secret-key');
  assert.equal(await verifyJwt(tok, 'attacker-key'), null);
});
await t('tampered payload is rejected', async () => {
  const tok = await signJwt({ sub: 'usr_1' }, 'secret-key');
  const [h, , s] = tok.split('.');
  const evil = b64u(new TextEncoder().encode(JSON.stringify({ sub: 'admin', exp: 9999999999 })));
  assert.equal(await verifyJwt(`${h}.${evil}.${s}`, 'secret-key'), null);
});
await t('expired token is rejected', async () => {
  const tok = await signJwt({ sub: 'usr_1' }, 'secret-key', -10);
  assert.equal(await verifyJwt(tok, 'secret-key'), null);
});
await t('garbage token is rejected', async () => {
  assert.equal(await verifyJwt('not.a.jwt', 'secret-key'), null);
  assert.equal(await verifyJwt('', 'secret-key'), null);
});

console.log('\nIdentifiers');
await t('emails normalize + validate', () => {
  assert.equal(normalizeIdentifier('  Foo@Bar.COM '), 'foo@bar.com');
  assert.equal(normalizeIdentifier('not-an-email'), null);
  assert.equal(normalizeIdentifier('a@b'), null);
});
await t('phones normalize', () => {
  assert.equal(normalizeIdentifier('+1 (555) 123-4567'), '+15551234567');
  assert.equal(normalizeIdentifier('123'), null);
});
await t('channel detection', () => {
  assert.equal(channelOf('a@b.com'), 'email');
  assert.equal(channelOf('+15551234567'), 'phone');
});

console.log('\nMisc');
await t('timingSafeEqual', () => {
  assert.equal(timingSafeEqual('abc', 'abc'), true);
  assert.equal(timingSafeEqual('abc', 'abd'), false);
  assert.equal(timingSafeEqual('abc', 'ab'), false);
});
await t('sha256 stable + b64u round trip', async () => {
  assert.equal(await sha256('x'), await sha256('x'));
  assert.notEqual(await sha256('x'), await sha256('y'));
  const bytes = new Uint8Array([1, 2, 250, 255]);
  assert.deepEqual(Array.from(unb64u(b64u(bytes))), Array.from(bytes));
});

console.log(`\n${pass} tests passed\n`);

// Regression: the live Workers runtime caps PBKDF2 at 100k iterations. Hashing
// must therefore chain rounds and must never request more than the cap at once.
console.log('\nWorkers PBKDF2 cap');
await t('effective work factor is 600k (OWASP)', async () => {
  const r = await hashPassword('pw');
  assert.equal(r.iter, 600000);
});
await t('no single deriveBits call exceeds the 100k platform cap', async () => {
  const orig = crypto.subtle.deriveBits.bind(crypto.subtle);
  let maxSeen = 0;
  crypto.subtle.deriveBits = (algo, ...rest) => {
    if (algo?.iterations) maxSeen = Math.max(maxSeen, algo.iterations);
    return orig(algo, ...rest);
  };
  await hashPassword('pw');
  crypto.subtle.deriveBits = orig;
  assert.ok(maxSeen <= 100000, `requested ${maxSeen} > 100000 cap`);
});
await t('chained hash still verifies', async () => {
  const { hash, salt, iter } = await hashPassword('chain-me');
  assert.equal(await verifyPassword('chain-me', { pw_hash: hash, pw_salt: salt, pw_iter: iter }), true);
  assert.equal(await verifyPassword('wrong', { pw_hash: hash, pw_salt: salt, pw_iter: iter }), false);
});
console.log('');
