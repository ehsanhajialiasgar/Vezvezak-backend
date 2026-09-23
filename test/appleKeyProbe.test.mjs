// A 500 IS NOT A DIAGNOSIS (Ehsan 2026-09-22).
//
// The four Apple secrets went in, the Worker was deployed, and POST /iap/validate answered HTTP 500 with
// `error code: 1101` — an unhandled exception, nothing to read. Every HTTP status and every network failure in
// fetchTransaction was already named; the FIRST step, signing the JWT, was the one that was not, so a key that
// will not load escaped as a crash. That is the guard-not-on-every-path shape at the top of the function.
//
// It also matters WHICH key: the App Store Server API and the App Store Connect API take different keys,
// generated on the same page. A Team Key signs perfectly and is refused by the Server API with 401, which
// looks like a wrong secret when the secret is fine and simply of the wrong kind.
// Run: node test/appleKeyProbe.test.mjs
import assert from 'node:assert/strict';
import { signAppleJwt, fetchTransaction, appleKeyProbe, decodeJwsPayload } from '../src/iap.js';

let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

// A real, throwaway P-256 key in PKCS#8, generated here — nothing secret, and it makes the signer runnable.
const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
const b64 = btoa(String.fromCharCode(...pkcs8));
const pem = `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----\n`;
const CFG = { issuerId: 'issuer-uuid', keyId: 'KEYID12345', privateKey: pem, bundleId: 'com.ehsan.vezvezak' };

await t('the JWT the backend builds is the one the App Store SERVER API requires', async () => {
  const jwt = await signAppleJwt(CFG, 1_700_000_000);
  const [h, p] = jwt.split('.').slice(0, 2).map(x => JSON.parse(Buffer.from(x, 'base64url').toString()));
  assert.equal(h.alg, 'ES256');
  assert.equal(h.typ, 'JWT');
  assert.equal(h.kid, CFG.keyId, 'the key id identifies WHICH key Apple should check against');
  assert.equal(p.iss, CFG.issuerId);
  assert.equal(p.aud, 'appstoreconnect-v1');
  // `bid` is the claim that makes this a SERVER API token. An App Store Connect token does not carry it, and
  // its absence is how a key meant for one API is told apart from a key meant for the other.
  assert.equal(p.bid, CFG.bundleId, 'without bid this is an App Store Connect token, not a Server API one');
  assert.ok(p.exp - p.iat <= 3600, "Apple refuses a lifetime over an hour");
  assert.ok(p.exp > p.iat);
});

await t('a .p8 pasted with literal backslash-n still loads', async () => {
  // What a key pasted through a shell or a JSON field looks like. \\s+ does not remove it and atob then throws.
  const mangled = { ...CFG, privateKey: pem.replace(/\n/g, '\\n') };
  const jwt = await signAppleJwt(mangled, 1_700_000_000);
  assert.equal(jwt.split('.').length, 3, 'the signer must survive the commonest paste shape');
});

await t('THE 500: a key that cannot load is now a REASON, not a crash', async () => {
  const bad = { ...CFG, privateKey: '-----BEGIN PRIVATE KEY-----\nnot base64 at all !!!\n-----END PRIVATE KEY-----' };
  const r = await fetchTransaction('2000000000000001', bad, async () => { throw new Error('must not be reached'); });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'apple_key_unusable', `a crash instead of a reason: ${JSON.stringify(r)}`);
});

await t("Apple's OWN error code decides, not the bare status", async () => {
  const reply = (status, body) => async () => new Response(body === undefined ? '' : JSON.stringify(body), {
    status, headers: { 'content-type': 'application/json' },
  });
  // 4040005 TransactionIdNotFound — the key authenticated, the app resolved, and only the id we invented is
  // missing. That is the BEST answer a key probe can get, and reporting it as a failure was the bug.
  let r = await appleKeyProbe(CFG, reply(404, { errorCode: 4040005, errorMessage: 'Transaction id not found.' }), 1);
  assert.equal(r.reason, 'ok', JSON.stringify(r));
  assert.equal(r.appleError, 'transaction_id_not_found');
  assert.equal(r.appleErrorCode, 4040005);

  // 4040010 AppNotFound — the key is fine; the APP is not in that environment, which is exactly what an
  // unreleased app looks like in production. A different fact, and it must not read as a bad key.
  r = await appleKeyProbe(CFG, reply(404, { errorCode: 4040010, errorMessage: 'App not found.' }), 1, 'Production');
  assert.equal(r.reason, 'apple_app_not_in_environment', JSON.stringify(r));
  assert.equal(r.appleError, 'app_not_found');
  assert.notEqual(r.reason, 'ok', 'production not knowing an unreleased app is not proof the key works');
  assert.notEqual(r.reason, 'apple_rejected_key', 'nor is it a rejected key');

  // 401 — a well-formed ES256 JWT Apple will not take here means the wrong KIND of key.
  assert.equal((await appleKeyProbe(CFG, reply(401, { errorCode: 4010000 }), 1)).reason, 'apple_rejected_key');
  // A 404 with a code we have never seen is named by its number, never silently treated as success.
  r = await appleKeyProbe(CFG, reply(404, { errorCode: 4049999 }), 1);
  assert.equal(r.appleError, 'apple_error_4049999');
  assert.notEqual(r.reason, 'ok');
  // A body that is not JSON at all must not throw, and must not become ok.
  r = await appleKeyProbe(CFG, reply(500), 1);
  assert.equal(r.reason, 'apple_http_500');
  assert.equal(r.appleErrorCode, null);
  // 200 is still 200.
  assert.equal((await appleKeyProbe(CFG, async () => new Response('{}', { status: 200 }), 1)).reason, 'ok');
  const unreachable = await appleKeyProbe(CFG, async () => { throw new Error('dns'); }, 1);
  assert.equal(unreachable.reason, 'apple_unreachable');
  assert.equal(unreachable.keyLoads, true, 'the key loaded; it was the network that did not');
});

await t('the probe reveals the status and nothing else', async () => {
  const r = await appleKeyProbe(CFG, async () => new Response('{}', { status: 200 }), 1);
  const dumped = JSON.stringify(r);
  for (const secret of [CFG.privateKey, b64, CFG.issuerId, CFG.keyId]) {
    assert.ok(!dumped.includes(secret.slice(0, 24)), 'the probe leaked part of the key material');
  }
  const bad = await appleKeyProbe({ ...CFG, privateKey: 'nonsense' }, async () => new Response('', { status: 200 }), 1);
  assert.equal(bad.keyLoads, false);
  assert.ok(!JSON.stringify(bad).includes('nonsense'), 'a failure must not echo the value that failed');
});

await t('it reads a transaction that cannot exist — nobody\'s data, either environment', async () => {
  let url = '';
  await appleKeyProbe(CFG, async u => { url = String(u); return new Response('{}', { status: 200 }); }, 1);
  assert.match(url, /api\.storekit-sandbox\.itunes\.apple\.com/, `default must be sandbox; probed ${url}`);
  assert.match(url, /\/inApps\/v1\/transactions\/0{16}$/, 'an id of all zeroes cannot belong to a purchase');
  await appleKeyProbe(CFG, async u => { url = String(u); return new Response('{}', { status: 200 }); }, 1, 'Production');
  assert.match(url, /api\.storekit\.itunes\.apple\.com/, `production must be asked too; probed ${url}`);
});

await t('decodeJwsPayload still refuses anything malformed', () => {
  for (const bad of [null, 'x', 'a.b', 'a..c']) assert.throws(() => decodeJwsPayload(bad));
});

await t("real validation follows Apple's documented order: production, then sandbox", async () => {
  // Each rig gets its OWN counter. Sharing one made the second call in the next rig read past the end of its
  // sequence and throw, which arrived as 'apple_unreachable' — a test failing for its own plumbing.
  let calls = [];
  const reply = seq => { let i = 0; return async (u) => {
    calls.push(String(u));
    const r = seq[i++];
    if (!r) throw new Error('sequence exhausted');
    return new Response(r.body === undefined ? '' : JSON.stringify(r.body), { status: r.status, headers: { 'content-type': 'application/json' } });
  }; };
  // A SANDBOX PURCHASE: production does not know the app, sandbox does. Without the fall-back, every sandbox
  // tester's purchase is refused — which is every purchase before the app ships.
  const seq = [
    { status: 404, body: { errorCode: 4040010, errorMessage: 'App not found.' } },
    { status: 200, body: { signedTransactionInfo: 'x.eyJwcm9kdWN0SWQiOiJ2ZXpfcHJvX21vbnRobHkifQ.y' } },
  ];
  const r = await fetchTransaction('2000000000000001', CFG, reply(seq), 1);
  assert.equal(calls.length, 2, `expected production then sandbox, got ${calls.length} call(s)`);
  assert.match(calls[0], /api\.storekit\.itunes\.apple\.com/, 'production must be asked first');
  assert.match(calls[1], /storekit-sandbox/, 'and sandbox second');
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.environment, 'Sandbox');

  // NEGATIVE: a 404 from production carrying a code that is NOT one of the documented two must not silently
  // fall through to sandbox — it is a different failure and is named.
  calls = [];
  const other = await fetchTransaction('2000000000000001', CFG, reply([{ status: 404, body: { errorCode: 4040099 } }]), 1);
  assert.equal(other.ok, false);
  assert.equal(other.reason, 'apple_error_4040099', JSON.stringify(other));

  // And a non-404 failure carries Apple's own code in its reason.
  calls = [];
  const bad = await fetchTransaction('2000000000000001', CFG, reply([{ status: 500, body: { errorCode: 5000000 } }]), 1);
  assert.match(String(bad.reason), /apple_500_/, JSON.stringify(bad));
});

console.log(`\nVERDICT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
