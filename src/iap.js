// IN-APP PURCHASE VALIDATION — launch chain step 5 (Ehsan 2026-09-13).
//
// Until today this did not exist, and subscriptionService.applyPurchasedPlan's comment in the app claimed
// "iapService validated the receipt on the backend" — a validation that never happened anywhere. A false
// claim in code is the shape that becomes a false claim in copy, so the endpoint now exists and the comment
// was rewritten to say exactly what is and is not true.
//
// ── THE TRUST MODEL: THE CLIENT IS NEVER BELIEVED ─────────────────────────────────────────────────────────
// The client sends ONE thing: a transaction id. It does not send a plan, an expiry, a product or a signed
// transaction for us to trust. The server asks APPLE, over the App Store Server API, authenticated with our
// own App Store Connect key (an ES256 JWT), and builds the entitlement ONLY from Apple's answer.
// Chosen over validating a client-supplied StoreKit 2 JWS locally, because that path means hand-rolling
// X.509 chain validation to Apple's root in a Worker — security-critical code where one bug lets anyone mint
// a Max plan. Asking Apple directly moves the trust boundary to TLS to api.storekit.itunes.apple.com.
// STATED LIMIT: Apple's response is itself a signed JWS and we DECODE it without re-verifying its x5c chain.
// We fetched it over TLS from Apple with our authenticated JWT, so an attacker would have to break TLS to
// Apple to inject one; Apple recommends verifying anyway as defence in depth. NOT BUILT — recorded, not hidden.
//
// ── IT IS THE FIRST WRITER OF user_plans, AND THAT CHANGES WHAT IS REACHABLE ──────────────────────────────
// Before this file, nothing wrote user_plans: every account resolved to 'free', so every plan gate in the
// backend was unreachable in practice. The moment this endpoint writes a 'pro' row, moderateReview's and
// moderateCatalogItem's plan gates become reachable. MODERATION_ENABLED="0" sits ABOVE those gates and still
// holds them closed — asserted by test/moderation-flag.test.mjs and the weeklyCaps two-condition cases.
//
// ── EXPIRY IS NOW A SERVER FACT (ledger 1.2) ──────────────────────────────────────────────────────────────
// user_plans had no expiry column and nothing compared dates, so a paid plan never expired on our side. This
// writes expires_at from Apple's expiresDate, and planFor() in lib.js refuses any paid row whose expiry is
// absent, unparseable or past. Same table, same write path, same pass.
//
// ── FAIL CLOSED ON EVERY UNKNOWN ──────────────────────────────────────────────────────────────────────────
// Missing credentials, a malformed id, any non-200 from Apple, a malformed JWS, a bundle mismatch, an unknown
// product, a non-subscription type, a revocation, a missing or past expiry, a transaction already bound to a
// different account — each is a refusal, and each names why. Nothing on this path grants by default.
import { json, fail, readJson, requireAuth, nowIso, b64u, unb64u } from './lib.js';

// The store product ids the app defines (VezvezakNew/src/services/iapService.ts PRODUCT_IDS). A product not
// in this map is an UNKNOWN, and unknown refuses.
export const PRODUCT_PLANS = {
  vez_pro_monthly: 'pro',
  vez_pro_yearly: 'pro',
  vez_max_monthly: 'max',
  vez_max_yearly: 'max',
};

const APPLE_HOSTS = {
  Production: 'https://api.storekit.itunes.apple.com',
  Sandbox: 'https://api.storekit-sandbox.itunes.apple.com',
};

// Null unless EVERY credential is present. A partial configuration is an unknown.
export function appleConfig(env) {
  const cfg = {
    issuerId: env.APPLE_ISSUER_ID, keyId: env.APPLE_KEY_ID,
    privateKey: env.APPLE_PRIVATE_KEY, bundleId: env.APPLE_BUNDLE_ID,
  };
  return Object.values(cfg).every(v => typeof v === 'string' && v.trim().length > 0) ? cfg : null;
}

// App Store Connect API JWT: ES256, audience appstoreconnect-v1, lifetime well under Apple's 60-minute cap.
export async function signAppleJwt(cfg, nowSec = Math.floor(Date.now() / 1000)) {
  // A PASTED .p8 ARRIVES IN MORE THAN ONE SHAPE (Ehsan 2026-09-22). Whitespace and the BEGIN/END lines were
  // already stripped; a literal backslash-n — what a key pasted through a shell or a JSON field looks like —
  // was not, and survives \s+ as the two characters \ and n, which makes atob throw. Both are removed here,
  // because the person setting the secret cannot see which shape they produced.
  const pem = cfg.privateKey.replace(/\\n/g, '').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const header = { alg: 'ES256', kid: cfg.keyId, typ: 'JWT' };
  const payload = { iss: cfg.issuerId, iat: nowSec, exp: nowSec + 20 * 60, aud: 'appstoreconnect-v1', bid: cfg.bundleId };
  const enc = new TextEncoder();
  const data = `${b64u(enc.encode(JSON.stringify(header)))}.${b64u(enc.encode(JSON.stringify(payload)))}`;
  // WebCrypto returns ECDSA signatures as raw r||s (IEEE P1363) — exactly the JWS ES256 encoding.
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(data)));
  return `${data}.${b64u(sig)}`;
}

// Decode a JWS payload. Throws on anything malformed — the caller turns that into a refusal.
export function decodeJwsPayload(jws) {
  if (typeof jws !== 'string') throw new Error('jws_not_string');
  const parts = jws.split('.');
  if (parts.length !== 3 || !parts[1]) throw new Error('jws_malformed');
  const obj = JSON.parse(new TextDecoder().decode(unb64u(parts[1])));
  if (!obj || typeof obj !== 'object') throw new Error('jws_payload_not_object');
  return obj;
}

// Ask Apple. Production first; a 404 there means "not a production transaction", so try Sandbox (Apple's
// documented order). Any other non-200, or any network failure, is an unknown.
export async function fetchTransaction(transactionId, cfg, fetchImpl = fetch, nowSec) {
  // THE FIRST STEP WAS THE ONLY UNGUARDED ONE (Ehsan 2026-09-22). Every HTTP status and every network failure
  // below is named; signing was not, so a key that will not load — the wrong format, a bad paste, the wrong
  // kind of key — escaped as an unhandled worker exception and reached the app as HTTP 500 `error code: 1101`.
  // Measured live on production the day the secrets went in: a 500 with nothing to read, which is the same
  // blindness the merchant duplicate-name fix was about.
  let token;
  try { token = await signAppleJwt(cfg, nowSec); }
  catch { return { ok: false, reason: 'apple_key_unusable' }; }
  // A refusal in Production that Sandbox may still answer. Held, not returned, so that if Sandbox refuses too
  // the caller is told what BOTH environments said rather than only the last one.
  let heldProduction = null;
  for (const env of ['Production', 'Sandbox']) {
    let res;
    try {
      res = await fetchImpl(`${APPLE_HOSTS[env]}/inApps/v1/transactions/${transactionId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
    } catch {
      return { ok: false, reason: 'apple_unreachable' };
    }
    if (res.status === 404) {
      // APPLE'S DOCUMENTED ORDER, BY CODE (Ehsan 2026-09-23). Production is asked first; a 404 there is the
      // documented signal to try Sandbox — an app that has not shipped is not in production at all, and a
      // sandbox tester's purchase never will be. The code is read so the fall-back happens for the two reasons
      // Apple documents and not for a 404 that means something else.
      const { code, named } = await readAppleError(res);
      if (env === 'Production' && (named === 'app_not_found' || named === 'transaction_id_not_found' || code === null)) {
        heldProduction = named ? `apple_404_${named}` : 'apple_http_404';
        continue;
      }
      if (env === 'Production') return { ok: false, reason: named || 'apple_http_404' };
      return { ok: false, reason: named === 'app_not_found' ? 'apple_app_not_in_environment' : 'apple_not_found' };
    }
    if (res.status !== 200) {
      const { named } = await readAppleError(res);
      const reason = named ? `apple_${res.status}_${named}` : `apple_http_${res.status}`;
      // PRODUCTION ANSWERS 401 FOR AN APP THAT HAS NEVER SHIPPED (Ehsan 2026-09-23, measured). The same key,
      // the same JWT, the same second: Sandbox authenticated and answered about the transaction, Production
      // returned a bodiless 401. Production has no record of an app that is not on the App Store, so it has
      // nothing to authorise the token AGAINST and rejects the caller rather than reporting a missing app.
      // Falling back only on 4040010 would therefore have failed EVERY pre-release purchase — the sandbox
      // testers' purchases are the only purchases that exist before launch. So a Production 401 falls through
      // to Sandbox exactly as a Production 404 does. It stays correct after launch: a real production
      // transaction gets a 200 in Production and never reaches this line.
      if (env === 'Production' && res.status === 401) { heldProduction = reason; continue; }
      if (env === 'Sandbox' && heldProduction) return { ok: false, reason: `${reason}_after_${heldProduction}` };
      return { ok: false, reason };
    }
    let body;
    try { body = await res.json(); } catch { return { ok: false, reason: 'apple_body_not_json' }; }
    if (!body || typeof body.signedTransactionInfo !== 'string') return { ok: false, reason: 'apple_no_signed_transaction' };
    try {
      return { ok: true, environment: env, transaction: decodeJwsPayload(body.signedTransactionInfo) };
    } catch (e) {
      return { ok: false, reason: `apple_${e.message}` };
    }
  }
  return { ok: false, reason: 'apple_no_environment_answered' };   // unreachable by construction; refuse if it ever is
}

// PURE. Turns Apple's transaction into an entitlement, or a named refusal. Every branch that is not an
// explicit, fully-checked grant refuses.
export function evaluateTransaction(tx, cfg, nowMs = Date.now()) {
  if (!tx || typeof tx !== 'object') return { ok: false, reason: 'no_transaction' };
  if (tx.bundleId !== cfg.bundleId) return { ok: false, reason: 'bundle_mismatch' };
  const plan = PRODUCT_PLANS[tx.productId];
  if (!plan) return { ok: false, reason: 'unknown_product' };
  if (tx.type !== 'Auto-Renewable Subscription') return { ok: false, reason: 'not_a_subscription' };
  if (tx.revocationDate != null) return { ok: false, reason: 'revoked' };
  const expires = Number(tx.expiresDate);
  if (!Number.isFinite(expires) || expires <= 0) return { ok: false, reason: 'no_expiry' };
  if (expires <= nowMs) return { ok: false, reason: 'expired' };
  const original = tx.originalTransactionId != null ? String(tx.originalTransactionId) : '';
  if (!/^\d{1,32}$/.test(original)) return { ok: false, reason: 'no_original_transaction_id' };
  return { ok: true, plan, expiresAt: new Date(expires).toISOString(), originalTransactionId: original };
}

export async function iapValidate(request, env, fetchImpl = fetch) {
  const claims = await requireAuth(request, env);
  if (!claims?.sub) return fail(401, 'Sign in to restore or validate a purchase.', 'auth_required');

  const body = await readJson(request);
  const transactionId = body && typeof body.transactionId === 'string' ? body.transactionId.trim() : '';
  if (!/^\d{1,32}$/.test(transactionId)) return fail(400, 'A valid transaction id is required.', 'bad_transaction_id');

  const cfg = appleConfig(env);
  if (!cfg) return fail(503, 'Purchase validation is not configured.', 'iap_not_configured');

  const fetched = await fetchTransaction(transactionId, cfg, fetchImpl);
  if (!fetched.ok) return fail(502, 'Could not validate this purchase with Apple.', fetched.reason);

  const verdict = evaluateTransaction(fetched.transaction, cfg);
  if (!verdict.ok) return fail(402, 'This purchase does not grant an active plan.', verdict.reason);

  // REPLAY: one Apple subscription belongs to one Vezvezak account. A transaction already bound to a
  // DIFFERENT account is refused — otherwise one purchase could be restored into any number of accounts.
  const bound = await env.DB.prepare(
    'SELECT user_id FROM user_plans WHERE original_transaction_id = ? AND user_id != ?',
  ).bind(verdict.originalTransactionId, claims.sub).first();
  if (bound) return fail(409, 'This purchase is already linked to another account.', 'transaction_bound_elsewhere');

  await env.DB.prepare(
    `INSERT INTO user_plans (user_id, plan, expires_at, source, original_transaction_id, environment, updated_at)
     VALUES (?, ?, ?, 'apple', ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET plan = excluded.plan, expires_at = excluded.expires_at,
       source = excluded.source, original_transaction_id = excluded.original_transaction_id,
       environment = excluded.environment, updated_at = excluded.updated_at`,
  ).bind(claims.sub, verdict.plan, verdict.expiresAt, verdict.originalTransactionId, fetched.environment, nowIso()).run();

  return json(200, { ok: true, plan: verdict.plan, expiresAt: verdict.expiresAt, environment: fetched.environment });
}

// APPLE'S OWN ERROR CODES, NAMED (Ehsan 2026-09-23).
//
// The App Store Server API answers a failure with {errorCode, errorMessage}. The STATUS alone cannot tell these
// apart, and they mean opposite things about the key:
//   4040010 AppNotFound           - authenticated fine; this app is not in the environment we asked
//   4040005 TransactionIdNotFound - authenticated fine, app resolved; only the transaction is missing
// The second is the best possible answer to "is this key good": everything worked except the thing we made up.
// Matched as NUMBERS, because the message beside them is prose and may be reworded.
export const APPLE_ERROR = {
  4040010: 'app_not_found',
  4040001: 'app_not_found',
  4040005: 'transaction_id_not_found',
  4010000: 'unauthenticated',
  // 4000006 InvalidTransactionId — MEASURED against Apple 2026-09-23 with a good key: sixteen zeros is not a
  // well-formed transaction id, and Apple says so with a 400. Saying so REQUIRES having authenticated us and
  // resolved the app first; an unauthenticated caller never gets this far, it gets a bodiless 401. So this code
  // is a PASS for the only question the probe asks, and PROBE_AUTHENTICATED below treats it as one.
  4000006: 'invalid_transaction_id',
};

// The Apple answers that can only be produced AFTER our key was accepted. Each one reports a fact about the
// thing we asked for, which Apple cannot know without first knowing who is asking.
export const PROBE_AUTHENTICATED = new Set(['transaction_id_not_found', 'invalid_transaction_id']);

// Pull Apple's code out of a body that may or may not be JSON, without ever throwing.
export async function readAppleError(res) {
  let body = null;
  try { body = await res.json(); } catch { body = null; }
  const code = body && typeof body.errorCode === 'number' ? body.errorCode : null;
  return { code, named: code !== null ? (APPLE_ERROR[code] || 'apple_error_' + code) : null };
}

// WHICH INPUT IS DIFFERENT? — a comparison needs two sides (Ehsan 2026-09-23).
//
// The isolation script on Ehsan's Mac signed the same claims, with the same algorithm, for the same probe id,
// in the same minute, and Sandbox ANSWERED it (400 InvalidTransactionId — authenticated). The Worker, asking
// the same question, gets a bodiless 401. Identical code cannot produce both, so an INPUT differs — and a 401
// is silent about which one. Every candidate is a secret, so the difference has to be shown without showing
// any of them.
//
// A fingerprint does that. Each value is hashed and only twelve hex characters come back, which is enough to
// say EQUAL or DIFFERENT and not enough to recover a 36-character issuer id or a private key. The public key
// is derived from the stored private key and fingerprinted from its x/y coordinates: those coordinates are
// public by definition — Apple has them — and they identify WHICH key is stored without exposing it.
//
// The rule this obeys: do not ask for the secret. It is never asked for, never printed and never returned.
async function fp(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 12);
}

// The SHAPE of each credential, which is knowable without knowing the value. An Issuer ID is a UUID and a Key
// ID is a short alphanumeric run; a value that is neither cannot be right, and saying so beats a bodiless 401.
// MEASURED 2026-09-23: the stored issuer was 89 characters — a multi-line clipboard flattened by `tr -d
// '[:space:]'` into one string — while the key and key id were exactly right. Nothing looked at the shape, so
// three correct inputs and one impossible one produced the same silent 401 as four wrong ones would.
export const ISSUER_ID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const KEY_ID_SHAPE = /^[A-Z0-9]{8,12}$/;

export function credentialShape(cfg) {
  const problems = [];
  if (!ISSUER_ID_SHAPE.test(cfg.issuerId)) problems.push('issuer_id_is_not_a_uuid');
  if (!KEY_ID_SHAPE.test(cfg.keyId)) problems.push('key_id_is_not_a_key_id');
  if (!/BEGIN PRIVATE KEY|^[A-Za-z0-9+/=\s\\n-]+$/.test(cfg.privateKey)) problems.push('private_key_is_not_pem');
  if (!/^[a-z0-9.-]+$/i.test(cfg.bundleId)) problems.push('bundle_id_is_not_a_bundle_id');
  return problems;
}

export async function credentialFingerprints(cfg) {
  const out = {
    problems: credentialShape(cfg),
    issuerIdLen: cfg.issuerId.length, issuerIdFp: await fp(cfg.issuerId),
    keyIdLen: cfg.keyId.length, keyIdFp: await fp(cfg.keyId),
    bundleId: cfg.bundleId,      // not a secret: it ships inside the app binary
    publicKeyFp: null,
  };
  try {
    const pem = cfg.privateKey.replace(/\\n/g, '').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const jwk = await crypto.subtle.exportKey('jwk', key);
    out.publicKeyFp = await fp(`${jwk.x}.${jwk.y}`);   // the PUBLIC point only — d is never read
  } catch { out.publicKeyFp = 'unreadable'; }
  return out;
}

// IS THIS KEY THE RIGHT KEY? — the question a 401 cannot answer on its own (Ehsan 2026-09-22).
//
// The App Store Server API and the App Store Connect API take DIFFERENT keys, and both are generated on the
// same page. A Team Key authenticates against App Store Connect and is refused by the Server API, which is
// exactly the failure that looks like "the secret is wrong" when the secret is perfectly fine and simply of
// the wrong kind. Apple's own documented probe is the sandbox test-notification endpoint, which sends nothing
// to anybody and only reports whether the caller is authorised.
//
// It returns a STATUS and a reason. Never the key, never the token, never any part of either.
export async function appleKeyProbe(cfg, fetchImpl = fetch, nowSec, environment = 'Sandbox') {
  let token;
  try { token = await signAppleJwt(cfg, nowSec); }
  catch (e) { return { keyLoads: false, reason: 'apple_key_unusable', detail: String(e?.name || 'error') }; }
  // A TRANSACTION LOOKUP IS A BETTER KEY PROBE THAN A TEST NOTIFICATION (2026-09-23). notifications/test
  // depends on a server-notification URL being configured in App Store Connect, so its 404 confounds "the key
  // is wrong" with "you have not set a webhook". Reading a transaction that cannot exist separates every case
  // in ONE call and reads nothing belonging to anybody.
  const probeId = '0'.repeat(16);   // syntactically valid, cannot belong to a real purchase
  let res;
  try {
    res = await fetchImpl(`${APPLE_HOSTS[environment]}/inApps/v1/transactions/${probeId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch {
    return { keyLoads: true, environment, reason: 'apple_unreachable' };
  }
  if (res.status === 200) return { keyLoads: true, environment, status: 200, reason: 'ok' };
  const { code, named } = await readAppleError(res);
  const base = { keyLoads: true, environment, status: res.status, appleErrorCode: code, appleError: named };
  // THE KEY IS GOOD when Apple got far enough to say something about the transaction itself.
  if (PROBE_AUTHENTICATED.has(named)) return { ...base, reason: 'ok' };
  if (res.status === 401) return { ...base, reason: 'apple_rejected_key' };
  if (named === 'app_not_found') return { ...base, reason: 'apple_app_not_in_environment' };
  return { ...base, reason: 'apple_http_' + res.status };
}

// ── APP STORE SERVER NOTIFICATIONS v2 ────────────────────────────────────────
// Apple tells us within seconds when a subscription is refunded, revoked, expires or fails to renew. Without
// this, a refunded customer keeps a paid plan until their expiry date — we would have given away the service
// AND the money back.
//
// WE DO NOT VERIFY THE JWS CHAIN, AND THAT IS THE SAFER CHOICE, not a shortcut. Verifying a v2 payload means
// hand-rolling X.509 chain validation up to Apple's root inside a Worker — security-critical code where one
// bug lets anyone mint a Max plan by posting their own JWS. Instead the payload is treated as UNTRUSTED from
// the first line: we read only the original transaction id out of it, and then ASK APPLE ourselves over the
// authenticated Server API, exactly as iapValidate does. A forged notification names a transaction Apple's own
// API refutes, so the forgery fails on the answer rather than on our parsing of the claim. The trust boundary
// is TLS to Apple, which is where it already is for every other decision here.
//
// ALWAYS 200 WHEN WE HAVE UNDERSTOOD IT. Apple retries anything else, and a retry storm against a route that
// is working but disagrees is worse than a missed notification we can catch on reconciliation.
export const REVOKING_TYPES = new Set(['REFUND', 'REVOKE', 'EXPIRED', 'GRACE_PERIOD_EXPIRED']);
export const RENEWING_TYPES = new Set(['DID_RENEW', 'SUBSCRIBED', 'DID_CHANGE_RENEWAL_STATUS', 'OFFER_REDEEMED', 'RESUBSCRIBE']);

// PURE: pull what we need out of an untrusted payload. Never throws — a payload we cannot read is a refusal,
// not a crash, because the sender is not authenticated.
export function readNotification(signedPayload) {
  let outer;
  try { outer = decodeJwsPayload(signedPayload); } catch { return null; }
  const type = typeof outer?.notificationType === 'string' ? outer.notificationType : null;
  const uuid = typeof outer?.notificationUUID === 'string' ? outer.notificationUUID : null;
  if (!type || !uuid) return null;
  let tx = null;
  try {
    const signed = outer?.data?.signedTransactionInfo;
    if (typeof signed === 'string') tx = decodeJwsPayload(signed);
  } catch { tx = null; }
  const original = tx?.originalTransactionId != null ? String(tx.originalTransactionId)
    : (outer?.data?.originalTransactionId != null ? String(outer.data.originalTransactionId) : null);
  return {
    type, uuid,
    subtype: typeof outer?.subtype === 'string' ? outer.subtype : null,
    originalTransactionId: /^\d{1,32}$/.test(String(original || '')) ? String(original) : null,
    // The transaction id to ASK Apple about. Apple's own is preferred; the original is the fallback.
    transactionId: tx?.transactionId != null && /^\d{1,32}$/.test(String(tx.transactionId)) ? String(tx.transactionId) : null,
  };
}

export async function appleNotification(request, env, fetchImpl = fetch) {
  const body = await readJson(request);
  const signedPayload = body && typeof body.signedPayload === 'string' ? body.signedPayload : '';
  if (!signedPayload) return fail(400, 'A signed payload is required.', 'no_payload');
  const note = readNotification(signedPayload);
  // Unreadable: refuse LOUDLY rather than 200. A 400 here means the sender is not Apple, or Apple changed the
  // shape — both are things we must find out about, and Apple's retries are how we would notice.
  if (!note) return fail(400, 'Unreadable notification.', 'unreadable');

  // IDEMPOTENT. Apple retries until it gets a 2xx, and does not deduplicate; a repeated RENEWAL would extend an
  // entitlement twice. The insert IS the lock: if the row already exists we have handled it and say so.
  const taken = await env.DB.prepare(
    'INSERT OR IGNORE INTO apple_notifications (notification_uuid, notification_type, subtype, original_transaction_id, outcome, received_at) VALUES (?, ?, ?, ?, ?, ?)',
  ).bind(note.uuid, note.type, note.subtype, note.originalTransactionId, 'received', nowIso()).run();
  if (!taken?.meta?.changes) return json(200, { ok: true, duplicate: true });

  const settle = async outcome => {
    await env.DB.prepare('UPDATE apple_notifications SET outcome = ? WHERE notification_uuid = ?')
      .bind(outcome, note.uuid).run();
    return json(200, { ok: true, outcome });
  };

  // WHOSE ACCOUNT. One Apple subscription binds to exactly one Vezvezak account (iapValidate enforces it), so
  // the original transaction id is the only link we need — and a notification for a transaction we have never
  // seen is not an error, it is somebody who has not signed in yet.
  if (!note.originalTransactionId) return settle('ignored_unknown_txn');
  const row = await env.DB.prepare('SELECT user_id FROM user_plans WHERE original_transaction_id = ?')
    .bind(note.originalTransactionId).first();
  if (!row?.user_id) return settle('ignored_unknown_txn');

  // REVOCATION IS IMMEDIATE AND NEEDS NO CONFIRMATION FROM APPLE. Taking a plan AWAY on a forged notification
  // costs a customer their service for one refresh; LEAVING one in place on a real refund costs us the service
  // and the money. The asymmetry decides: revoke first, on the notification alone.
  if (REVOKING_TYPES.has(note.type)) {
    await env.DB.prepare(
      "UPDATE user_plans SET plan = 'free', expires_at = NULL, updated_at = ? WHERE user_id = ? AND original_transaction_id = ?",
    ).bind(nowIso(), row.user_id, note.originalTransactionId).run();
    return settle('revoked');
  }

  // GRANTING IS THE OPPOSITE: never on the notification's word. We ask Apple, over the authenticated Server
  // API, and take the entitlement from THEIR answer — the same door iapValidate uses.
  const cfg = appleConfig(env);
  if (!cfg) return settle('refused_unverified');
  const askAbout = note.transactionId || note.originalTransactionId;
  const fetched = await fetchTransaction(askAbout, cfg, fetchImpl);
  if (!fetched.ok) return settle('refused_unverified');
  const verdict = evaluateTransaction(fetched.transaction, cfg);
  if (!verdict.ok) return settle('refused_unverified');
  await env.DB.prepare(
    `UPDATE user_plans SET plan = ?, expires_at = ?, source = 'apple', environment = ?, updated_at = ?
     WHERE user_id = ? AND original_transaction_id = ?`,
  ).bind(verdict.plan, verdict.expiresAt, fetched.environment, nowIso(), row.user_id, note.originalTransactionId).run();
  return settle('granted');
}
