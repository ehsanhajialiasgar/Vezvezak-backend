// IN-APP PURCHASE VALIDATION — launch chain step 5 (Ehsan 2026-09-14).
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
  const pem = cfg.privateKey.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
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
  const token = await signAppleJwt(cfg, nowSec);
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
      if (env === 'Production') continue;
      return { ok: false, reason: 'apple_not_found' };   // 404 in BOTH environments: Apple has no such transaction
    }
    if (res.status !== 200) return { ok: false, reason: `apple_http_${res.status}` };
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
