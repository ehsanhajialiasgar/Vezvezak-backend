// Account deletion + export are REAL (Ehsan 2026-08-13). The app promises the
// user's data is erased and cannot be undone, so these fail the build if that ever
// stops being true. Ehsan's decision: FULL DELETION of everything the user created
// (reviews, app reviews and merchant listings included — free-text can carry
// personal detail that nulling a foreign key would leave behind). affiliate_clicks,
// conversions, an incoming referred_hash and telemetry stay (not attributable).
//
// Part 1 (source/schema scans) runs on any Node. Part 2 (behavioral) runs the REAL
// accountDelete/accountExport against an in-memory SQLite from schema.sql; it
// self-skips where node:sqlite is unavailable (e.g. Node 22 CI without the flag).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = (f) => readFileSync(resolve(HERE, '..', 'src', f), 'utf8');
const SCHEMA = readFileSync(resolve(HERE, '..', 'schema.sql'), 'utf8');
const IDX = SRC('index.js');

let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

console.log('\nThe endpoints exist and delete the right tables');
await t('both /account/export and /account/delete are routed', () => {
  assert.match(IDX, /p === '\/account\/export'\) return accountExport/);
  assert.match(IDX, /p === '\/account\/delete'\) return accountDelete/);
});
await t('reviews, app_reviews and merchant listings are DELETED (full erasure)', () => {
  for (const tbl of ['reviews', 'app_reviews', 'merchants', 'catalog_items', 'jobs', 'influencers', 'verifications', 'feedback', 'referral_codes', 'user_plans', 'weekly_search_usage', 'consumed_searches']) {
    assert.ok(new RegExp(`DELETE_BY_USER_ID = \\[[^\\]]*'${tbl}'`).test(IDX), `${tbl} must be in the delete list`);
  }
  assert.ok(!/UPDATE reviews SET user_id = NULL/.test(IDX), 'no anonymise path — full deletion today');
});
// ORPHAN-CAPABLE WRITES (2026-09-15). A row written with user_id NULL is unreachable by accountDelete, so every §11
// "we remove …" sentence would carry an unwritten exception. DERIVED: every INSERT binding `claims?.sub || null`.
// merchants and reviews must never be in it (both reachable, both named in §11). The rest are OPEN, with the distinction
// the founder stated 2026-09-15: ENDPOINT OPEN, PATH CLOSED — no reachable app path writes them, so our own app
// cannot create an orphan today; a caller outside the app still can.
await t('no merchant listing or review can be written without an account; other anonymous writes are declared, not hidden', () => {
  // jobs + influencers routes were DELETED 2026-09-15, so their anonymous INSERTs are gone from the derivation.
  const OPEN_FOR_FOUNDER = new Set(['app_reviews', 'feedback']);
  const fns = IDX.split(/\n(?=(?:export\s+)?async function )/);
  const orphanTables = fns.filter(f => /claims\?\.sub \|\| null/.test(f))
    .flatMap(f => [...f.matchAll(/INSERT INTO (\w+)/g)].map(m => m[1]));
  assert.ok(fns.length > 20, 'COULD NOT VERIFY — handlers not split');
  assert.ok(!orphanTables.includes('merchants'), 'merchants must require auth (user_id never NULL)');
  assert.ok(!orphanTables.includes('reviews'), 'reviews must require auth (§11: every review you wrote is deleted)');
  const undeclared = [...new Set(orphanTables)].filter(x => !OPEN_FOR_FOUNDER.has(x));
  assert.deepEqual(undeclared, [], 'a new anonymous write into a deletable table must be declared here, with the founder');
  const fn = fns.find(f => /^async function merchantSubmit/.test(f) || /\nasync function merchantSubmit/.test('\n' + f));
  assert.match(fn, /if \(!claims\) return fail\(401/);
  const rv = fns.find(f => /^async function reviewSubmit/.test(f) || /\nasync function reviewSubmit/.test('\n' + f));
  assert.match(rv, /if \(!claims\) return fail\(401/);
});
await t('catalog_variants (no user_id) is deleted via the user\'s items first', () => {
  assert.match(IDX, /DELETE FROM catalog_variants WHERE item_id IN \(SELECT id FROM catalog_items WHERE user_id = \?\)/);
});
await t('identifier tables, outbound referrals and abuse counters are cleared; users LAST; atomic', () => {
  assert.match(IDX, /DELETE FROM otp_codes WHERE identifier = \?/);
  assert.match(IDX, /DELETE FROM reset_tokens WHERE identifier = \?/);
  assert.match(IDX, /DELETE FROM referrals WHERE referrer_code = \?/);
  assert.match(IDX, /DELETE FROM rate_limits WHERE bucket LIKE \?/);
  assert.match(IDX, /DELETE FROM users WHERE id = \?[\s\S]*?env\.DB\.batch\(stmts\)/, 'users deleted last, then one atomic batch');
});
await t('export never SELECTs password material', () => {
  const fn = IDX.slice(IDX.indexOf('async function accountExport'), IDX.indexOf('async function accountExport') + 1700);
  // no SELECT line may pull a password field (the header comment naming them is fine)
  assert.ok(!/SELECT[^\n]*(pw_hash|pw_salt|pw_iter)/i.test(fn), 'export must not select password fields');
  assert.ok(!/SELECT \* FROM users/.test(fn), 'export must use an explicit safe column list for the account');
  assert.match(fn, /reviews:.*FROM reviews WHERE user_id = \?/);
});
await t('delete returns success only after finding a real account', () => {
  const fn = IDX.slice(IDX.indexOf('async function accountDelete'), IDX.indexOf('async function accountExport'));
  assert.match(fn, /if \(!user\) return fail\(404/, 'no account → not success');
  assert.match(fn, /ok\(\{ deleted: true \}\)/);
});

// ── Part 2: behavioral, against real SQLite ──────────────────────────────────
let DatabaseSync;
try { ({ DatabaseSync } = await import('node:sqlite')); }
catch { console.log('\nNOTICE: node:sqlite unavailable — behavioral erasure test skipped (structure covered above).'); console.log(`\n  ${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0); }

const { signJwt, bucketSubject } = await import('../src/lib.js');
const { accountDelete, accountExport } = await import('../src/index.js');

const db = new DatabaseSync(':memory:');
db.exec(SCHEMA);
function makeD1(database) {
  return {
    prepare(sql) {
      const stmt = database.prepare(sql);
      let bound = [];
      const api = {
        bind(...a) { bound = a; return api; },
        async first() { const r = stmt.get(...bound); return r === undefined ? null : r; },
        async run() { const r = stmt.run(...bound); return { meta: { changes: r.changes } }; },
        async all() { return { results: stmt.all(...bound) }; },
      };
      return api;
    },
    async batch(list) { const out = []; for (const s of list) out.push(await s.run()); return out; },
  };
}
const env = { DB: makeD1(db), JWT_SECRET: 'test-secret' };
const iso = new Date().toISOString();
const ID = 'user-under-test@example.test';        // the account identifier (redacted style)

// Seed a user with a row in (nearly) every table that holds user data — including a
// catalog_variant (no user_id, must go via the item) — plus a SECOND user whose
// rows must be left completely untouched.
function seed(uid, identifier, tag) {
  db.prepare('INSERT INTO users (id,identifier,channel,name,pw_hash,pw_salt,pw_iter,verified,created_at) VALUES (?,?,?,?,?,?,?,0,?)').run(uid, identifier, 'email', 'Name', 'HASH', 'SALT', 210000, iso);
  db.prepare('INSERT INTO reviews (id,user_id,subject,stars,text,lang,created_at,ip_hash) VALUES (?,?,?,?,?,?,?,?)').run('rev_' + tag, uid, 'Widget', 5, 'great widget', 'en', iso, 'IPHASH_' + tag);
  db.prepare('INSERT INTO app_reviews (id,user_id,stars,text,approved,created_at) VALUES (?,?,?,?,?,?)').run('arv_' + tag, uid, 5, 'love the app', 1, iso);
  db.prepare('INSERT INTO merchants (id,user_id,store_name,address,status,submitted_at) VALUES (?,?,?,?,?,?)').run('mer_' + tag, uid, 'Store', 'Somewhere', 'live', iso);
  db.prepare('INSERT INTO catalog_items (id,merchant_id,user_id,title,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?)').run('cit_' + tag, 'mer_' + tag, uid, 'Item', 'live', iso, iso);
  db.prepare('INSERT INTO catalog_variants (id,item_id,merchant_id,price,created_at) VALUES (?,?,?,?,?)').run('var_' + tag, 'cit_' + tag, 'mer_' + tag, 9.99, iso);
  db.prepare('INSERT INTO jobs (id,user_id,title,business,status,submitted_at) VALUES (?,?,?,?,?,?)').run('job_' + tag, uid, 'Job', 'Biz', 'live', iso);
  db.prepare('INSERT INTO influencers (id,user_id,name,handle,status,submitted_at) VALUES (?,?,?,?,?,?)').run('inf_' + tag, uid, 'Inf', '@h', 'live', iso);
  db.prepare('INSERT INTO verifications (id,user_id,kind,status,submitted_at) VALUES (?,?,?,?,?)').run('ver_' + tag, uid, 'seller', 'pending', iso);
  db.prepare('INSERT INTO feedback (id,user_id,kind,text,status,created_at) VALUES (?,?,?,?,?,?)').run('fb_' + tag, uid, 'bug', 'hi', 'new', iso);
  db.prepare('INSERT INTO referral_codes (code,user_id,created_at) VALUES (?,?,?)').run('CODE_' + tag, uid, iso);
  db.prepare('INSERT INTO referrals (id,referrer_code,referred_hash,created_at) VALUES (?,?,?,?)').run('ref_' + tag, 'CODE_' + tag, 'DEVHASH_' + tag, iso);
  db.prepare('INSERT INTO user_plans (user_id,plan,updated_at) VALUES (?,?,?)').run(uid, 'pro', iso);
  db.prepare('INSERT INTO weekly_search_usage (user_id,local_used,online_used,window_start,refill_dow,refill_minute) VALUES (?,?,?,?,?,?)').run(uid, 3, 4, 1, 2, 100);
  db.prepare('INSERT INTO consumed_searches (user_id,search_id,kind,window_start,photos_used,created_at) VALUES (?,?,?,?,?,?)').run(uid, 'S1', 'local', 1, 0, iso);
  db.prepare('INSERT INTO otp_codes (id,identifier,purpose,code_hash,expires_at,created_at) VALUES (?,?,?,?,?,?)').run('otp_' + tag, identifier, 'signin', 'H', 1, 1);
  db.prepare('INSERT INTO reset_tokens (token,identifier,expires_at) VALUES (?,?,?)').run('tok_' + tag, identifier, 1);
  // Bucket names hold a keyed hash of the subject (lib.rateLimit, 2026-09-15) — seeded the way rateLimit stores them.
  const now = Date.now();
  db.prepare('INSERT INTO rate_limits (bucket,count,window_at) VALUES (?,?,?)').run('login:' + BUCKET[identifier], 1, now);
  db.prepare('INSERT INTO rate_limits (bucket,count,window_at) VALUES (?,?,?)').run('merchant:' + BUCKET[uid], 1, now);
}
const BUCKET = {};
for (const x of ['usr_del', ID, 'usr_keep', 'other_user@example.test']) BUCKET[x] = await bucketSubject(x, env);
seed('usr_del', ID, 'del');
seed('usr_keep', 'other_user@example.test', 'keep');   // an '_' in the identifier: a LIKE wildcard if unescaped

async function call(fn, token, body) {
  const req = { headers: { get: (k) => (k.toLowerCase() === 'authorization' ? (token ? `Bearer ${token}` : null) : null) }, json: async () => body || {} };
  const res = await fn(req, env);
  return { status: res.status, body: await res.json() };
}
const delTok = await signJwt({ sub: 'usr_del', identifier: ID }, env.JWT_SECRET);

console.log('\n(e) export exists and returns the user\'s data (no password material)');
await t('export returns the account + its rows, never pw_hash', async () => {
  const r = await call(accountExport, delTok, {});
  assert.equal(r.status, 200);
  const ex = r.body.export;
  assert.equal(ex.account.identifier, ID);
  assert.ok(!('pw_hash' in ex.account) && !('pw_salt' in ex.account), 'no password material in export');
  assert.equal(ex.reviews.length, 1, 'the user\'s review is included');
  assert.equal(ex.merchants.length, 1);
  assert.equal(ex.jobs.length, 1);
});

console.log('\n(d) delete returns success ONLY on a real account');
await t('deleting the real account succeeds', async () => {
  const r = await call(accountDelete, delTok, {});
  assert.equal(r.status, 200);
  assert.equal(r.body.deleted, true);
});
await t('deleting a non-existent account is NOT reported as success', async () => {
  const ghost = await signJwt({ sub: 'usr_ghost', identifier: 'ghost@example.test' }, env.JWT_SECRET);
  const r = await call(accountDelete, ghost, {});
  assert.equal(r.status, 404);
});

console.log('\n(a) schema-driven: after deletion NO row anywhere carries that user_id / identifier');
await t('every table with a user_id column has zero rows for the deleted user', () => {
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all().map(r => r.name);
  let checkedUser = 0, checkedIdent = 0;
  for (const name of tables) {
    const cols = db.prepare(`PRAGMA table_info(${name})`).all().map(c => c.name);
    if (cols.includes('user_id')) {
      checkedUser++;
      assert.equal(db.prepare(`SELECT COUNT(*) c FROM ${name} WHERE user_id = ?`).get('usr_del').c, 0, `${name} still has rows for the deleted user_id`);
    }
    if (cols.includes('identifier')) {
      checkedIdent++;
      assert.equal(db.prepare(`SELECT COUNT(*) c FROM ${name} WHERE identifier = ?`).get(ID).c, 0, `${name} still references the deleted identifier`);
    }
  }
  assert.ok(checkedUser >= 10, `expected to check many user_id tables, checked ${checkedUser}`);
  assert.ok(checkedIdent >= 2, `expected to check identifier tables, checked ${checkedIdent}`);
});
await t('the user\'s content is truly gone (reviews, merchant listing, variant, outbound referrals, buckets)', () => {
  assert.equal(db.prepare("SELECT COUNT(*) c FROM reviews WHERE ip_hash='IPHASH_del'").get().c, 0, 'the review row is deleted, not just nulled');
  assert.equal(db.prepare("SELECT COUNT(*) c FROM merchants WHERE id='mer_del'").get().c, 0);
  assert.equal(db.prepare("SELECT COUNT(*) c FROM catalog_variants WHERE id='var_del'").get().c, 0, 'the child variant is gone too');
  assert.equal(db.prepare("SELECT COUNT(*) c FROM referrals WHERE referrer_code='CODE_del'").get().c, 0);
  assert.equal(db.prepare('SELECT COUNT(*) c FROM rate_limits WHERE bucket = ?').get('login:' + BUCKET[ID]).c, 0);
  assert.equal(db.prepare('SELECT COUNT(*) c FROM rate_limits WHERE bucket = ?').get('merchant:' + BUCKET['usr_del']).c, 0);
  assert.equal(db.prepare("SELECT COUNT(*) c FROM rate_limits WHERE bucket LIKE '%user-under-test%'").get().c, 0, 'no plaintext identifier is stored at all');
});

console.log('\nDeletion touches ONLY the target account');
await t('the second user\'s rows are completely untouched', () => {
  assert.equal(db.prepare("SELECT COUNT(*) c FROM users WHERE id='usr_keep'").get().c, 1);
  assert.equal(db.prepare("SELECT COUNT(*) c FROM reviews WHERE ip_hash='IPHASH_keep'").get().c, 1);
  assert.equal(db.prepare("SELECT COUNT(*) c FROM catalog_variants WHERE id='var_keep'").get().c, 1);
  assert.equal(db.prepare("SELECT COUNT(*) c FROM jobs WHERE user_id='usr_keep'").get().c, 1);
  assert.equal(db.prepare('SELECT COUNT(*) c FROM rate_limits WHERE bucket IN (?, ?)').get('login:' + BUCKET['other_user@example.test'], 'merchant:' + BUCKET['usr_keep']).c, 2, 'the other account\'s counters survive');
});

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
