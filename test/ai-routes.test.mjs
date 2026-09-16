// /ai/normalize (intent resolution) and /ai/chat (per-user weekly turns) — behaviour, against the REAL handlers on an
// in-memory SQLite built from schema.sql, with a fake Workers AI (Ehsan 2026-09-16). Run: node test/ai-routes.test.mjs
// Self-skips the behavioural part where node:sqlite is unavailable.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA = readFileSync(resolve(HERE, '..', 'schema.sql'), 'utf8');
let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

let DatabaseSync;
try { ({ DatabaseSync } = await import('node:sqlite')); }
catch { console.log('NOTICE: node:sqlite unavailable — behavioural AI route tests skipped.'); process.exit(0); }

const { signJwt } = await import('../src/lib.js');
const { aiNormalize, aiChat, accountExport } = await import('../src/index.js');
const { AI_WEEKLY_TURNS } = await import('../src/usage.js');
const { CACHE_RETENTION_MS } = await import('../src/translate.js');

const db = new DatabaseSync(':memory:');
db.exec(SCHEMA);
const D1 = {
  prepare(sql) {
    const stmt = db.prepare(sql); let bound = [];
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
let answers = {}, calls = [];
const AI = { run: async (model, input) => {
  const q = input.messages?.find(m => m.role === 'user')?.content ?? '';
  calls.push({ model, q });
  const a = typeof answers === 'function' ? answers(q) : answers[q];
  if (a instanceof Error) throw a;
  return { response: a ?? 'CONTEXT ANSWER' };
} };
const env = (flags = {}) => ({ DB: D1, JWT_SECRET: 's', AI, AI_NORMALIZE_ENABLED: '1', AI_CHAT_ENABLED: '1', ...flags });
const req = (body, token) => ({ headers: { get: k => (k.toLowerCase() === 'authorization' && token ? `Bearer ${token}` : null) }, json: async () => body });
const call = async (fn, e, body, token) => { const r = await fn(req(body, token), e); return { status: r.status, body: await r.json() }; };

console.log('\n/ai/normalize — intent, any script, checked, cached, retained 30 days');
await t('flag off → resolved:false "disabled", and the model is never called', async () => {
  calls = []; answers = { 'نمک': 'salt' };
  const r = await call(aiNormalize, env({ AI_NORMALIZE_ENABLED: '0' }), { query: 'نمک' });
  assert.deepEqual([r.body.resolved, r.body.reason, r.body.query], [false, 'disabled', 'نمک']);
  assert.equal(calls.length, 0);
});
await t('نمک → salt (resolved); the second ask is served from the cache (one model call)', async () => {
  calls = []; answers = { 'نمک': 'salt' };
  const a = await call(aiNormalize, env(), { query: 'نمک' });
  const b = await call(aiNormalize, env(), { query: 'نمک' });
  assert.deepEqual([a.body.resolved, a.body.query, b.body.query], [true, 'salt', 'salt']);
  assert.equal(calls.length, 1);
});
await t('no language list: plain-ASCII Spanish goes to the model too', async () => {
  calls = []; answers = { silla: 'chair' };
  const r = await call(aiNormalize, env(), { query: 'silla' });
  assert.deepEqual([r.body.resolved, r.body.query, calls.length], [true, 'chair', 1]);
});
await t('[[UNKNOWN]] → unresolved "unknown", and that answer is cached too', async () => {
  calls = []; answers = { 'كيف': '[[UNKNOWN]]' };
  const a = await call(aiNormalize, env(), { query: 'كيف' });
  const b = await call(aiNormalize, env(), { query: 'كيف' });
  assert.deepEqual([a.body.resolved, a.body.reason, b.body.reason, calls.length], [false, 'unknown', 'unknown', 1]);
});
await t('[[UNKNOWN]] with a sentence in the user\'s language → the sentence is returned, and served from the cache the same way', async () => {
  calls = []; answers = { 'سلام': '[[UNKNOWN]] لطفا محصول مورد نظر خود را به روش دیگری بنامید' };
  const a = await call(aiNormalize, env(), { query: 'سلام' });
  const b = await call(aiNormalize, env(), { query: 'سلام' });
  assert.deepEqual([a.body.reason, a.body.message, b.body.message, calls.length], ['unknown', 'لطفا محصول مورد نظر خود را به روش دیگری بنامید', 'لطفا محصول مورد نظر خود را به روش دیگری بنامید', 1]);
});
await t('a model number the answer dropped → rejected (never a guessed product)', async () => {
  answers = { 'هدفون WH-1000XM5': 'wireless headphones' };
  const r = await call(aiNormalize, env(), { query: 'هدفون WH-1000XM5' });
  assert.deepEqual([r.body.resolved, r.body.reason], [false, 'rejected']);
});
await t('an answer still in another script → rejected', async () => {
  answers = { 'میز چوبی': 'میز wooden' };
  const r = await call(aiNormalize, env(), { query: 'میز چوبی' });
  assert.equal(r.body.resolved, false);
});
await t('model error → unresolved "model_error"', async () => {
  answers = { 'قهوه': new Error('down') };
  const r = await call(aiNormalize, env(), { query: 'قهوه' });
  assert.deepEqual([r.body.resolved, r.body.reason], [false, 'model_error']);
});
await t('retention: an entry older than 30 days is not used, and a write deletes it', async () => {
  const old = Date.now() - CACHE_RETENTION_MS - 60_000;
  db.prepare("INSERT INTO translation_cache (k, translated, at) VALUES ('stale-key', 'stale', ?)").run(old);
  db.prepare('UPDATE translation_cache SET at = ?').run(old);   // every entry so far is now expired
  calls = []; answers = { 'نمک': 'salt' };
  const r = await call(aiNormalize, env(), { query: 'نمک' });
  assert.deepEqual([r.body.query, calls.length], ['salt', 1], 'expired cache entry was not used');
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM translation_cache WHERE at < ?").get(Date.now() - CACHE_RETENTION_MS).n, 0);
});

console.log('\n/ai/chat — signed in, plan turns per week, atomic, refunded on model error');
const iso = new Date().toISOString(), future = new Date(Date.now() + 86_400_000).toISOString();
for (const [u, plan] of [['u_free', 'free'], ['u_pro', 'pro'], ['u_other', 'pro']]) db.prepare('INSERT INTO user_plans (user_id, plan, expires_at, source, updated_at) VALUES (?,?,?,?,?)').run(u, plan, future, 'comp', iso);
const tok = async u => signJwt({ sub: u, identifier: `${u}@x.test` }, 's');
const ask = { system: 'SYS', context: { offers: [] }, messages: [{ role: 'user', content: 'which is cheapest?' }] };
const turns = u => db.prepare("SELECT COUNT(*) AS n FROM consumed_searches WHERE user_id = ? AND kind = 'ai'").get(u).n;

await t('flag off → 503, before anything else', async () => {
  const r = await call(aiChat, env({ AI_CHAT_ENABLED: '0' }), ask, await tok('u_pro'));
  assert.equal(r.status, 503);
});
await t('signed out → 401', async () => {
  assert.equal((await call(aiChat, env(), ask, null)).status, 401);
});
await t('free plan → 402 "plan", no turn taken, model not called', async () => {
  calls = [];
  const r = await call(aiChat, env(), ask, await tok('u_free'));
  assert.deepEqual([r.status, r.body.reason, turns('u_free'), calls.length], [402, 'plan', 0, 0]);
});
await t('pro: a turn is taken and answered', async () => {
  answers = () => 'X is cheapest';
  const r = await call(aiChat, env(), ask, await tok('u_pro'));
  assert.deepEqual([r.status, r.body.reply, turns('u_pro')], [200, 'X is cheapest', 1]);
});
await t('model error → the turn is refunded', async () => {
  answers = () => new Error('down');
  const r = await call(aiChat, env(), ask, await tok('u_pro'));
  assert.deepEqual([r.status, turns('u_pro')], [503, 1]);
});
await t(`at the cap (${AI_WEEKLY_TURNS.pro}) → 402 "cap_reached", no extra row, model not called; another account is unaffected`, async () => {
  const ws = db.prepare('SELECT window_start FROM weekly_search_usage WHERE user_id = ?').get('u_pro').window_start;
  const ins = db.prepare("INSERT INTO consumed_searches (user_id, search_id, kind, window_start, photos_used, created_at) VALUES ('u_pro', ?, 'ai', ?, 0, ?)");
  for (let i = turns('u_pro'); i < AI_WEEKLY_TURNS.pro; i++) ins.run(`seed${i}`, ws, iso);
  calls = []; answers = () => 'ok';
  const r = await call(aiChat, env(), ask, await tok('u_pro'));
  assert.deepEqual([r.status, r.body.reason, turns('u_pro'), calls.length], [402, 'cap_reached', AI_WEEKLY_TURNS.pro, 0]);
  const o = await call(aiChat, env(), ask, await tok('u_other'));
  assert.equal(o.status, 200);
});
await t('a question with no result context takes no turn', async () => {
  const before = turns('u_other');
  const r = await call(aiChat, env(), { ...ask, context: null }, await tok('u_other'));
  assert.deepEqual([r.status, turns('u_other')], [200, before]);
});
await t('the account export reports assistant turns', async () => {
  db.prepare('INSERT INTO users (id,identifier,channel,name,pw_hash,pw_salt,pw_iter,verified,created_at) VALUES (?,?,?,?,?,?,?,0,?)').run('u_pro', 'u_pro@x.test', 'email', 'P', 'H', 'S', 1, iso);
  const r = await call(accountExport, env(), {}, await tok('u_pro'));
  assert.equal(r.body.export.assistantTurns[0].turns, AI_WEEKLY_TURNS.pro);
});

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
