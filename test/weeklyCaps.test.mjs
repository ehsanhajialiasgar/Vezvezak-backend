// Weekly-CAP enforcement gates (Ehsan 2026-08-13). These fail the build.
// A wrong cap, a leaked dollar balance, or a free-tier path that reaches a
// billable AI call each cost the self-funding founder real money.
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  WEEKLY_CAPS, METERED_KINDS, PHOTO_PER_SEARCH, resolvePlan, planCaps, billableAiAllowed,
  refillSlot, windowStartFor, nextResetMs, shouldRefill, capReached,
} from '../src/usage.js';
import { moderateReview, moderateCatalogItem } from '../src/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = (f) => readFileSync(resolve(HERE, '..', 'src', f), 'utf8');
const SCHEMA = readFileSync(resolve(HERE, '..', 'schema.sql'), 'utf8');

let pass = 0, fail = 0;
const t = async (n, fn) => { try { await fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

console.log('\n(a) a request beyond cap is refused server-side, not merely hidden in UI');
await t('capReached refuses at/over the cap', () => {
  assert.equal(capReached(18, 18), true);   // exactly at cap → refuse
  assert.equal(capReached(18, 19), true);
  assert.equal(capReached(18, 17), false);
  assert.equal(capReached(0, 0), true);      // free local (cap 0) always refused
});
await t('searchConsume returns 402 cap_reached and never falls through when over cap', () => {
  const s = SRC('index.js');
  assert.match(s, /reason:\s*'cap_reached'/, 'must return a cap_reached refusal');
  assert.match(s, /json\(402,\s*\{\s*allowed:\s*false/, 'refusal is a 402, not a 200');
  // the increment is guarded by `< cap` so a race can never push past the cap
  assert.match(s, /SET \$\{col\} = \$\{col\} \+ 1[\s\S]*?WHERE user_id = \? AND \$\{col\} < \?/, 'increment must be guarded by < cap');
});

console.log('\n(b) NO monetary balance survives — asserted against the REAL schema');
await t('the old per-user dollar table ai_usage is dropped, not created', () => {
  assert.match(SCHEMA, /DROP TABLE IF EXISTS ai_usage/, 'ai_usage must be dropped');
  assert.ok(!/CREATE TABLE IF NOT EXISTS ai_usage\b/.test(SCHEMA), 'ai_usage must NOT be created');
  assert.ok(!/used_usd/.test(SCHEMA), 'no used_usd column may survive anywhere in the schema');
});
await t('weekly_search_usage stores COUNTS only — no money column', () => {
  const block = SCHEMA.match(/CREATE TABLE IF NOT EXISTS weekly_search_usage[\s\S]*?\);/);
  assert.ok(block, 'weekly_search_usage table must exist');
  const cols = block[0];
  for (const money of [/usd/i, /dollar/i, /\bcents?\b/i, /balance/i, /\bcredit/i, /allowance/i, /wallet/i, /\bREAL\b/]) {
    assert.ok(!money.test(cols), `weekly_search_usage must have no money column (${money})`);
  }
  for (const c of ['local_used', 'online_used', 'window_start', 'refill_dow', 'refill_minute']) {
    assert.ok(cols.includes(c), `expected count/window column ${c}`);
  }
});
await t('no per-user dollar balance is minted into the JWT', () => {
  // signJwt payloads in the backend carry identity only, never a spendable balance.
  const s = SRC('index.js');
  const payloads = [...s.matchAll(/signJwt\(\s*(\{[^}]*\})/g)].map(m => m[1]);
  assert.ok(payloads.length > 0, 'expected signJwt call sites');
  for (const p of payloads) for (const money of [/usd/i, /balance/i, /credit/i, /allowance/i, /dollars?/i]) {
    assert.ok(!money.test(p), `JWT payload must not carry a money field: ${p}`);
  }
});

console.log('\n(c) reset REFILLS (not expires) and is STAGGERED per account');
await t('a passed weekly boundary triggers a refill, and next reset is +1 week', () => {
  const dow = 3, minute = 500;
  const now = Date.UTC(2026, 7, 13, 12, 0, 0);           // some Thursday
  const ws = windowStartFor(now, dow, minute);
  assert.ok(ws <= now, 'window start must be at/before now');
  assert.equal(nextResetMs(ws) - ws, 7 * 86400000, 'a window is exactly one week');
  // a window that began before the most recent boundary must refill
  assert.equal(shouldRefill(now, ws - 7 * 86400000, dow, minute), true);
  assert.equal(shouldRefill(now, ws, dow, minute), false);
});
await t('the refill branch resets used→0 (no carry-over) (source)', () => {
  const s = SRC('index.js');
  // Refill zeroes BOTH counts to the same full cap — it never adds leftover
  // capacity (no `+ (cap - used)` or similar carry-over arithmetic).
  assert.match(s, /SET local_used = 0, online_used = 0, window_start = \?/, 'refill zeroes both counts');
});
await t('reset slots are staggered across the week (not a single global instant)', () => {
  const dows = new Set(), minutes = new Set();
  for (let i = 0; i < 400; i++) {
    const { dow, minute } = refillSlot('usr_' + i);
    assert.ok(dow >= 0 && dow <= 6 && Number.isInteger(dow), 'dow in 0-6');
    assert.ok(minute >= 0 && minute <= 1439 && Number.isInteger(minute), 'minute in 0-1439');
    dows.add(dow); minutes.add(minute);
  }
  assert.equal(dows.size, 7, 'resets must spread across all 7 weekdays');
  assert.ok(minutes.size > 50, 'resets must spread across many minutes, not one instant');
});
await t('a slot is stable for a given account', () => {
  assert.deepEqual(refillSlot('usr_stable'), refillSlot('usr_stable'));
});

console.log('\n(d) NO free-tier path reaches Google Places or a billable AI call');
await t('free has zero local (Google Places) slots', () => {
  assert.equal(WEEKLY_CAPS.free.local, 0);
  assert.equal(planCaps('free').local, 0);
});
await t('billable AI is allowed for paid tiers ONLY', () => {
  assert.equal(billableAiAllowed('free'), false);
  assert.equal(billableAiAllowed('pro'), true);
  assert.equal(billableAiAllowed('max'), true);
  assert.equal(billableAiAllowed(undefined), false);   // absent ⇒ free ⇒ no AI
});
await t('moderateReview never touches env.AI on a free plan', async () => {
  const trap = { AI: { run: () => { throw new Error('env.AI CALLED for a free user'); } } };
  const v = await moderateReview(trap, 5, 'a genuine and specific review of this product', 'free');
  assert.equal(v.approved, false);
  assert.equal(v.byModel, false);
  assert.equal(v.note, 'awaiting_moderation');
});
await t('moderateReview DOES moderate on a paid plan', async () => {
  const yes = { AI: { run: async () => ({ response: 'YES' }) } };
  const v = await moderateReview(yes, 5, 'a genuine and specific review of this product', 'pro');
  assert.equal(v.approved, true);
  assert.equal(v.byModel, true);
});
await t('moderateCatalogItem never touches env.AI on a free plan', async () => {
  const trap = { AI: { run: () => { throw new Error('env.AI CALLED for a free user'); } } };
  const status = await moderateCatalogItem(trap, { title: 'Blue Widget', description: 'a nice blue widget', brand: 'Acme', model: 'X1' }, 'free');
  assert.equal(status, 'pending');
});
await t('extract refuses a free plan BEFORE any fetch/AI (source)', () => {
  const s = SRC('extract.js');
  assert.match(s, /billableAiAllowed\(await planFor\(env, claims\.sub\)\)/, 'extract must gate on plan');
});
await t('only local|online are metered — accessibility (voice.*) is never counted', () => {
  assert.ok(METERED_KINDS.has('local') && METERED_KINDS.has('online'));
  for (const k of ['voice.listen', 'voice.speak', 'voice', 'tts', 'compute']) {
    assert.ok(!METERED_KINDS.has(k), `${k} must never be metered`);
  }
});

console.log('\n(e) server caps match pricingStrategy.ts EXACTLY (divergence guard)');
await t('WEEKLY_CAPS mirrors CONSUMER_TIERS localPerWeek/onlinePerWeek', () => {
  const P = resolve(HERE, '..', '..', 'VezvezakNew', 'src', 'services', 'pricingStrategy.ts');
  if (!existsSync(P)) { console.log('     · NOTICE: pricingStrategy.ts sibling absent (single-repo CI) — divergence check deferred to full-tree verify.sh'); return; }
  const src = readFileSync(P, 'utf8');
  for (const key of ['free', 'pro', 'max']) {
    const row = src.match(new RegExp(`key:\\s*'${key}'[^}]*`));
    assert.ok(row, `pricingStrategy.ts must define tier ${key}`);
    const local = Number((row[0].match(/localPerWeek:\s*(\d+)/) || [])[1]);
    const online = Number((row[0].match(/onlinePerWeek:\s*(\d+)/) || [])[1]);
    assert.equal(local, WEEKLY_CAPS[key].local, `${key} local cap must match pricingStrategy.ts (${local} vs ${WEEKLY_CAPS[key].local})`);
    assert.equal(online, WEEKLY_CAPS[key].online, `${key} online cap must match pricingStrategy.ts (${online} vs ${WEEKLY_CAPS[key].online})`);
  }
});
await t('resolvePlan folds legacy/unknown onto a live tier (default free)', () => {
  assert.equal(resolvePlan('max20x'), 'max');
  assert.equal(resolvePlan('enterprise'), 'free');
  assert.equal(resolvePlan(undefined), 'free');
  assert.equal(resolvePlan('pro'), 'pro');
});

console.log('\n(f) Part 1b — a cap counts whole SEARCHES (vz_sid dedupe) + a photo ceiling');
await t('consumed_searches table dedupes on (user, vz_sid, kind) and bounds photos', () => {
  const block = SCHEMA.match(/CREATE TABLE IF NOT EXISTS consumed_searches[\s\S]*?\);/);
  assert.ok(block, 'consumed_searches table must exist');
  const cols = block[0];
  assert.match(cols, /PRIMARY KEY \(user_id, search_id, kind\)/, 'PK must dedupe a bundle by (user, vz_sid, kind)');
  assert.match(cols, /photos_used\s+INTEGER/, 'must track photos_used for the sub-call ceiling');
  for (const money of [/usd/i, /balance/i, /\bREAL\b/, /dollar/i]) assert.ok(!money.test(cols), `no money column (${money})`);
});
await t('searchConsume dedupes sub-calls into one slot (insert-first, idempotent)', () => {
  const s = SRC('index.js');
  assert.match(s, /INSERT OR IGNORE INTO consumed_searches/, 'first sub-call inserts the dedupe row');
  assert.match(s, /idempotent:\s*true/, 'a repeat sub-call is allowed without a second increment');
  // a refused race must not leave a phantom slot behind
  assert.match(s, /DELETE FROM consumed_searches WHERE user_id = \? AND search_id = \?/, 'a lost-race must undo its dedupe row');
});
await t('photoConsume bounds photos per search and requires a consumed local slot', () => {
  const s = SRC('index.js');
  assert.match(s, /photos_used = photos_used \+ 1[\s\S]*?AND photos_used < \?/, 'photo bump is guarded by the ceiling');
  assert.match(s, /AND kind = \? AND window_start = \?/, 'photo must match an existing consumed (local) slot');
  assert.match(s, /reason:\s*'photo_ceiling_or_no_search'/, 'over-ceiling / no-slot refuses');
});
await t('PHOTO_PER_SEARCH is a small positive integer (6)', () => {
  assert.equal(PHOTO_PER_SEARCH, 6);
  assert.ok(Number.isInteger(PHOTO_PER_SEARCH) && PHOTO_PER_SEARCH > 0 && PHOTO_PER_SEARCH < 20);
});

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
