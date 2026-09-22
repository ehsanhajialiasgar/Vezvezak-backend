// PRE-AUTH METERED CEILING GATE (Ehsan 2026-08-26). Build-failing.
//
// The shape this locks, not the one route: a route reachable WITHOUT auth that can reach
// a metered THIRD-PARTY host (Resend email, Workers AI) must be bounded by a ceiling
// BROADER than a per-identifier limit. A per-identifier-only limit is defeated by
// rotating the identifier (the 1.4 trace found exactly this on /auth/otp/request: a
// metered Resend send capped only at 5/h per identifier = no real ceiling). "Broader"
// means a GLOBAL bucket (a literal rateLimit key, no ${…}) or a PER-IP bucket (a key
// mentioning ip). Tie the test to the shape so the next such route cannot slip past.
//
// Same self-running harness as the other backend tests: CI runs `node <file>` and the
// process exits 1 on any failure.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

let pass = 0, fail = 0;
const t = (n, fn) => { try { fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

const SRC = new URL('../src/', import.meta.url);
const files = readdirSync(SRC).filter(f => f.endsWith('.js'));
const sources = files.map(f => readFileSync(new URL(f, SRC), 'utf8'));
const all = sources.join('\n');

// A metered third-party host the BACKEND reaches directly (edit when a new one is added).
const METERED = /api\.resend\.com|\benv\.AI\b/;

// Brace-matched top-level function bodies, name -> body (across all backend files).
function functionsOf(code, into) {
  const re = /(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\([^)]*\)\s*\{/g;
  let m;
  while ((m = re.exec(code))) {
    let i = code.indexOf('{', m.index), depth = 0, j = i;
    for (; j < code.length; j++) { if (code[j] === '{') depth++; else if (code[j] === '}') { depth--; if (depth === 0) { j++; break; } } }
    into[m[1]] = code.slice(i, j);
  }
}
const FN = {};
for (const code of sources) functionsOf(code, FN);

// Does this function transitively reach a metered host (itself, or via a callee)?
const memo = {};
function reachesMetered(name, seen = new Set()) {
  if (name in memo) return memo[name];
  if (seen.has(name)) return false;
  seen.add(name);
  const body = FN[name];
  if (!body) return false;
  if (METERED.test(body)) return (memo[name] = true);
  for (const other of Object.keys(FN)) {
    if (other !== name && new RegExp(`\\b${other}\\s*\\(`).test(body) && reachesMetered(other, seen)) return (memo[name] = true);
  }
  return (memo[name] = false);
}

// Route handlers: the function dispatched by `p === '/path') return HANDLER(`.
const handlers = [...all.matchAll(/p\s*===\s*'[^']+'\s*\)\s*return\s+([A-Za-z0-9_]+)\s*\(/g)].map(m => m[1]);

// Pre-auth = the handler body does not require a verified session.
const isPreAuth = body => !/requireAuth\s*\(/.test(body);

// A ceiling BROADER than per-identifier: a literal (global) rateLimit bucket, or a
// bucket keyed on IP. A `${identifier}`-style template bucket alone does NOT count.
//
// FOLLOWED THROUGH CALLS, like reachesMetered above (Ehsan 2026-09-22). The ceilings moved out of otpRequest
// into issueCode() — the one function both otpRequest and signup now call, because sign-up began sending a code
// and two copies of three ceilings would have been two things to keep in step. This check read the handler's
// OWN body only, so the move made it report otpRequest as unguarded while the guard was one call away. A gate
// that follows the call for "does it spend money" must follow it for "is it bounded", or the two answers are
// about different programs.
const ceilMemo = {};
function hasBroadCeiling(name, seen = new Set()) {
  if (name in ceilMemo) return ceilMemo[name];
  if (seen.has(name)) return false;
  seen.add(name);
  const body = FN[name];
  if (!body) return false;
  const buckets = [...body.matchAll(/rateLimit\s*\(\s*env\s*,\s*([`'][^`']*[`'])/g)].map(m => m[1]);
  if (buckets.some(b => !b.includes('${') || /ip/i.test(b))) return (ceilMemo[name] = true);
  for (const other of Object.keys(FN)) {
    if (other !== name && new RegExp(`\\b${other}\\s*\\(`).test(body) && hasBroadCeiling(other, seen)) return (ceilMemo[name] = true);
  }
  return (ceilMemo[name] = false);
}

t('the analysis actually sees the known metered pre-auth routes — BOTH of them', () => {
  assert.ok(handlers.length > 0, 'no route handlers found — the dispatch pattern changed; fix the parser');
  for (const h of ['otpRequest', 'signup']) {
    assert.ok(handlers.includes(h), `${h} not detected as a route handler`);
    // signup joined this set on 2026-09-22 by sending a confirmation code. A gate that stopped seeing it would
    // pass by looking away, which is the failure this line exists to prevent.
    assert.ok(reachesMetered(h), `${h} not detected as reaching a metered host — it sends email through issueCode`);
    assert.ok(isPreAuth(FN[h]), `${h} is no longer pre-auth — re-read this gate's scope before trusting it`);
  }
});

t('the broad-ceiling check is not trivially true — a function with no ceiling anywhere fails it', () => {
  // NEGATIVE: without this, "everything has a ceiling" could mean the matcher matches anything.
  assert.equal(hasBroadCeiling('publicUser'), false, 'a helper that touches no rateLimit must not read as bounded');
  assert.equal(hasBroadCeiling('issueCode'), true, 'and the chokepoint that holds all three must read as bounded');
});

t('every pre-auth route reaching a metered third-party host has a ceiling above per-identifier', () => {
  const offenders = [], checked = [];
  for (const h of new Set(handlers)) {
    const body = FN[h];
    if (!body || !reachesMetered(h) || !isPreAuth(body)) continue;
    checked.push(h);
    if (!hasBroadCeiling(h)) offenders.push(h);
  }
  assert.deepStrictEqual(
    offenders, [],
    `pre-auth metered route(s) gated only by a per-identifier limit (rotation-defeatable — add a global and/or per-IP ceiling): ${offenders.join(', ')}`,
  );
  // NAME THE SET. A count of zero offenders means nothing until it is said which routes were judged.
  console.log(`     field of view: ${checked.length} pre-auth metered route(s) judged: ${checked.join(', ')}`);
  assert.ok(checked.length >= 2, `only ${checked.length} route(s) reached the judgement — the analysis narrowed`);
});

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
