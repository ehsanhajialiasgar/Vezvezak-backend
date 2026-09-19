// ─────────────────────────────────────────────────────────────────────────────
// WEEKLY SEARCH CAPS — server-authoritative (Ehsan 2026-08-13).
//
// A cap is a CEILING on live searches per WEEK, local and online counted
// SEPARATELY. It REFILLS to the same level at each weekly boundary — nothing
// rolls over, expires, or is forfeited. It is a search COUNT, never money: no
// dollar figure is stored or derived per user anywhere (D1, JWT, or client).
//
// These numbers MIRROR the client's single source of truth,
// VezvezakNew/src/services/pricingStrategy.ts → CONSUMER_TIERS
// (localPerWeek / onlinePerWeek). Cross-repo import is impossible in a Worker
// bundle, so the duplication is guarded: test/weeklyCaps.test.mjs parses that
// file (when the sibling repo is checked out) and FAILS THE BUILD if the two
// ever drift. Change one, you change both.
//
// This module is PURE (no D1, no I/O) so every decision here is unit-tested
// without a Worker harness. The D1 read/write lives in index.js.
// ─────────────────────────────────────────────────────────────────────────────

export const WEEKLY_CAPS = {
  // FREE IS NOT ZERO ANY MORE (Ehsan 2026-09-17). It was { local: 0, online: 0 }, and the 2026-09-17 cold-install
  // trace showed what that meant in the product: a free user — signed in or not — never saw a single result. The
  // free path reads a cache that only the paid path writes, so on a fresh install it is empty forever and every
  // search ended on one sentence and an em dash. "That is not a free tier, it is a broken app wearing a paywall."
  //
  // 1 local + 5 online, chosen on cost: one local (Google Places) search costs what 5.3 online (SerpApi) ones do
  // ($0.085 vs $0.016, list price, never invoiced), and online is what fills the screen. A fully-active free user
  // costs $0.072–0.101/week — $0.31–0.43/month — against zero revenue and no conversion data yet.
  //
  // THREE CONDITIONS, all of them structural, not promises:
  //   1. proxy ENFORCE_CAPS='1'. With it off the proxy never calls /search/consume, nothing is counted, and a
  //      non-zero free cap is unlimited paid search per install. The zero used to be the wall; the count is the
  //      wall now, so the count has to actually happen. (capsNeedEnforcement.test binds the two.)
  //   2. SEARCH_DAILY_CEILING below — a global blast brake, so a bug or an abuser cannot spend a month in a day.
  //   3. the client serves a repeated query from its 24h cache without spending a slot.
  // Client mirror: pricingStrategy.ts CONSUMER_TIERS free → localPerWeek 1 / onlinePerWeek 5. Change one, change
  // both (weeklyCapClient.test.mjs / weeklyCaps.test.mjs fail on drift).
  free: { local: 1,  online: 5   },
  pro:  { local: 18, online: 40  },
  max:  { local: 45, online: 100 },
};

// GLOBAL DAILY CEILING — a blast brake, not a usage model (Ehsan 2026-09-17, condition 2 of the free weekly searches).
// Per-user weekly caps bound what one honest account can spend; nothing bounded what the whole system can spend in
// a day. At list price these two numbers cap a day at 500·$0.085 + 2500·$0.016 = $82.50, and they are sized to
// carry ~3,500 fully-active free users (500 local/day = 3,500/week = one each; 2,500 online/day = 17,500/week =
// five each) plus paid traffic on top. Raise them deliberately when real traffic approaches them — a user refused
// by this ceiling is told the service is busy, never that their own searches are gone.
// STATED LIMIT: it counts SLOTS (local + online). Photos ride under a consumed local slot (PHOTO_PER_SEARCH), and
// details/geocode are auth-gated follow-ups that take no slot — neither is under this brake. That gap is recorded.
export const SEARCH_DAILY_CEILING = { local: 500, online: 2500 };
// ASSISTANT TURNS per week (Ehsan 2026-09-16; sized 2026-08-28 at ~$0.00024/turn, <1% of a paid plan at the cap).
// A RUNAWAY control, not a cost model. Free is 0: the assistant is a paid feature, like live search. Counted as rows
// of kind 'ai' in consumed_searches for the account's current weekly window (no new column, no migration).
export const AI_WEEKLY_TURNS = { free: 0, pro: 150, max: 400 };
export function aiTurnCap(plan) {
  return AI_WEEKLY_TURNS[resolvePlan(plan)] ?? 0;
}

// Only these two kinds are metered as SLOTS. Accessibility (voice.listen /
// voice.speak) is on-device and NEVER routed through consume — it is not billable
// and not a member of this set, so it can never be counted against a cap.
export const METERED_KINDS = new Set(['local', 'online']);

// A single LOCAL search legitimately fans out to Text + Nearby (+ a few Photos
// when store cards are opened). Those sub-calls share ONE vz_sid and collapse into
// ONE 'local' slot (consumed_searches dedupe). Photos consume no slot but are
// bounded per search bundle so a tampered client can't pull unlimited paid photos
// under one slot. 6/search matches the client's list+detail photo budget.
export const PHOTO_PER_SEARCH = 6;

// ── THE BOUND ON AN ALREADY-CONSUMED BUNDLE (Ehsan 2026-09-19) ───────────────────────────────────────────────
// vz_sid is built by the CLIENT and is unsigned. Until today, once a bundle's row existed, every later call with
// that same id returned allowed:true — "cap or no cap" — for the rest of the week, and the global daily ceiling
// sat below that return, so neither guard was on the path. Holding one vz_sid constant bypassed the weekly cap.
//
// That idempotent allow is NOT a mistake and must stay: the cap decides whether a NEW bundle may start, never
// whether a granted one may finish (removing it is what served the last search of every week half). What was
// missing is a BOUND on how much one granted bundle may finish.
//
// TWO BOUNDS, because either alone leaks. A count alone resets with its rate-limit window, handing a replayer a
// fresh allowance every window for the rest of the week. A freshness window alone bounds nothing inside it — a
// client can issue thousands of calls in two minutes. Together they are finite and small: at most
// SEARCH_SUBCALLS_PER_SLOT extra calls, only while the bundle is younger than SEARCH_BUNDLE_TTL_MS, and a new id
// costs a slot.
//
// WHY THIS SHAPE AND NOT THE OTHER TWO IN THIS FILE. The assistant builds its id server-side, which is stronger —
// but vz_sid exists precisely so the client can bind sub-calls it makes in parallel, so a server-issued id needs a
// round-trip before every search, on the critical path, with a new failure mode. The photo path's shape (an atomic
// bounded bump) is the one copied here — the difference is that it counts in rate_limits rather than a new column,
// so no migration stands between this hole and its fix. The bucket name is hashed by storedBucket, so no raw
// search id is stored.
//
// SIZING. A legitimate LOCAL bundle makes two metered calls (Places Text + Nearby): one insert, one idempotent
// hit. Four allows that plus three retries. The client's own billable timeout is 15s, so a five-minute bundle is
// far longer than any real sub-call can take.
export const SEARCH_SUBCALLS_PER_SLOT = 4;
export const SEARCH_BUNDLE_TTL_MS = 5 * 60 * 1000;

// ── BILLABLE FOLLOW-UPS: geocode AND place/details (Ehsan 2026-09-19) ────────────────────────────────────────
// Both are real Google money and NEITHER had a cap. SLOT_KIND is null for them on the client, so no slot is taken,
// and the proxy's only guard was "an Authorization header exists" — which `Bearer lol` satisfies, verified against
// the deployed Worker today (200, with live Google data). The Worker URL ships in the app bundle.
//
// place/details is the expensive one: the store card re-requests display fields on view (Google forbids caching
// them), so a scroll through a result list is dozens of paid calls, and the in-session cache kept only successes —
// an error re-fired on every render.
//
// THE FIX IS ONE MECHANISM FOR BOTH PROBLEMS. The proxy cannot verify a JWT (it holds no JWT_SECRET, deliberately),
// so instead of inventing a second auth path it now asks the backend — which DOES verify — and the same question
// carries the cap. A call that cannot be attributed to a real account does not happen, and a call from a real
// account is bounded three ways: per search bundle, per account per day, and globally per day.
export const LOOKUP_PER_SLOT = 40;              // a full scroll of a result list, and no more
export const LOOKUP_DAILY_PER_USER = 300;
export const LOOKUP_DAILY_CEILING = 20000;      // global blast brake, sized like SEARCH_DAILY_CEILING

// Legacy plan ids fold onto the three live tiers; anything unknown (or absent)
// resolves to 'free', so the server ALWAYS enforces free limits authoritatively
// even before an IAP receipt writes a paid plan.
const PLAN_ALIAS = { max20x: 'max' };
export function resolvePlan(rawPlan) {
  const p = PLAN_ALIAS[rawPlan] || rawPlan;
  return WEEKLY_CAPS[p] ? p : 'free';
}

export function planCaps(plan) {
  return WEEKLY_CAPS[resolvePlan(plan)];
}

// A billable AI call (review/catalog moderation, page extraction) may run
// synchronously ONLY for a paid plan. Free (and anonymous) never reach env.AI —
// the free tier must incur zero billable AI. Pushed into the moderation
// functions themselves so the gate is structural, not a scattered if.
export function billableAiAllowed(plan) {
  const p = resolvePlan(plan);
  return p === 'pro' || p === 'max';
}

// Deterministic per-account reset slot, spread across the week so resets do NOT
// all fire at one global instant (which would spike load AND cost together).
// A stable FNV-1a hash of the user id → a fixed weekday (0-6) + minute-of-day
// (0-1439), stored on the row so it is inspectable and never moves.
export function refillSlot(userId) {
  let h = 2166136261 >>> 0;
  const s = String(userId);
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  h >>>= 0;
  return { dow: h % 7, minute: Math.floor(h / 7) % 1440 };
}

const WEEK_MS = 7 * 86400000;

// The most recent weekly boundary (this account's dow + minute, in UTC) at or
// before `nowMs`. The current window runs [windowStart, windowStart + 1 week).
export function windowStartFor(nowMs, dow, minute) {
  const d = new Date(nowMs);
  const deltaDays = (d.getUTCDay() - dow + 7) % 7;
  let start = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - deltaDays, 0, minute, 0, 0);
  if (start > nowMs) start -= WEEK_MS;   // boundary is later today → use last week's
  return start;
}

// When the current window ends and the cap REFILLS (used → 0). Not an expiry:
// the same full cap is available again; nothing is forfeited.
export function nextResetMs(windowStart) {
  return windowStart + WEEK_MS;
}

// Has the account's weekly boundary passed since its window began? If so the
// counts refill to full. Pure decision; index.js performs the D1 UPDATE.
export function shouldRefill(nowMs, windowStart, dow, minute) {
  return windowStart < windowStartFor(nowMs, dow, minute);
}

// The refusal decision: at or over the cap, refuse. Free local (cap 0) refuses
// every time — a free user can never obtain a live Google Places slot. Never
// fails open.
export function capReached(cap, used) {
  return used >= cap;
}
