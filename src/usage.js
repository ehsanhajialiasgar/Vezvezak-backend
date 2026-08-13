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
  free: { local: 0,  online: 3   },
  pro:  { local: 18, online: 40  },
  max:  { local: 45, online: 100 },
};

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
