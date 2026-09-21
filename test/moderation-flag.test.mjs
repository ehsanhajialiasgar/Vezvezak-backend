// AI MODERATION must be FLAG-GATED, default off, fail-closed (Ehsan 2026-09-03). moderateReview() and
// moderateCatalogItem() send a user's review text, or a listing's title/description/brand/model, to
// Workers AI. Until today the ONLY thing holding privacy §5 ("it does not run for any user today — no
// review or listing text is sent to any model") was the PLAN gate: pro || max. That made a published
// legal sentence depend on a row in user_plans — the first redeemed comp code would have falsified it
// with no code change, no deploy and no gate firing. The flag sits ABOVE the plan gate; BOTH remain.
// These are SOURCE-level assertions (the handlers aren't exported in a testable shape), so removing or
// reordering either gate fails the build. Run: node test/moderation-flag.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Comments are stripped before any ordering assertion: moderateReview's own doc comment says
// "never reaches env.AI", and matching THAT would make the test assert against prose instead of code.
const stripComments = x => x.replace(/(^|[^:])\/\/.*$/gm, '$1').replace(/\/\*[\s\S]*?\*\//g, '');
const IDX = stripComments(readFileSync('src/index.js', 'utf8'));
const TOML = readFileSync('wrangler.toml', 'utf8');
let passed = 0;
const t = (name, fn) => { fn(); passed++; console.log('  ok -', name); };

function bodyOf(name) {
  const start = IDX.indexOf(`export async function ${name}(`);
  assert.ok(start >= 0, `${name} not found in src/index.js`);
  const end = IDX.indexOf('\n}\n', start);
  assert.ok(end > start, `${name} body end not found`);
  return IDX.slice(start, end);
}

// WHAT "FAILS CLOSED" MEANS HERE, restated 2026-09-18. The flag guards ONE thing: whether text is sent to a
// model. It was ALSO holding the catalogue shut — with the flag off every item returned 'pending', and since
// nothing else in the backend ever wrote 'live', a merchant's products were invisible to every buyer for ever.
// That was not a moderation decision, it was an accident of who owned the default. A listing now goes live
// labelled "listed by the merchant · unverified" and the deterministic screen is what can refuse it; the flag
// keeps its real job, which is that nothing reaches env.AI while it is off (asserted below, unchanged).
// A REVIEW is different and keeps its old default: an unmoderated review is marked awaiting_moderation rather
// than shown as checked, because there the claim is about OUR check, not about the merchant's own listing.
// moderateReview WAS IN THIS LIST and went with the in-app review feature on 2026-09-21 (the App Store is where
// people review the app). What it proved about the flag is unchanged and is still proved here, over the function
// that remains: nothing reaches env.AI while MODERATION_ENABLED is off, and the flag can never be what APPROVES
// anything. The paragraph above about a review's different default is kept as the record of a decision, not as a
// description of live code.
for (const [fn, closed] of [['moderateCatalogItem', /return 'live'/]]) {
  t(`${fn} gates on MODERATION_ENABLED !== "1" and never lets the flag approve`, () => {
    const body = bodyOf(fn);
    const m = body.match(/if \(env\.MODERATION_ENABLED !== '1'\) (return [^\n;]+);/);
    assert.ok(m, `${fn} must gate on env.MODERATION_ENABLED !== '1'`);
    assert.match(m[1], closed, `${fn}'s flag-off value must be the one this product decided, not a model's approval`);
  });

  t(`${fn}: the deterministic screen is ABOVE the flag — it runs whatever the flag says`, () => {
    const body = bodyOf(fn);
    const screen = body.search(/screenCatalogText|screenReviewText|PROHIBITED/);
    const flag = body.indexOf('MODERATION_ENABLED');
    if (screen >= 0) assert.ok(screen < flag, `${fn}'s prohibited screen must precede the flag gate`);
  });

  t(`${fn}: the FLAG runs before anything can reach the model`, () => {
    const body = bodyOf(fn);
    const flag = body.indexOf('MODERATION_ENABLED');
    const model = body.search(/env\.AI\b/);
    assert.ok(flag >= 0 && model >= 0);
    assert.ok(flag < model, `${fn}: the flag gate must precede every env.AI reference`);
  });

  t(`${fn}: the PLAN gate SURVIVES — two conditions, not one replacing the other`, () => {
    const body = bodyOf(fn);
    const flag = body.indexOf('MODERATION_ENABLED');
    const plan = body.indexOf('billableAiAllowed(plan)');
    assert.ok(plan >= 0, `${fn} must still consult billableAiAllowed(plan) — the flag does not replace it`);
    assert.ok(flag < plan, `${fn}: the flag must sit ABOVE the plan gate`);
  });
}

t('wrangler.toml declares MODERATION_ENABLED and DEFAULTS IT OFF (never committed as "1")', () => {
  const m = TOML.match(/MODERATION_ENABLED\s*=\s*"([^"]*)"/);
  assert.ok(m, 'MODERATION_ENABLED must be declared in wrangler.toml [vars]');
  assert.notEqual(m[1], '1', 'MODERATION_ENABLED must not be committed as "1" — flipping it on requires updating privacy §5 first');
});

t('no OTHER env.AI path in index.js is held by a plan gate alone', () => {
  // The general form of today's defect: a model-reaching path whose only hold is who paid.
  // Every env.AI site must have a FLAG above it, so no published sentence rests on a DB row.
  const lines = IDX.split('\n');
  const unflagged = [];
  lines.forEach((ln, i) => {
    if (!/env\.AI\.run\(/.test(ln)) return;
    const before = lines.slice(Math.max(0, i - 60), i).join('\n');
    if (!/_ENABLED !== '1'/.test(before)) unflagged.push(i + 1);
  });
  assert.deepEqual(unflagged, [], `env.AI.run at line(s) ${unflagged.join(', ')} has no _ENABLED flag above it`);
});

console.log(`\nmoderation flag gate: ${passed}/8 checks passed`);
