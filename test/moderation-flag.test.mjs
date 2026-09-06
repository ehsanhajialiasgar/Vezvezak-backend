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

for (const [fn, closed] of [['moderateReview', /note: 'awaiting_moderation'/], ['moderateCatalogItem', /return 'pending'/]]) {
  t(`${fn} gates on MODERATION_ENABLED !== "1" and FAILS CLOSED`, () => {
    const body = bodyOf(fn);
    const m = body.match(/if \(env\.MODERATION_ENABLED !== '1'\) (return [^\n;]+);/);
    assert.ok(m, `${fn} must gate on env.MODERATION_ENABLED !== '1'`);
    assert.match(m[1], closed, `${fn}'s flag gate must return the unmoderated/fail-closed value, never an approval`);
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
