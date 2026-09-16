// /ai/normalize must be FLAG-GATED, default off, fail-closed (Ehsan 2026-08-30). This route sends the
// search query to Workers AI (m2m100); without an explicit env flag the DEPLOY STATE alone decided
// whether user query text left for a language model — one `wrangler deploy` would have made the
// published privacy policy's §6 ("no data to any AI provider today") false, with no code change and no
// decision. These are SOURCE-level assertions (the handler isn't exported) so a future edit that drops
// or reorders the gate fails the build here — the hold is structural, not a comment. Run: node test/ai-normalize-flag.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const IDX = readFileSync('src/index.js', 'utf8');
const TOML = readFileSync('wrangler.toml', 'utf8');
let passed = 0;
const t = async (name, fn) => { await fn(); passed++; console.log('  ok -', name); };

// Extract the aiNormalize function body (from its declaration to the next top-level `}\n`).
function bodyOf(name) {
  const start = IDX.indexOf(`async function ${name}(`);
  assert.ok(start >= 0, `${name} not found in src/index.js`);
  const end = IDX.indexOf('\n}\n', start);
  assert.ok(end > start, `${name} body end not found`);
  return IDX.slice(start, end);
}

await t('aiNormalize gates on AI_NORMALIZE_ENABLED !== "1" and returns UNRESOLVED (fail closed)', () => {
  const body = bodyOf('aiNormalize');
  assert.match(body, /env\.AI_NORMALIZE_ENABLED\s*!==\s*'1'\s*\)\s*return ok\(\{ query, resolved: false, reason: 'disabled' \}\)/,
    'the flag gate must answer unresolved when the flag is not "1"');
});

await t('the flag check runs BEFORE anything can reach the model (env.AI / resolveIntent)', () => {
  const body = bodyOf('aiNormalize');
  const gate = body.indexOf('AI_NORMALIZE_ENABLED');
  const model = body.search(/resolveIntent\(|env\.AI\b/);
  assert.ok(gate >= 0, 'flag gate present');
  assert.ok(model >= 0, 'a model-reaching reference exists');
  assert.ok(gate < model, 'the flag gate must precede every env.AI / resolveIntent reference');
});

await t('wrangler.toml declares the flag; "1" only with the predeploy policy check', () => {
  const m = TOML.match(/AI_NORMALIZE_ENABLED\s*=\s*"([^"]*)"/);
  assert.ok(m, 'AI_NORMALIZE_ENABLED must be declared in wrangler.toml [vars]');
  // ON since 2026-09-16 — deliberately, after privacy publish 5. Re-anchored: the flag must be declared, and turning it
  // on is only allowed together with the predeploy check that ties it to the published §5.
  assert.ok(['0', '1'].includes(m[1]), 'AI_NORMALIZE_ENABLED must be "0" or "1"');
  if (m[1] === '1') {
    const gate = readFileSync('scripts/policy-before-deploy-gate.mjs', 'utf8');
    assert.match(gate, /AI_NORMALIZE_ENABLED: \{ absent: 'no search text reaches any language model today'/);
  }
});

console.log(`\nai-normalize flag gate: ${passed}/3 checks passed`);
