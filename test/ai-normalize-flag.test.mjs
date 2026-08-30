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

await t('aiNormalize gates on AI_NORMALIZE_ENABLED !== "1" and returns the raw query (fail closed)', () => {
  const body = bodyOf('aiNormalize');
  assert.match(body, /env\.AI_NORMALIZE_ENABLED\s*!==\s*'1'\s*\)\s*return ok\(\{ query \}\)/,
    'the flag gate must return the raw query when the flag is not "1"');
});

await t('the flag check runs BEFORE anything can reach the model (env.AI / translateQuery)', () => {
  const body = bodyOf('aiNormalize');
  const gate = body.indexOf('AI_NORMALIZE_ENABLED');
  const model = body.search(/translateQuery\(|env\.AI\b/);
  assert.ok(gate >= 0, 'flag gate present');
  assert.ok(model >= 0, 'a model-reaching reference exists');
  assert.ok(gate < model, 'the flag gate must precede every env.AI / translateQuery reference');
});

await t('wrangler.toml declares the flag and DEFAULTS IT OFF (never "1")', () => {
  const m = TOML.match(/AI_NORMALIZE_ENABLED\s*=\s*"([^"]*)"/);
  assert.ok(m, 'AI_NORMALIZE_ENABLED must be declared in wrangler.toml [vars]');
  assert.notEqual(m[1], '1', 'AI_NORMALIZE_ENABLED must not be committed as "1" (default off)');
});

console.log(`\nai-normalize flag gate: ${passed}/3 checks passed`);
