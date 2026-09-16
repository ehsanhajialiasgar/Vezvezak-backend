// Intent resolution — the accept rules and the model call (2026-09-16; re-anchored from the m2m100 token-protection
// tests: the INTENT they guarded — a model number must survive, a failed model never becomes a guessed product — is kept).
// Run: node test/translate.test.mjs
import assert from 'node:assert/strict';
import { acceptIntent, resolveIntent, INTENT_PROMPT, INTENT_MODEL, UNKNOWN } from '../src/translate.js';

let passed = 0;
const test = async (name, fn) => { await fn(); passed++; console.log('  ok -', name); };

await test('a plain answer is accepted; quotes and a trailing full stop are stripped; only the first line counts', () => {
  assert.deepEqual(acceptIntent('نمک', 'salt'), { resolved: true, query: 'salt' });
  assert.deepEqual(acceptIntent('میز', '"table."\nbecause میز means table'), { resolved: true, query: 'table' });
});
await test('MODEL NUMBERS must survive verbatim (a broken model number is a wrong product)', () => {
  assert.equal(acceptIntent('کاور iPhone 15 Pro', 'iPhone 15 Pro case').resolved, true);
  assert.equal(acceptIntent('هدفون WH-1000XM5', 'wireless headphones').resolved, false);
  assert.equal(acceptIntent('هدفون WH-1000XM5', 'WH-1000XM6 headphones').resolved, false);
});
await test('[[UNKNOWN]], empty, non-Latin or over-long answers are unresolved', () => {
  assert.deepEqual(acceptIntent('asdf', UNKNOWN), { resolved: false, reason: 'unknown' });
  assert.equal(acceptIntent('x', '').resolved, false);
  assert.equal(acceptIntent('میز', 'میز').resolved, false);
  assert.equal(acceptIntent('桌子', '桌子 table').resolved, false);
  assert.equal(acceptIntent('x', 'a'.repeat(201)).resolved, false);
});
await test('the prompt asks for intent in any language, English terms only, and [[UNKNOWN]] when unsure', () => {
  assert.match(INTENT_PROMPT, /any language or script/);
  assert.match(INTENT_PROMPT, /Never read a word as a look-alike/);
  assert.match(INTENT_PROMPT, /model numbers/);
  assert.ok(INTENT_PROMPT.includes(UNKNOWN));
});
await test('resolveIntent sends the whole query, with the prompt, to the chat model at temperature 0', async () => {
  const seen = [];
  const env = { AI: { run: async (model, input) => { seen.push({ model, input }); return { response: 'iPhone 15 Pro case' }; } } };
  const r = await resolveIntent(env, 'کاور iPhone 15 Pro');
  assert.deepEqual(r, { resolved: true, query: 'iPhone 15 Pro case' });
  assert.equal(seen[0].model, INTENT_MODEL);
  assert.equal(seen[0].input.temperature, 0);
  assert.deepEqual(seen[0].input.messages.map(m => m.role), ['system', 'user']);
  assert.equal(seen[0].input.messages[1].content, 'کاور iPhone 15 Pro');
});
await test('a model error propagates (the route maps it to unresolved — never to the raw query as if resolved)', async () => {
  await assert.rejects(resolveIntent({ AI: { run: async () => { throw new Error('down'); } } }, 'نمک'));
});

console.log(`\n${passed} passed`);
