// Intent resolution — the accept rules and the model call (2026-09-16; re-anchored from the m2m100 token-protection
// tests: the INTENT they guarded — a model number must survive, a failed model never becomes a guessed product — is kept).
// Run: node test/translate.test.mjs
import assert from 'node:assert/strict';
import { acceptIntent, resolveIntent, sharesWritingSystem, INTENT_PROMPT, INTENT_MODEL, UNKNOWN } from '../src/translate.js';

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
  assert.match(INTENT_PROMPT, /any of the world's languages and scripts/);
  assert.match(INTENT_PROMPT, /not from the script alone/, 'a shared script or spelling is not the language');
  assert.match(INTENT_PROMPT, /Examples:/, 'worked examples (none from the eval set)');
  for (const w of ['نمک', 'میز', 'silla', 'salt', 'chair']) assert.ok(!INTENT_PROMPT.includes(w), `the eval word ${w} is not an example`);
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

await test('[[UNKNOWN]] carries the model\'s sentence in the user\'s language — only when it is in the user\'s writing system', () => {
  assert.deepEqual(acceptIntent('كيف حالك', '[[UNKNOWN]] لا أستطيع معرفة المنتج الذي تبحث عنه'),
    { resolved: false, reason: 'unknown', message: 'لا أستطيع معرفة المنتج الذي تبحث عنه' });
  assert.equal(acceptIntent('Բարեւ', '[UNKNOWN] Ես չգիտեմ').message, 'Ես չգիտեմ', 'a single-bracket token is still the token');
  assert.equal(acceptIntent('این چند وات است؟', '[[UNKNOWN]]只能回答关于屏幕上的结果的问题').message, undefined, 'a Chinese sentence for a Persian query is dropped');
  assert.equal(acceptIntent('মালী', 'gardener or [[UNKNOWN]] আমি বুঝতে পারিনি').resolved, false, 'a guess next to the token is not a resolution');
  assert.equal(acceptIntent('x', '[[UNKNOWN]] see https://example.com').message, undefined);
});
await test('writing system is a property of the code points, not a list', () => {
  assert.equal(sharesWritingSystem('نمک', 'نمی‌دانم'), true);
  assert.equal(sharesWritingSystem('Kumusta', 'Pakisabi sa akin'), true);
  assert.equal(sharesWritingSystem('café', 'je ne sais pas'), true);
  assert.equal(sharesWritingSystem('桌子', 'テーブルが見つかりません'), false, 'Han first letter, a kana-only reply');
  assert.equal(sharesWritingSystem('이것은', '모르겠습니다'), true);
  assert.equal(sharesWritingSystem('این', '只能回答'), false);
  assert.equal(sharesWritingSystem('123', 'anything'), false, 'no letter in the question → nothing to match');
});
await test('the prompt asks for the "could not tell" sentence in the language the person wrote in', () => {
  assert.match(INTENT_PROMPT, /one short sentence in the language the person wrote in/);
});

console.log(`\n${passed} passed`);
