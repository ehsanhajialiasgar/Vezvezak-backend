// Intent resolution — the accept rules and the model call.
// RE-ANCHORED 2026-09-24 from acceptIntent to acceptStructuredIntent. The contract changed (an intent now
// carries a CATEGORY, because «کیف» resolving to the word "bag" returned bin liners), and the rules these
// tests guard did NOT: a model number must survive verbatim, a failed model never becomes a guessed product,
// quotes are stripped, non-Latin or over-long answers are refused, [[UNKNOWN]] is honoured. Every one of them
// is asserted below against the parser a real query now passes through.
// Run: node test/translate.test.mjs
import assert from 'node:assert/strict';
import { sharesWritingSystem, INTENT_MODEL, UNKNOWN, resolveStructuredIntent } from '../src/translate.js';
import { acceptStructuredIntent, STRUCTURED_INTENT_PROMPT, CATEGORIES } from '../src/intent.js';

const shares = sharesWritingSystem;
const A = (q, raw) => acceptStructuredIntent(q, raw, shares);
const J = (terms, category = 'other', attrs = {}) => JSON.stringify({ terms, category, attrs });

let passed = 0;
const test = async (name, fn) => { await fn(); passed++; console.log('  ok -', name); };

await test('a well-formed answer is accepted; quotes are stripped; prose around the JSON is ignored', () => {
  assert.deepEqual(A('نمک', J('salt', 'grocery.food')), { resolved: true, terms: 'salt', category: 'grocery.food', attrs: {} });
  assert.equal(A('میز', 'Here you go: ' + J('table', 'furniture')).terms, 'table');
  assert.equal(A('میز', JSON.stringify({ terms: '"table"', category: 'furniture' })).terms, 'table');
});
await test('MODEL NUMBERS must survive verbatim (a broken model number is a wrong product)', () => {
  assert.equal(A('کاور iPhone 15 Pro', J('iPhone 15 Pro case', 'phone.accessories')).resolved, true);
  assert.equal(A('هدفون WH-1000XM5', J('wireless headphones', 'audio')).resolved, false);
  assert.equal(A('هدفون WH-1000XM5', J('WH-1000XM6 headphones', 'audio')).resolved, false);
});
await test('[[UNKNOWN]], empty, non-Latin or over-long answers are unresolved', () => {
  assert.deepEqual(A('asdf', UNKNOWN), { resolved: false, reason: 'unknown' });
  assert.equal(A('x', '').resolved, false);
  assert.equal(A('میز', J('میز', 'furniture')).resolved, false);
  assert.equal(A('桌子', J('桌子 table', 'furniture')).resolved, false);
  assert.equal(A('x', J('a'.repeat(201), 'other')).resolved, false);
});
await test('THE CATEGORY IS CLOSED — an id outside the vocabulary cannot be filtered on, so it is refused', () => {
  assert.equal(A('x', J('thing', 'not.a.real.category')).resolved, false);
  assert.equal(A('x', JSON.stringify({ terms: 'thing' })).resolved, false, 'a missing category is not a resolution');
  for (const c of ['bags.handbag', 'footwear', 'phones', 'other']) assert.ok(CATEGORIES.includes(c), `${c} must be in the vocabulary`);
});
await test('AMBIGUITY IS ASKED, NEVER GUESSED — and one option is not an ambiguity', () => {
  const r = A('bag', JSON.stringify({ ambiguous: [
    { category: 'bags.handbag', terms: 'handbag' }, { category: 'household.binbags', terms: 'bin bags' },
  ] }));
  assert.deepEqual([r.resolved, r.reason, r.options.length], [false, 'ambiguous', 2]);
  assert.equal(A('bag', JSON.stringify({ ambiguous: [{ category: 'bags.handbag', terms: 'handbag' }] })).resolved, false);
  assert.equal(A('bag', JSON.stringify({ ambiguous: [{ category: 'bags.handbag', terms: 'handbag' }] })).reason, 'rejected');
  // An option whose category is not in the vocabulary is dropped; dropping below two refuses the whole answer.
  assert.equal(A('bag', JSON.stringify({ ambiguous: [
    { category: 'bags.handbag', terms: 'handbag' }, { category: 'made.up', terms: 'x' },
  ] })).reason, 'rejected');
});
await test('THE MODEL MAY ANSWER WITH AN OBJECT — Workers AI parses JSON before we see it', () => {
  // Measured live: String(response) on an object gave "[object Object]" and EVERY query came back 'empty'.
  const obj = { terms: 'handbag', category: 'bags.handbag', attrs: { gender: 'women' } };
  assert.deepEqual(A('کیف', obj), A('کیف', JSON.stringify(obj)), 'both shapes must judge the same');
  assert.equal(A('کیف', obj).terms, 'handbag');
});
await test('attributes are only what the query states — a model may not invent a brand', () => {
  const r = A('کیف', JSON.stringify({ terms: 'handbag', category: 'bags.handbag', attrs: { brand: 'Gucci', size: '', model: '' } }));
  assert.deepEqual(r.attrs, { brand: 'Gucci' }, 'empty attributes are dropped, not carried as blanks');
  assert.deepEqual(A('کیف', J('handbag', 'bags.handbag')).attrs, {});
});
await test('the prompt asks for MEANING not translation, a closed category, and [[UNKNOWN]] when unsure', () => {
  assert.match(STRUCTURED_INTENT_PROMPT, /any of the world's languages and scripts/);
  assert.match(STRUCTURED_INTENT_PROMPT, /MEANING, NOT DICTIONARY/, 'the defect this exists for');
  assert.match(STRUCTURED_INTENT_PROMPT, /model numbers/);
  assert.match(STRUCTURED_INTENT_PROMPT, /ambiguous/, 'the model must be able to refuse to choose');
  assert.ok(STRUCTURED_INTENT_PROMPT.includes(UNKNOWN));
  for (const c of CATEGORIES) assert.ok(STRUCTURED_INTENT_PROMPT.includes(c), `${c} must be offered to the model`);
  // Eval words must not be examples, or the evaluation measures the prompt rather than the model.
  for (const w of ['نمک', 'میز', 'silla', 'salt', 'chair']) assert.ok(!STRUCTURED_INTENT_PROMPT.includes(w), `the eval word ${w} is not an example`);
});
await test('resolveStructuredIntent sends the whole query, with the prompt, at temperature 0', async () => {
  const seen = [];
  const env = { AI: { run: async (model, input) => { seen.push({ model, input }); return { response: J('iPhone 15 Pro case', 'phone.accessories') }; } } };
  const r = await resolveStructuredIntent(env, 'کاور iPhone 15 Pro');
  assert.equal(r.resolved, true);
  assert.equal(r.terms, 'iPhone 15 Pro case');
  assert.equal(seen[0].model, INTENT_MODEL);
  assert.equal(seen[0].input.temperature, 0);
  assert.deepEqual(seen[0].input.messages.map(m => m.role), ['system', 'user']);
  assert.equal(seen[0].input.messages[1].content, 'کاور iPhone 15 Pro');
});
await test('a model error propagates (the route maps it to unresolved — never to the raw query as if resolved)', async () => {
  await assert.rejects(resolveStructuredIntent({ AI: { run: async () => { throw new Error('down'); } } }, 'نمک'));
});

await test('[[UNKNOWN]] carries the model\'s sentence in the user\'s language — only when it is in the user\'s writing system', () => {
  assert.deepEqual(A('كيف حالك', '[[UNKNOWN]] لا أستطيع معرفة المنتج الذي تبحث عنه'),
    { resolved: false, reason: 'unknown', message: 'لا أستطيع معرفة المنتج الذي تبحث عنه' });
  assert.equal(A('Բարեւ', '[UNKNOWN] Ես չգիտեմ').message, 'Ես չգիտեմ', 'a single-bracket token is still the token');
  assert.equal(A('این چند وات است؟', '[[UNKNOWN]]只能回答关于屏幕上的结果的问题').message, undefined, 'a Chinese sentence for a Persian query is dropped');
  assert.equal(A('মালী', 'gardener or [[UNKNOWN]] আমি বুঝতে পারিনি').resolved, false, 'a guess next to the token is not a resolution');
  assert.equal(A('x', '[[UNKNOWN]] see https://example.com').message, undefined);
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
  assert.match(STRUCTURED_INTENT_PROMPT, /one short sentence, in the language the person wrote in/);
});

console.log(`\n${passed} passed`);
