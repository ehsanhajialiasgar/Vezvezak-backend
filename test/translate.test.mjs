// Translation token-protection + reassembly tests (P0.5). Run: node test/translate.test.mjs
import assert from 'node:assert/strict';
import { segmentForTranslation, translateQuery } from '../src/translate.js';

let passed = 0;
const test = async (name, fn) => { await fn(); passed++; console.log('  ok -', name); };

// ── segmentForTranslation: what gets protected vs translated ──
await test('fully non-Latin query → one translatable run (context kept together)', () => {
  assert.deepEqual(segmentForTranslation('لپ‌تاپ گیمینگ'), [{ kind: 'translate', text: 'لپ‌تاپ گیمینگ' }]);
});
await test('a Latin brand token is PROTECTED, non-Latin around it translates', () => {
  assert.deepEqual(segmentForTranslation('iPhone کاور'), [
    { kind: 'keep', text: 'iPhone' },
    { kind: 'translate', text: 'کاور' },
  ]);
});
await test('MODEL NUMBERS and digits are protected (a broken model number is a wrong product)', () => {
  assert.deepEqual(segmentForTranslation('کاور iPhone 15 Pro Max'), [
    { kind: 'translate', text: 'کاور' },
    { kind: 'keep', text: 'iPhone 15 Pro Max' },
  ]);
  // alphanumeric SKU / model code stays intact
  assert.deepEqual(segmentForTranslation('هدفون WH-1000XM5'), [
    { kind: 'translate', text: 'هدفون' },
    { kind: 'keep', text: 'WH-1000XM5' },
  ]);
});
await test('empty / whitespace → no segments', () => {
  assert.deepEqual(segmentForTranslation(''), []);
  assert.deepEqual(segmentForTranslation('   '), []);
});

// ── translateQuery: protected tokens NEVER reach the model; runs are reassembled in order ──
const fakeAI = (seen) => ({
  run: async (_model, { text, source_lang, target_lang }) => {
    seen.push({ text, source_lang, target_lang });
    return { translated_text: `EN[${text}]` }; // deterministic stand-in for m2m100
  },
});

await test('protected tokens are never sent to the model; order preserved', async () => {
  const seen = [];
  const out = await translateQuery({ AI: fakeAI(seen) }, 'کاور iPhone 15', 'fa');
  assert.equal(out, 'EN[کاور] iPhone 15');
  assert.deepEqual(seen.map(s => s.text), ['کاور']);          // only the non-Latin run was sent
  assert.equal(seen[0].source_lang, 'fa');
  assert.equal(seen[0].target_lang, 'en');                    // always translate toward English
});

await test('a fully non-Latin query is sent as ONE run (not word-by-word)', async () => {
  const seen = [];
  const out = await translateQuery({ AI: fakeAI(seen) }, 'لپ‌تاپ گیمینگ', 'fa');
  assert.equal(out, 'EN[لپ‌تاپ گیمینگ]');
  assert.equal(seen.length, 1);                               // context kept together, one call
});

// ── fail open: a model error keeps the raw run (never lose/alter the product term) ──
await test('model error → the raw run is kept (fail open)', async () => {
  const throwingAI = { run: async () => { throw new Error('model down'); } };
  const out = await translateQuery({ AI: throwingAI }, 'کاور iPhone', 'fa');
  assert.equal(out, 'کاور iPhone'); // run un-translated, brand intact, search proceeds
});

console.log(`\n${passed} passed`);
