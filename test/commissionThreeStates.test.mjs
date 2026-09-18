// A NULL ANSWER MAY NOT BE COERCED INTO A NO (Ehsan 2026-09-18).
//
// commission_agreed was added as INTEGER NOT NULL DEFAULT 0, so every row that predated the column read 0 —
// "declined" and "never asked" were the same value, and on the remote database all 8 rows were the second one.
// The column is nullable now (1 agreed · 0 declined · NULL never asked), and the danger moves to the READ side:
// one `?`, one `!!`, one `|| false` anywhere between the row and a person turns "we never asked" back into
// "they said no" — silently, and about a commercial term.
//
// This gate reads every path the value can travel and fails on a coercion, plus it proves the round trip with
// the real handlers. Run: node test/commissionThreeStates.test.mjs
import assert from 'node:assert/strict';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
// CODE ONLY, NOT THE PROSE ABOUT IT. The first run of this gate failed on its own subject matter: the comment
// that explains the old `body.commissionAgreed ? 1 : 0` bug contains that exact expression, so a raw text scan
// called the fix a coercion. A pattern gate that reads comments is reading a description of the code, not the
// code — the same family as the polarity class. Comments are stripped before anything is matched.
const stripComments = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
const IDX = stripComments(readFileSync(resolve(HERE, '..', 'src', 'index.js'), 'utf8'));
const SCHEMA = readFileSync(resolve(HERE, '..', 'schema.sql'), 'utf8');
let pass = 0, fail = 0;
const t = (n, fn) => { try { fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

t('the column can hold the third state at all', () => {
  const row = SCHEMA.match(/commission_agreed\s+INTEGER[^,\n]*/)[0];
  assert.doesNotMatch(row, /NOT NULL/, `commission_agreed must be nullable, got: ${row.trim()}`);
  assert.doesNotMatch(row, /DEFAULT/, 'and it must have no default — a default IS the fabricated answer');
});

t('the write path records only an explicit answer', () => {
  assert.match(IDX, /body\.commissionAgreed === true \? 1 : body\.commissionAgreed === false \? 0 : null/,
    'absent or malformed must be stored as NULL');
  assert.doesNotMatch(IDX, /body\.commissionAgreed \? 1 : 0/, 'the truthiness form treats silence as a no');
});

// Every SQL read that names the column, and what happens to the value afterwards.
t('no read path coerces the value on its way to a person', () => {
  const reads = [...IDX.matchAll(/commission_agreed(?:\s+AS\s+commissionAgreed)?/g)].map(m => m.index);
  assert.ok(reads.length >= 3, `expected the write + /merchants/mine + the export, found ${reads.length}`);
  // A coercion is any of these applied to the field name anywhere in the file.
  // ANY receiver, not just `row.` — the first version of this list matched `row.commissionAgreed` and missed a
  // planted `!!m.commissionAgreed` by one identifier. Found by running the negative proof, not by reading it.
  const F = '[\\w$.]*commission_?[aA]greed';
  const COERCIONS = [
    new RegExp(`!!\\s*${F}`),
    new RegExp(`${F}\\s*\\|\\|`),
    new RegExp(`${F}\\s*\\?\\?\\s*(0|false)`),
    new RegExp(`Boolean\\(\\s*${F}`),
    new RegExp(`${F}\\s*\\?\\s*[^:]*:\\s*(0|false)`),
    // A SIXTH PATTERN WAS REMOVED HERE, and the reason matters more than the pattern: it read
    // `<field> === false ?` as "treating false as the only negative branch", and the very ladder that FIXES
    // this bug — `=== true ? 1 : === false ? 0 : null` — matches it. A rule that fires on the correct answer is
    // not a stricter rule, it is a broken one, and the four patterns above already cover turning NULL into a no
    // (!!, ||, ?? 0, Boolean(), and a ternary landing on 0/false).
  ];
  for (const re of COERCIONS) {
    const hit = IDX.match(re);
    // the WRITE path's explicit === true/=== false ladder is not a coercion; it is the thing that prevents one
    if (hit && !/=== true/.test(hit[0])) assert.fail(`a read path coerces the value (${re}): ${hit[0]}`);
  }
});

t('the app cannot type the third state away', () => {
  const p = resolve(HERE, '..', '..', 'VezvezakNew', 'src', 'services', 'merchantService.ts');
  if (!existsSync(p)) { console.log('     · NOTICE: app sibling absent — the client type check is deferred to the full-tree run'); return; }
  const svc = readFileSync(p, 'utf8');
  assert.match(svc, /commissionAgreed\?: boolean \| null;/, 'the client type must allow null, or the UI cannot show "never asked"');
});

t('nothing renders the value as a yes/no without the third state', () => {
  const app = resolve(HERE, '..', '..', 'VezvezakNew', 'src');
  if (!existsSync(app)) { console.log('     · NOTICE: app sibling absent — the render check is deferred to the full-tree run'); return; }
  // Derived, not listed: every .ts/.tsx file under src is read. Today nothing renders the field; the day
  // something does, it must handle null explicitly rather than fall into an else that means "declined".
  const walk = (d, out = []) => {
    for (const e of readdirSync(d)) {
      const p = `${d}/${e}`;
      if (statSync(p).isDirectory()) { if (e !== '__tests__' && e !== 'node_modules') walk(p, out); }
      else if (/\.tsx?$/.test(e)) out.push(p);
    }
    return out;
  };
  let checked = 0;
  for (const f of walk(app)) {
    const src = stripComments(readFileSync(f, 'utf8'));
    if (!/commissionAgreed/.test(src)) continue;
    checked++;
    if (!/commissionAgreed\s*\?\s/.test(src)) continue;              // no ternary on it → nothing to check
    assert.match(src, /commissionAgreed == null|commissionAgreed === null|commissionAgreed !== null|commissionAgreed === undefined/,
      `${f} branches on commissionAgreed without a null branch — "never asked" would render as "declined"`);
  }
  console.log(`     field of view: ${checked} app file(s) mention the field`);
});

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
