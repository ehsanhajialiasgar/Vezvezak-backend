// AFFILIATE WRITES must be FLAG-GATED, default off, fail-closed (Ehsan 2026-09-10).
//
// Two routes WRITE the affiliate tables: /affiliate/click → affiliate_clicks, and
// /affiliate/postback → conversions (the commission record itself). Until today the only thing
// keeping those tables empty was that our app never called them — the CLIENT was gated on
// affiliateActive() while the server accepted whatever arrived. That made privacy §11 a claim
// about our app rather than about our server, and the earlier wording ("we do not collect them")
// claimed an inability the code did not have.
//
// Comments are stripped before any ordering assertion: the handlers' own comments name
// AFFILIATE_ENABLED and env.DB, and matching those would assert against prose instead of code.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const stripComments = x => x.replace(/(^|[^:])\/\/.*$/gm, '$1').replace(/\/\*[\s\S]*?\*\//g, '');
const IDX = stripComments(readFileSync('src/index.js', 'utf8'));
const TOML = readFileSync('wrangler.toml', 'utf8');
let passed = 0;
const t = (name, fn) => { fn(); passed++; console.log('  ok -', name); };

function bodyOf(name) {
  const start = IDX.indexOf(`async function ${name}(`);
  assert.ok(start >= 0, `${name} not found in src/index.js`);
  const end = IDX.indexOf('\n}\n', start);
  assert.ok(end > start, `${name} body end not found`);
  return IDX.slice(start, end);
}

for (const fn of ['affiliateClick', 'affiliatePostback']) {
  t(`${fn} gates on AFFILIATE_ENABLED !== "1" and FAILS CLOSED`, () => {
    const body = bodyOf(fn);
    const m = body.match(/if \(env\.AFFILIATE_ENABLED !== '1'\) (return [^\n;]+);/);
    assert.ok(m, `${fn} must gate on env.AFFILIATE_ENABLED !== '1'`);
    assert.match(m[1], /return fail\(/, `${fn}'s flag gate must REFUSE, never fall through to a write`);
  });

  t(`${fn}: the flag is the FIRST statement — nothing runs before it`, () => {
    const body = bodyOf(fn);
    const flag = body.indexOf('AFFILIATE_ENABLED');
    const write = body.search(/env\.DB\b/);
    const other = body.search(/readJson\(|rateLimit\(|verifyPostbackSecret\(/);
    assert.ok(flag >= 0 && write >= 0, `${fn}: flag and a DB reference must both exist`);
    assert.ok(flag < write, `${fn}: the flag must precede every env.DB reference`);
    assert.ok(other < 0 || flag < other, `${fn}: the flag must precede readJson / rateLimit / verifyPostbackSecret — a refused request must not even be parsed or counted`);
  });
}

t('EVERY write to affiliate_clicks or conversions sits under the flag', () => {
  // The generalising check: the defect class is a writer nobody remembered to gate. Counted at the
  // WRITE, not at the file — index.js holds both, so a file-level check here would be vacuous.
  // Resolve the ENCLOSING FUNCTION of each write and check THAT body. The first version of this
  // check looked back 60 lines for the flag — a PROXIMITY window, not a scope check — and stayed
  // GREEN when a third writer was injected into affiliateStatus, because affiliatePostback's flag
  // sat 26 lines above it. Proximity is a coarser unit than scope and the coarser unit always
  // passes more: the same granularity defect this file exists to catch, inside this file.
  const fnStarts = [...IDX.matchAll(/(?:async )?function (\w+)\s*\(/g)].map(m => ({ name: m[1], at: m.index }));
  const enclosing = (pos) => { let best = null; for (const f of fnStarts) if (f.at < pos && (!best || f.at > best.at)) best = f; return best; };
  const bodyFrom = (at) => { const end = IDX.indexOf('\n}\n', at); return IDX.slice(at, end > at ? end : IDX.length); };
  const unflagged = [];
  for (const m of IDX.matchAll(/INSERT[\s\S]{0,200}?(affiliate_clicks|conversions)/gi)) {
    const fn = enclosing(m.index);
    const line = IDX.slice(0, m.index).split('\n').length;
    if (!fn) { unflagged.push(`${line} (no enclosing function)`); continue; }
    if (!/AFFILIATE_ENABLED !== '1'/.test(bodyFrom(fn.at))) unflagged.push(`${line} in ${fn.name}()`);
  }
  assert.deepEqual(unflagged, [], `an INSERT into an affiliate table has no AFFILIATE_ENABLED flag IN ITS OWN FUNCTION: ${unflagged.join('; ')}`);
});

t('wrangler.toml declares AFFILIATE_ENABLED and DEFAULTS IT OFF — flipping it needs privacy §11 first', () => {
  const m = TOML.match(/AFFILIATE_ENABLED\s*=\s*"([^"]*)"/);
  assert.ok(m, 'AFFILIATE_ENABLED must be declared in wrangler.toml [vars]');
  assert.notEqual(m[1], '1',
    'AFFILIATE_ENABLED must not be committed as "1".\n' +
    '\n' +
    'ONE RULE: THE WORLD MUST NEVER BE MORE PERMISSIVE THAN THE PAGE SAYS.\n' +
    'It runs in opposite orders depending on which way you are moving, and adding a refusal is\n' +
    'not the same move as removing one:\n' +
    '\n' +
    '  LOOSENING the world (this failure — flipping the flag 0 -> 1, so the server starts\n' +
    '  accepting purchase-referral and commission records): THE PAGE LOOSENS FIRST. Privacy §11\n' +
    '  currently states the server will NOT accept one. Update §11, publish it, verify live == repo,\n' +
    '  and only then flip this flag and deploy. Deploying first makes a published legal sentence\n' +
    '  false the moment it lands, with no other code change and no other gate firing.\n' +
    '\n' +
    '  TIGHTENING the world (adding a refusal, as this flag itself did on 2026-09-10): THE PAGE\n' +
    '  FOLLOWS. Deploy the worker first, then publish the page. In between, the page understates\n' +
    '  our protection — it claims less than the server does — which is inaccurate but never a claim\n' +
    '  to a safety we lack.\n' +
    '\n' +
    'SEPARATE CONDITION, do not confuse it with this one: the FTC disclosures are held by\n' +
    'affiliate-disclosure-gate in the app repo, keyed on an id being filled in src/services/affiliate.ts.\n' +
    'The material connection exists if and only if an id is filled; this flag governs whether our\n' +
    'SERVER records anything. Different units, deliberately.');
});

console.log(`\naffiliate flag gate: ${passed}/6 checks passed`);
