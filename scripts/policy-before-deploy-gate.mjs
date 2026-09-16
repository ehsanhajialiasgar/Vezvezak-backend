#!/usr/bin/env node
// POLICY BEFORE DEPLOY — blocks `npm run deploy` (predeploy) (Ehsan 2026-09-15).
// Run: node scripts/policy-before-deploy-gate.mjs
//
// THE RULE: the world must never be more open than the page says. A deploy that starts WRITING a database column the
// DEPLOYED privacy policy does not describe publishes the collection before the disclosure. The policy text goes out
// first; this gate refuses the deploy until it has.
//
// INCIDENT: launch-chain steps 5/6 (88d439e, 2edcc9d) made the Worker write user_plans.expires_at, source,
// original_transaction_id, environment and comp_redeemed. Policy §2 describes none of them. It was a note in a report;
// it is now this gate.
//
// DERIVED, NOT LISTED:
//   • NEW columns = every column in an INSERT INTO t (…) / UPDATE t SET … in src/ at HEAD, MINUS the same derivation run
//     on the tree at BASELINE (read from git at run time — no hand-kept column list).
//   • Each new column needs a PHRASE here AND that phrase must appear in the page fetched from the live URL. A new
//     column with no phrase fails outright: describe it in the policy and give it its phrase in the same pass.
//   • Both derivations must be non-empty, and the fetched page must be non-empty (a comparison needs two sides).
//
// STATED LIMITS:
//   • BASELINE = the commit the LIVE Worker runs, derived at run time (see liveBaseline). Cloudflare holds no git sha
//     of its own, so `npm run deploy` writes one: --tag <HEAD>. The gate reads the live version, and if a secret change
//     made it untagged, the newest tagged version with the SAME script etag. Uploads made before tagging existed are
//     recorded in UNTAGGED by etag — a fact the gate re-checks against Cloudflare on every run, not a free constant.
//     Anything it cannot resolve — split traffic, an unknown etag, a tag git does not know — blocks the deploy.
//   • Wrangler lists only the most recent versions; more untagged secret changes than that since the last deploy
//     leaves the tagged one out of view and the gate blocks (safe direction).
//   • `npx wrangler deploy` run by hand bypasses npm's predeploy. Deploy with `npm run deploy`.
//   • Containment only: a phrase present on the page is not proof the sentence around it is right (a person reads it).
//   • It sees SQL literals in src/. A column written through a dynamically built statement would be invisible.
import { execSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

// Uploads made before deploys carried a tag: script etag → commit. Each entry is evidence, not belief — it is used
// only while Cloudflare reports that exact etag as live.
// 77ff5c8b… = version 13a34f7b (uploaded 2026-09-10T12:41Z, two minutes after 1d026f5) and the secret change 811f8393.
// Probed 2026-09-16, not read from a dashboard: POST /extract answers 401 (route present — before a49358d deleted
// it) and /affiliate/click answers 503 affiliate_disabled (0b1e2dc or later); src is identical 0b1e2dc..1d026f5.
// The constant it replaces said 531bee3, which was never deployed; nothing checked it.
const UNTAGGED = { '77ff5c8b2c183668fc535651aa95319c4436264cdda4d237bfb226d559682546': '1d026f5' };
const WRANGLER = (JSON.parse(readFileSync('package.json', 'utf8')).scripts.deploy.match(/^npx --yes (wrangler@\d+\.\d+\.\d+) deploy --tag /) || [])[1];
const wrangler = args => JSON.parse(execSync(`npx --yes ${WRANGLER} ${args} --json`, { encoding: 'utf8', env: { ...process.env, CI: '1' }, stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000, maxBuffer: 32e6 }));
const TAG = v => v?.annotations?.['workers/tag'];
function liveBaseline() {
  if (!WRANGLER) throw new Error('package.json "deploy" is not `npx --yes wrangler@<exact> deploy --tag …` — the deploy would not record its commit');
  const dirty = execSync('git status --porcelain -- src wrangler.toml', { encoding: 'utf8' }).trim();
  if (dirty) throw new Error(`src/ or wrangler.toml differs from HEAD — the upload would not be the commit its tag names:\n${dirty}`);
  const shares = wrangler('deployments status').versions || [];
  if (shares.length !== 1 || shares[0].percentage !== 100) throw new Error(`live traffic is split across ${shares.length} version(s) — one baseline cannot describe it`);
  const id = shares[0].version_id;
  const live = wrangler(`versions view ${id}`);
  const etag = live?.resources?.script?.etag;
  if (!etag) throw new Error(`live version ${id} reports no script etag`);
  let sha, how;
  if (TAG(live)) [sha, how] = [TAG(live), `tag on live version ${id.slice(0, 8)}`];
  else {
    for (const v of wrangler('versions list').reverse()) {
      if (!TAG(v)) continue;
      if (wrangler(`versions view ${v.id}`)?.resources?.script?.etag === etag) { [sha, how] = [TAG(v), `tag on ${v.id.slice(0, 8)}, same script etag as live ${id.slice(0, 8)}`]; break; }
    }
    if (!sha && UNTAGGED[etag]) [sha, how] = [UNTAGGED[etag], `recorded untagged upload, live ${id.slice(0, 8)} etag ${etag.slice(0, 8)}`];
  }
  if (!sha) throw new Error(`live version ${id} (etag ${etag.slice(0, 12)}) matches no tagged version and no recorded upload — find what is running (a probe that answers differently between versions) and record it`);
  try { execSync(`git cat-file -e ${sha}^{commit}`, { stdio: 'ignore' }); } catch { throw new Error(`live commit ${sha} (${how}) is not in this repository`); }
  return [sha, how];
}
let BASELINE, BASELINE_HOW;
try { [BASELINE, BASELINE_HOW] = liveBaseline(); }
catch (e) { console.error(`POLICY BEFORE DEPLOY — BLOCKED: COULD NOT DERIVE THE LIVE COMMIT — ${e.message.split('\n')[0]}`); if (e.message.includes('\n')) console.error(e.message.split('\n').slice(1).join('\n')); process.exit(1); }
console.log(`  live commit: ${BASELINE} (${BASELINE_HOW})`);
const POLICY_URL = 'https://vezvezak.com/privacy/';

// A phrase per column the policy must carry before a deploy may write it. The five IAP/comp columns had none until
// publish 4 described them; the phrase follows the published text, never the other way round.
const PHRASE = {
  // The baseline Worker only READ user_plans (plans were set owner-side); /iap/validate and /comp/redeem write the row.
  // §2 already carries the tier, stored against the account: "Your subscription tier and search counts".
  'user_plans.plan': 'Your subscription tier',
  'user_plans.user_id': 'Your subscription tier',
  // Publish 4 (site c179dce, live 2026-09-16) — §2 "If you have a paid plan: …", the approved wording:
  'user_plans.expires_at': 'when it expires',
  'user_plans.source': 'from a promotional code',
  'user_plans.original_transaction_id': 'original transaction ID',
  'user_plans.environment': 'test (sandbox)',
  'user_plans.comp_redeemed': 'hash of each code you redeemed',
};

// A published SENTENCE a new route falsifies. Derived: the routes are read from src/index.js at HEAD and at BASELINE;
// a route new since the baseline whose sentence is still on the deployed page blocks the deploy.
const FALSIFIED_BY_ROUTE = {
  '/iap/validate': 'Vezvezak has no paid subscriptions today',
  '/comp/redeem': 'Vezvezak has no paid subscriptions today',
};
const BOOKKEEPING = new Set(['id', 'created_at', 'updated_at', 'at']);

const WRITE_RE = [
  [/INSERT\s+(?:OR\s+\w+\s+)?INTO\s+(\w+)\s*\(([^)]+)\)/gi, m => m[2].split(',').map(c => c.trim().replace(/['"+\s]/g, ''))],
  [/UPDATE\s+(\w+)\s+SET\s+([\s\S]+?)\s+WHERE/gi, m => [...m[2].matchAll(/(\w+)\s*=/g)].map(c => c[1])],
];
function derive(files) {
  const out = new Set();
  for (const src of files) for (const [re, cols] of WRITE_RE) for (const m of src.matchAll(re)) for (const c of cols(m)) if (c) out.add(`${m[1]}.${c}`);
  return out;
}
const walk = d => readdirSync(d).flatMap(f => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : /\.(m?js|ts)$/.test(f) ? [p] : []; });
const head = derive(walk('src').map(f => readFileSync(f, 'utf8')));
const baseFiles = execSync(`git ls-tree -r --name-only ${BASELINE} -- src`, { encoding: 'utf8' }).split('\n').filter(f => /\.(m?js|ts)$/.test(f));
const base = derive(baseFiles.map(f => execSync(`git show ${BASELINE}:${f}`, { encoding: 'utf8', maxBuffer: 32e6 })));

const fails = [];
if (!head.size || !base.size) fails.push(`✗ COULD NOT VERIFY — derived columns: HEAD ${head.size}, ${BASELINE} ${base.size} (both must be non-empty)`);
const fresh = [...head].filter(c => !base.has(c) && !BOOKKEEPING.has(c.split('.')[1])).sort();

const routesOf = src => new Set([...src.matchAll(/p === '(\/[\w/-]+)'/g)].map(m => m[1]));
const headRoutes = routesOf(readFileSync('src/index.js', 'utf8'));
const baseRoutes = routesOf(execSync(`git show ${BASELINE}:src/index.js`, { encoding: 'utf8', maxBuffer: 32e6 }));
if (!headRoutes.size || !baseRoutes.size) fails.push(`✗ COULD NOT VERIFY — routes derived: HEAD ${headRoutes.size}, ${BASELINE} ${baseRoutes.size}`);
const newRoutes = [...headRoutes].filter(r => !baseRoutes.has(r) && FALSIFIED_BY_ROUTE[r]);

let page = '';
if (fresh.length || newRoutes.length) {
  try {
    const r = await fetch(`${POLICY_URL}?gate=${Date.now()}`, { headers: { 'Cache-Control': 'no-cache', 'User-Agent': 'vezvezak-policy-before-deploy' } });
    page = r.ok ? (await r.text()).replace(/<[^>]*>/g, ' ').replace(/&rsquo;/g, "'").replace(/\s+/g, ' ') : '';
  } catch { page = ''; }
  if (!page) fails.push(`✗ COULD NOT VERIFY — the deployed policy at ${POLICY_URL} returned nothing; a deploy that adds columns cannot proceed blind`);
}
for (const c of fresh) {
  if (!PHRASE[c]) fails.push(`✗ ${c} — written at HEAD, not at the deployed baseline ${BASELINE}, and the policy has no phrase for it. Publish the text first, then add its phrase here.`);
  else if (page && !page.toLowerCase().includes(PHRASE[c].toLowerCase())) fails.push(`✗ ${c} — phrase "${PHRASE[c]}" is not on the DEPLOYED policy. Publish the policy before this deploy.`);
}

for (const r of newRoutes) if (page && page.includes(FALSIFIED_BY_ROUTE[r])) fails.push(`✗ route ${r} is new since ${BASELINE} and the deployed policy still says "${FALSIFIED_BY_ROUTE[r]}". Publish the corrected text before this deploy.`);

console.log(`  field of view: routes HEAD ${headRoutes.size} / ${BASELINE} ${baseRoutes.size}, new route(s) that falsify a published sentence: ${newRoutes.join(', ') || '—'}`);
console.log(`  field of view: ${head.size} table.column writes at HEAD, ${base.size} at deployed baseline ${BASELINE}; ${fresh.length} new: ${fresh.join(', ') || '—'}`);
if (fails.length) { console.error(`POLICY BEFORE DEPLOY — BLOCKED (${fails.length}):\n  ${fails.join('\n  ')}`); process.exit(1); }
console.log('  ✓ every column this deploy newly writes is described on the deployed policy');
