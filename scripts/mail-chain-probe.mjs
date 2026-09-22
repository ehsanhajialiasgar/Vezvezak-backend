#!/usr/bin/env node
// CAN WE ACTUALLY SEND AN EMAIL? — the whole chain, measured, in one command (Ehsan 2026-09-22).
// Run: node scripts/mail-chain-probe.mjs [address]
//
// WHY: "is email working" had been answered by reading code and by waiting for an inbox. Neither is a measurement.
// Every "Forgot password" had been a 503 since the app existed and nothing anywhere said so, because the one
// endpoint that knew answered "Please try again later".
//
// This asks the live Worker, and it asks DNS, and it prints what each one SAID — not what it should say. It sends
// a real code to the address given (default: the founder's), so the last link, the inbox, is checked by a person.
import { execSync } from 'node:child_process';

const API = 'https://vezvezak-api.gfmnhs8y8r.workers.dev';
const TO = process.argv[2] || 'ehsan@vezvezak.com';
const DOMAIN = TO.split('@')[1];
// dig answers with one line per record. Joining them with a separator keeps a two-record answer (an MX pair, a
// CNAME beside a TXT) on ONE row — the first run printed the second line at column 0 and it read like a broken
// value. `only` keeps the lines that actually answer the question asked, so a CNAME in the middle of a TXT
// lookup does not masquerade as the TXT.
const digLines = a => { try { return execSync(`dig +short ${a}`, { encoding: 'utf8' }).trim().split('\n').filter(Boolean); } catch { return []; } };
const dig = (a, only) => digLines(a).filter(l => !only || only(l)).join(' · ');
const isTxt = l => l.startsWith('"');
const line = (label, v, verdict) => console.log(`  ${label.padEnd(26)} ${verdict}  ${v || '—'}`);

console.log(`\nMAIL CHAIN — ${TO}\n`);

// 1 · the Worker: is a key configured at all?
console.log('1 · the live Worker');
let reason = '(no answer)', status = 0, body = {};
try {
  const r = await fetch(`${API}/auth/otp/request`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ identifier: TO, purpose: 'reset' }),
  });
  status = r.status;
  body = await r.json().catch(() => ({}));
  reason = body.reason || '(none)';
} catch (e) { reason = `unreachable: ${e.message}`; }
line('POST /auth/otp/request', `HTTP ${status} reason=${reason}`, status === 200 ? '✓' : '✗');
if (body.error) console.log(`  ${''.padEnd(26)}    said: ${body.error}`);

// 2 · DNS, as it actually stands
console.log('\n2 · DNS for ' + DOMAIN);
const spf = digLines(`TXT ${DOMAIN}`).find(l => l.includes('v=spf1')) || '';
const dmarc = digLines(`TXT _dmarc.${DOMAIN}`).find(l => l.includes('v=DMARC1')) || '';
const dkim = dig(`TXT resend._domainkey.${DOMAIN}`, isTxt);
const sendMx = dig(`MX send.${DOMAIN}`);
const sendSpf = digLines(`TXT send.${DOMAIN}`).find(l => l.includes('v=spf1')) || '';
line('SPF (root)', spf, spf ? '·' : '✗');
line('DMARC', dmarc, dmarc ? '✓' : '✗');
line('DKIM resend._domainkey', dkim ? dkim.slice(0, 60) + '…' : '', dkim ? '✓' : '✗');
line('MX send.' + DOMAIN, sendMx, sendMx ? '✓' : '·');
line('SPF send.' + DOMAIN, sendSpf, sendSpf ? '✓' : '·');

// 3 · the verdict, stated as what is missing rather than as a score
console.log('\n3 · what is missing');
const missing = [];
// A WORKER THAT PREDATES THE REASON MUST NOT BE READ AS "NO PROBLEM" (Ehsan 2026-09-22). Until the fix is
// deployed the 503 carries no `reason`, so the sentence is the only evidence there is — it is matched, and the
// deferral is stated out loud rather than quietly passing (the gate-cannot-see rule).
const oldNotConfigured = status === 503 && /not configured yet/i.test(body.error || '');
if (reason === 'notConfigured' || oldNotConfigured) missing.push('RESEND_API_KEY is not set on the Worker — `npx wrangler secret put RESEND_API_KEY`');
if (reason === 'providerRejected') missing.push('Resend refused us: the key is wrong, or the sending domain is not verified in Resend');
if (status !== 200 && reason === '(none)' && !oldNotConfigured) missing.push(`the Worker refused with HTTP ${status} and no reason — it predates the reason-carrying build, or something else refused; deploy and re-run before trusting this line`);
if (!dkim) missing.push(`no DKIM at resend._domainkey.${DOMAIN} — add the record Resend shows after you add the domain`);
if (!dmarc) missing.push(`no DMARC at _dmarc.${DOMAIN} — without it, inboxes decide on their own`);
else if (!/\bp=(none|quarantine|reject)\b/.test(dmarc)) missing.push(`the DMARC record at _dmarc.${DOMAIN} has no policy (p=) — it is present but says nothing`);
if (!missing.length) console.log('  nothing — a code was accepted for sending. Check the inbox; that is the only link this cannot measure.');
else for (const m of missing) console.log(`  ✗ ${m}`);
console.log('');
process.exit(missing.length ? 1 : 0);
