// THE EMAIL LOOKS LIKE IT COMES FROM A COMPANY, AND STILL TELLS NOBODY ANYTHING (Ehsan 2026-09-22).
//
// It used to be one line — "Your Vezvezak code is 123456" — which is the shape of a phishing message and the
// shape of a message a mail client files under junk. The rules this keeps are the ones that are easy to lose the
// next time someone edits a template: no image (so opening it contacts no third-party host and reports no open),
// no link (so there is nothing to track and nothing for anyone to imitate), a plain-text alternative that says
// the same things, and the brand colour taken from the app's own token rather than typed again.
// Run: node test/mailTemplate.test.mjs
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { codeEmail, purposeCopy, SUPPORT_EMAIL, COMPANY_LINE } from '../src/mailTemplate.js';

const HERE = dirname(fileURLToPath(import.meta.url));
let pass = 0, fail = 0;
const t = (n, fn) => { try { fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

const PURPOSES = ['reset', 'signup', 'signin'];

t('the backend still accepts exactly the three purposes this template writes for', () => {
  const src = readFileSync(resolve(HERE, '..', 'src', 'index.js'), 'utf8');
  const m = src.match(/if \(!\[([^\]]+)\]\.includes\(purpose\)\)/);
  assert.ok(m, 'could not find the purpose whitelist — this check would be blind');
  const accepted = m[1].split(',').map(s => s.trim().replace(/'/g, '')).sort();
  assert.deepEqual(accepted, [...PURPOSES].sort(), `the route accepts ${accepted.join('/')} — the template must cover exactly those`);
});

t('each purpose gets its own subject and heading — none falls through to another', () => {
  const subjects = new Set(), headings = new Set();
  for (const p of PURPOSES) {
    const c = purposeCopy(p);
    assert.ok(c.subject && c.heading && c.lead, `${p} is missing copy`);
    subjects.add(c.subject); headings.add(c.heading);
  }
  assert.equal(subjects.size, 3, 'two purposes share a subject line');
  assert.equal(headings.size, 3, 'two purposes share a heading');
  assert.match(purposeCopy('reset').subject, /password reset/i);
});

t('NO IMAGE and NO LINK — opening it contacts nobody and there is nothing to click', () => {
  for (const p of PURPOSES) {
    const { html } = codeEmail('482913', p);
    assert.doesNotMatch(html, /<img\b/i, `${p}: an image would contact a host when the email is opened`);
    assert.doesNotMatch(html, /background-image|url\(/i, `${p}: a CSS-loaded image is still an image`);
    assert.doesNotMatch(html, /<a\b/i, `${p}: a link is something to track and something to imitate`);
    // The only https:// allowed is the xmlns/doctype namespace, which fetches nothing.
    const urls = [...html.matchAll(/https?:\/\/[^\s"'<>]+/g)].map(m => m[0]).filter(u => !u.startsWith('http://www.w3.org/'));
    assert.deepEqual(urls, [], `${p}: the email reaches out to ${urls.join(', ')}`);
  }
  // NEGATIVE: the detector must actually detect one, or the four assertions above prove nothing.
  assert.match('<img src="https://x/y.png">', /<img\b/i);
});

t('the brand colour is the APP\'s token, not a second copy typed by hand', () => {
  const tokens = resolve(HERE, '..', '..', 'VezvezakNew', 'src', 'core', 'tokens.ts');
  if (!existsSync(tokens)) {
    // A gate that cannot see must DEFER, not rule (2026-09-18).
    console.log('     NOTICE: ../VezvezakNew is not checked out — the brand-colour comparison was SKIPPED, not passed.');
    return;
  }
  const m = readFileSync(tokens, 'utf8').match(/vzBrand:\s*'(#[0-9A-Fa-f]{6})'/);
  assert.ok(m, 'vzBrand is not in tokens.ts any more — re-anchor this check before trusting it');
  const { html } = codeEmail('482913', 'reset');
  assert.ok(html.includes(m[1]), `the email uses a colour that is not the app's ${m[1]}`);
});

t('the code is in both parts, and both carry the same facts', () => {
  for (const p of PURPOSES) {
    const { html, text, subject } = codeEmail('482913', p);
    for (const part of [html, text]) {
      assert.ok(part.includes('482913'), `${p}: the code is missing from one part`);
      assert.ok(part.includes(SUPPORT_EMAIL), `${p}: no support address`);
      assert.ok(part.includes(COMPANY_LINE), `${p}: no company line`);
      assert.match(part, /never ask for your password/i, `${p}: the anti-phishing line is missing`);
      assert.match(part, /expires in 10 minutes/i, `${p}: the expiry is missing`);
      assert.match(part, /ignore this email/i, `${p}: an unexpected code must be safe to ignore, and say so`);
    }
    assert.ok(text.length > 120, `${p}: the plain-text alternative is a stub, not an alternative`);
    assert.ok(!text.includes('<'), `${p}: the plain-text part contains markup`);
    assert.ok(subject.length > 0);
  }
});

t('the stated expiry is the REAL one, read from the route', () => {
  const src = readFileSync(resolve(HERE, '..', 'src', 'index.js'), 'utf8');
  const m = src.match(/const OTP_TTL_MS = (\d+) \* (\d+) \* (\d+);/);
  assert.ok(m, 'could not read OTP_TTL_MS — the minutes in the email would be a guess');
  const minutes = (Number(m[1]) * Number(m[2]) * Number(m[3])) / 60000;
  assert.equal(minutes, 10);
  assert.match(codeEmail('1', 'reset', minutes).text, new RegExp(`expires in ${minutes} minutes`));
  // NEGATIVE: a different TTL must change the sentence, or it is a constant pretending to be derived.
  assert.match(codeEmail('1', 'reset', 25).text, /expires in 25 minutes/);
});

t('the code is escaped — a template that interpolates raw is a template that can be made to lie', () => {
  const { html } = codeEmail('<b>4</b>', 'reset');
  assert.ok(!html.includes('<b>4</b>'), 'raw markup reached the body');
  assert.ok(html.includes('&lt;b&gt;4&lt;/b&gt;'));
});

t('inline styles only — every mail client strips a <style> block', () => {
  const { html } = codeEmail('482913', 'reset');
  assert.doesNotMatch(html, /<style\b/i);
  assert.match(html, /style="/, 'the styling has to live somewhere');
});

console.log(`\nVERDICT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
