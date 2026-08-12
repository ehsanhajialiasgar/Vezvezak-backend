// Proves /extract's SSRF guard blocks internal targets in every encoding, and only
// allows http(s) on ports 80/443. blockedReason is applied to the initial URL AND
// re-applied to every redirect hop (fetchWithGuard, redirect:'manual'), so a public
// URL cannot 302 onto an internal address. (Ehsan 2026-08-11.)
import assert from 'node:assert/strict';
import { blockedReason } from '../src/extract.js';

let pass = 0, fail = 0;
const t = (n, fn) => { try { fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };
const reason = (u) => blockedReason(new URL(u));

console.log('\n/extract SSRF guard — internal targets blocked in every encoding');
const BLOCK = [
  ['http://169.254.169.254/latest', 'internal', 'cloud metadata (link-local)'],
  ['http://2130706433/',            'internal', 'decimal 127.0.0.1'],
  ['http://0x7f000001/',            'internal', 'hex 127.0.0.1'],
  ['http://0177.0.0.1/',            'internal', 'octal 127.x'],
  ['http://10.0.0.5/',              'internal', 'RFC1918 10/8'],
  ['http://192.168.1.1/',           'internal', '192.168/16'],
  ['http://172.20.5.5/',            'internal', '172.16/12'],
  ['http://100.100.0.1/',           'internal', 'CGNAT 100.64/10'],
  ['http://[::1]/',                 'internal', 'IPv6 loopback'],
  ['http://localhost/x',            'internal', 'localhost name'],
];
for (const [u, exp, d] of BLOCK) t(`blocks ${d}`, () => assert.equal(reason(u), exp));

console.log('\nscheme + port allowlist');
t('non-http scheme blocked', () => assert.equal(reason('ftp://example.com/'), 'scheme'));
t('port other than 80/443 blocked', () => assert.equal(reason('http://example.com:8080/'), 'port'));
t('explicit :443 allowed', () => assert.equal(reason('https://example.com:443/'), null));

console.log('\nlegitimate public pages pass');
for (const u of ['http://example.com/', 'https://sub.shop.example.com/product/5', 'https://store.co.uk/']) {
  t(`allows ${u}`, () => assert.equal(reason(u), null));
}

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
