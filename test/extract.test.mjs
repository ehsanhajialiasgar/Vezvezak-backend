// Proves the public reader obeys robots.txt and refuses rather than guesses.
import assert from 'node:assert/strict';
import { isAllowedByRobots, pageToText, extractJsonLd } from '../src/extract.js';

let pass = 0, fail = 0;
const t = (n, fn) => { try { fn(); console.log('  ✅', n); pass++; } catch (e) { console.log('  ❌', n, '\n     ', e.message); fail++; } };

console.log('\nrobots.txt is obeyed (the lawfulness guarantee)');
t('Disallow: / blocks everything', () => {
  assert.equal(isAllowedByRobots('User-agent: *\nDisallow: /', '/prices'), false);
});
t('a disallowed path is blocked, others allowed', () => {
  const r = 'User-agent: *\nDisallow: /admin\nDisallow: /cart';
  assert.equal(isAllowedByRobots(r, '/admin/users'), false);
  assert.equal(isAllowedByRobots(r, '/cart'), false);
  assert.equal(isAllowedByRobots(r, '/prices'), true);
});
t('a rule aimed at VezvezakBot overrides the * group', () => {
  const r = 'User-agent: *\nDisallow:\n\nUser-agent: VezvezakBot\nDisallow: /';
  assert.equal(isAllowedByRobots(r, '/anything'), false);
});
t('Allow overrides a broader Disallow (most specific wins)', () => {
  const r = 'User-agent: *\nDisallow: /\nAllow: /public';
  assert.equal(isAllowedByRobots(r, '/public/prices'), true);
  assert.equal(isAllowedByRobots(r, '/private'), false);
});
t('no robots.txt = allowed', () => {
  assert.equal(isAllowedByRobots('', '/x'), true);
  assert.equal(isAllowedByRobots(null, '/x'), true);
});
t('empty Disallow means allow all', () => {
  assert.equal(isAllowedByRobots('User-agent: *\nDisallow:', '/x'), true);
});
t('comments are ignored', () => {
  assert.equal(isAllowedByRobots('# hi\nUser-agent: *\nDisallow: /x # nope', '/x'), false);
});

console.log('\nstructured data is preferred over guessing');
t('reads a schema.org Product price exactly', () => {
  const html = `<script type="application/ld+json">
    {"@type":"Product","name":"Economy car per day","offers":{"@type":"Offer","price":"39.99","priceCurrency":"USD"}}
  </script>`;
  const o = extractJsonLd(html);
  assert.equal(o.length, 1);
  assert.equal(o[0].price, 39.99);
  assert.equal(o[0].currency, 'USD');
  assert.equal(o[0].name, 'Economy car per day');
});
t('handles an array of offers + nested graph', () => {
  const html = `<script type="application/ld+json">
    [{"@type":"Service","name":"60-min massage","offers":[{"price":"80","priceCurrency":"EUR"},{"price":"120","priceCurrency":"EUR"}]}]
  </script>`;
  assert.equal(extractJsonLd(html).length, 2);
});
t('malformed JSON-LD does not throw', () => {
  assert.deepEqual(extractJsonLd('<script type="application/ld+json">{not json</script>'), []);
});
t('ignores zero / non-numeric prices', () => {
  const html = `<script type="application/ld+json">{"@type":"Offer","price":"0"}</script>`;
  assert.deepEqual(extractJsonLd(html), []);
});

console.log('\npage text is safe to reason over');
t('scripts and styles are stripped (no code leaks into the model)', () => {
  const txt = pageToText('<style>.a{color:red}</style><script>var x=1</script><p>Price: $25</p>');
  assert.ok(!txt.includes('color:red') && !txt.includes('var x'));
  assert.ok(txt.includes('Price: $25'));
});
t('output is length-capped', () => {
  assert.ok(pageToText('<p>' + 'x'.repeat(50000) + '</p>').length <= 12000);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exitCode = fail ? 1 : 0;

// New open-standard extractors (added for the "read every cooperative site" goal)
import { extractMicrodata, extractOpenGraph } from '../src/extract.js';
console.log('\nmore open standards (Microdata + Open Graph)');
{
  const t2=(n,fn)=>{try{fn();console.log('  ✅',n);}catch(e){console.log('  ❌',n,'\n     ',e.message);process.exitCode=1;}};
  t2('reads Microdata itemprop price + name', ()=>{
    const html=`<div itemscope itemtype="https://schema.org/Product">
      <span itemprop="name">Compact SUV per day</span>
      <span itemprop="price" content="45.00">45,00</span>
      <meta itemprop="priceCurrency" content="EUR">
    </div>`;
    const o=extractMicrodata(html);
    assert.equal(o.length,1); assert.equal(o[0].price,45); assert.equal(o[0].currency,'EUR');
    assert.equal(o[0].name,'Compact SUV per day');
  });
  t2('reads Open Graph product price', ()=>{
    const html=`<meta property="og:title" content="Deluxe Massage 60min">
      <meta property="product:price:amount" content="79.99">
      <meta property="product:price:currency" content="USD">`;
    const o=extractOpenGraph(html);
    assert.equal(o.length,1); assert.equal(o[0].price,79.99); assert.equal(o[0].currency,'USD');
    assert.equal(o[0].name,'Deluxe Massage 60min');
  });
  t2('Microdata ignores zero/garbage prices', ()=>{
    assert.deepEqual(extractMicrodata('<span itemprop="price" content="0">free</span>'),[]);
  });
  t2('Open Graph returns nothing when no price meta', ()=>{
    assert.deepEqual(extractOpenGraph('<meta property="og:title" content="About us">'),[]);
  });
}
