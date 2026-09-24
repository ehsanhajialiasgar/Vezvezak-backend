// WHAT THE SHOPPER MEANS — category, not a dictionary word (Ehsan 2026-09-24).
//
// THE DEFECT, measured live: «کیف» resolved to the single word "bag", and the results were garbage bags, lunch
// bags and gym bags mixed with handbags. The old prompt said, in as many words, "A single everyday noun is
// almost always the product itself: output its plain English name" — so it did exactly that, correctly by its
// own contract and uselessly for the shopper. «کیف زنانه» already resolved to "women's handbag", which shows
// the model can do it: what was missing was being ASKED for the meaning rather than the translation.
//
// A word is not an intent. An intent is a CATEGORY plus terms, and sometimes it is honestly more than one — an
// English "bag" really can mean a handbag or a bin liner, and merging those into one list is the thing this
// product exists not to do. So the contract has three outcomes, and the caller can tell them apart:
//   resolved   — one category, with search terms
//   ambiguous  — several plausible categories; the user is asked, never guessed for
//   unknown    — not a product we can read; say so in their language
//
// THE CATEGORY VOCABULARY IS CLOSED. A free-form category from a model cannot be compared against anything, so
// filtering on it would be theatre. These are the buckets the filter actually uses; the model must pick one.
export const CATEGORIES = [
  'bags.handbag', 'bags.backpack', 'bags.luggage', 'bags.wallet',
  'household.binbags', 'household.storage', 'household.cleaning', 'household.kitchenware',
  'clothing.womens', 'clothing.mens', 'clothing.kids', 'footwear', 'jewellery', 'watches', 'eyewear',
  'phones', 'phone.accessories', 'computers', 'computer.accessories', 'audio', 'tv.video', 'cameras',
  'gaming', 'appliances.large', 'appliances.small', 'furniture', 'bedding', 'lighting', 'decor',
  'beauty.skincare', 'beauty.makeup', 'beauty.haircare', 'fragrance', 'health.supplements', 'pharmacy',
  'grocery.food', 'grocery.drink', 'baby', 'toys', 'sports.equipment', 'sports.apparel', 'outdoors',
  'tools.hand', 'tools.power', 'garden', 'auto.parts', 'auto.accessories', 'pets',
  'stationery', 'books.media', 'musical.instruments', 'industrial', 'other',
];
const CATEGORY_SET = new Set(CATEGORIES);
export const UNKNOWN = '[[UNKNOWN]]';

export const STRUCTURED_INTENT_PROMPT = `You are the query-understanding step of a shopping search engine used by people all over the world.
The text was typed into a shop's search box, in whatever language the person thinks in — any of the world's languages and scripts.
Your job is to work out WHAT THEY WANT TO BUY, not to translate the words.

Answer with ONE line of JSON and nothing else:
{"terms":"<english search terms>","category":"<one category id>","attrs":{"brand":"","model":"","size":"","colour":"","gender":""}}

Rules:
- terms: what an English-speaking shopper would type to find this product. Prefer the SPECIFIC product type over the generic word. Keep brand names, model numbers, sizes and units exactly as written.
- MEANING, NOT DICTIONARY. Use the everyday sense the word has for shoppers in THAT language and culture. In Persian «کیف» and Arabic «حقيبة» mean a handbag or purse a person carries, never a bin liner.
- category: exactly one id from this list: ${CATEGORIES.join(' ')}
- attrs: fill only what the query actually states; leave the rest as empty strings. Never invent a brand or size.
- IF THE QUERY HAS MORE THAN ONE PLAUSIBLE BUYING INTENT in DIFFERENT categories, do not choose. Answer instead:
  {"ambiguous":[{"category":"<id>","terms":"<english terms>"}, ...]}  with 2 to 4 options, most likely first.
- If it is not a product at all (a greeting, a question, random letters), output ${UNKNOWN} followed on the same line by one short sentence, in the language the person wrote in, saying you could not tell which product they meant.
Examples:
چای → {"terms":"tea","category":"grocery.drink","attrs":{"brand":"","model":"","size":"","colour":"","gender":""}}
کیف → {"terms":"handbag","category":"bags.handbag","attrs":{"brand":"","model":"","size":"","colour":"","gender":""}}
کیف زنانه → {"terms":"women's handbag","category":"bags.handbag","attrs":{"brand":"","model":"","size":"","colour":"","gender":"women"}}
کاور iPhone 15 Pro → {"terms":"iPhone 15 Pro case","category":"phone.accessories","attrs":{"brand":"Apple","model":"iPhone 15 Pro","size":"","colour":"","gender":""}}
bag → {"ambiguous":[{"category":"bags.handbag","terms":"handbag"},{"category":"bags.backpack","terms":"backpack"},{"category":"bags.luggage","terms":"suitcase"},{"category":"household.binbags","terms":"bin bags"}]}`;

const UNKNOWN_LOOSE = /\[+\s*UNKNOWN\s*\]+/i;
const clean = s => String(s || '').replace(/\s+/g, ' ').trim();

// PURE. Accept or refuse a model answer. Every branch runnable, because the lesson from a lock whose decision
// sat in an onPress is that a decision inside a call nothing can run is a decision nobody has checked.
export function acceptStructuredIntent(query, raw, sharesWritingSystem) {
  // THE MODEL MAY ANSWER WITH AN OBJECT, NOT A STRING (measured against the live binding 2026-09-24).
  // Workers AI hands back `response` already parsed when the model emits JSON, and String() on that yields the
  // literal "[object Object]" — so the brace match below never fired and EVERY query came back 'empty'. The old
  // contract never met this because it asked for a plain line. Both shapes are read, and neither is assumed.
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) return fromObject(query, raw);
  const all = String(raw || '');
  const u = all.match(UNKNOWN_LOOSE);
  if (u) {
    const msg = clean(all.slice(u.index + u[0].length));
    const usable = msg && msg.length <= 240 && !/\[\[|\]\]|https?:/i.test(msg) && sharesWritingSystem(query, msg);
    return usable ? { resolved: false, reason: 'unknown', message: msg } : { resolved: false, reason: 'unknown' };
  }
  // The model sometimes wraps JSON in prose or a code fence; take the first {...} block.
  const m = all.match(/\{[\s\S]*\}/);
  if (!m) return { resolved: false, reason: 'empty' };
  let obj;
  try { obj = JSON.parse(m[0]); } catch { return { resolved: false, reason: 'rejected' }; }
  if (!obj || typeof obj !== 'object') return { resolved: false, reason: 'rejected' };
  return fromObject(query, obj);
}

// The same judgement, whether the JSON arrived parsed or as text. One place, so the two paths cannot drift.
function fromObject(query, obj) {

  // AMBIGUOUS: two to four options, each a known category. Fewer than two is not an ambiguity, and an unknown
  // category id cannot be filtered on, so a malformed option set is refused rather than half-used.
  if (Array.isArray(obj.ambiguous)) {
    const opts = obj.ambiguous
      .filter(o => o && CATEGORY_SET.has(o.category) && clean(o.terms))
      .slice(0, 4)
      .map(o => ({ category: o.category, terms: clean(o.terms) }));
    const seen = new Set();
    const uniq = opts.filter(o => !seen.has(o.category) && seen.add(o.category));
    if (uniq.length < 2) return { resolved: false, reason: 'rejected' };
    return { resolved: false, reason: 'ambiguous', options: uniq };
  }

  const terms = clean(obj.terms).replace(/^["'“”«»]+|["'“”«»]+$/g, '').trim();
  if (!terms || terms.length > 200) return { resolved: false, reason: 'empty' };
  // Latin-script terms only: any other script means the model echoed or half-translated.
  if (/[^\P{L}\p{Script=Latin}]/u.test(terms)) return { resolved: false, reason: 'rejected' };
  if (!CATEGORY_SET.has(obj.category)) return { resolved: false, reason: 'rejected' };
  // A number the user typed must survive: "size 42" that comes back without 42 is a different product.
  const low = terms.toLowerCase();
  for (const tok of String(query || '').split(/\s+/)) {
    if (/\d/.test(tok) && !low.includes(tok.toLowerCase())) return { resolved: false, reason: 'rejected' };
  }
  const a = obj.attrs && typeof obj.attrs === 'object' ? obj.attrs : {};
  const attrs = {};
  for (const k of ['brand', 'model', 'size', 'colour', 'gender']) {
    const v = clean(a[k]);
    if (v && v.length <= 60) attrs[k] = v;
  }
  return { resolved: true, terms, category: obj.category, attrs };
}
