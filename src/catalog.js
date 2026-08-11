// Pure normalizers for the seller catalog — no I/O, unit-testable.
//
// Honesty is enforced HERE, not trusted from the seller (Doctrine Art.8):
//  • stock is NULL (unknown) unless the seller states true/false — never faked.
//  • a was_price is kept ONLY when it is genuinely higher than the price, so a
//    "discount" can never be manufactured by entering a fake original price.
//  • a GTIN is kept only if it's a valid length; junk is dropped, not stored.

const CONDITIONS = new Set(['new', 'used', 'refurbished']);

function str(v, max) {
  const s = String(v ?? '').trim();
  return s ? s.slice(0, max) : '';
}
function numOrNull(v) {
  if (v === undefined || v === null || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : null;
}
function intOrNull(v) {
  const n = numOrNull(v);
  return n === null ? null : Math.floor(n);
}

export function normalizeCondition(raw) {
  const s = String(raw || '').trim().toLowerCase();
  return CONDITIONS.has(s) ? s : null;
}

// A GTIN/UPC/EAN is only kept if it is all digits of a real length.
export function normalizeGtin(raw) {
  const d = String(raw || '').replace(/\D/g, '');
  return [8, 12, 13, 14].includes(d.length) ? d : null;
}

export function normalizeItem(input) {
  const title = str(input.title, 200);
  if (!title) return { ok: false, error: 'title required' };
  return {
    ok: true,
    value: {
      title,
      brand: str(input.brand, 80) || null,
      model: str(input.model, 120) || null,
      gtin: normalizeGtin(input.gtin),
      category: str(input.category, 80) || null,
      condition: normalizeCondition(input.condition),
      description: str(input.description, 4000) || null,
      imageUrl: /^https?:\/\//i.test(String(input.imageUrl || '')) ? str(input.imageUrl, 500) : null,
    },
  };
}

// Deterministic prohibited-content screen — the fast first moderation layer, run
// before any AI. Catches clearly-illegal/against-policy listings by keyword so
// they're rejected instantly and never depend on a model being available.
const PROHIBITED = [
  { re: /\b(guns?|firearms?|rifles?|pistols?|handguns?|ammunition|ammo|silencers?)\b/i, reason: 'weapons' },
  { re: /\b(grenades?|explosives?|c4|dynamite|bombs?)\b/i, reason: 'weapons' },
  { re: /\b(cocaine|heroin|meth(amphetamine)?|mdma|\blsd\b|illegal drugs?|narcotics?)\b/i, reason: 'drugs' },
  { re: /\b(counterfeit|knock ?off|fake (rolex|gucci|louis|brand)|replica (watch|bag))\b/i, reason: 'counterfeit' },
  { re: /\b(human organs?|organ for sale|human trafficking)\b/i, reason: 'illegal' },
  { re: /\b(child ?porn|csam|underage (porn|sex))\b/i, reason: 'csam' },
];

export function screenCatalogText(text) {
  const s = String(text || '');
  for (const p of PROHIBITED) if (p.re.test(s)) return { prohibited: true, reason: p.reason };
  return { prohibited: false };
}

export function normalizeVariant(input) {
  const price = numOrNull(input.price);
  const wasRaw = numOrNull(input.wasPrice ?? input.was_price ?? input.originalPrice);
  // Keep was_price ONLY if it's a real markdown above the current price.
  const wasPrice = wasRaw !== null && price !== null && wasRaw > price ? wasRaw : null;

  let attributes = null;
  if (input.attributes && typeof input.attributes === 'object') {
    try { attributes = JSON.stringify(input.attributes).slice(0, 2000); } catch { attributes = null; }
  } else if (typeof input.attributes === 'string') {
    attributes = str(input.attributes, 2000) || null;
  }

  const inStock = input.inStock === true ? 1 : input.inStock === false ? 0 : null;

  return {
    ok: true,
    value: {
      sku: str(input.sku, 80) || null,
      attributes,
      price,
      currency: (str(input.currency, 8) || '').toUpperCase() || null,
      wasPrice,
      unit: str(input.unit, 24) || null,
      inStock,
      quantity: intOrNull(input.quantity),
      tierMinQty: intOrNull(input.tierMinQty ?? input.tier_min_qty),
    },
  };
}
