// Pure helpers for the "Verified on Vezvezak" badge — matching a search result
// (a Google Places store) to one of OUR merchants. A badge is shown ONLY when a
// real, verified merchant matches by name AND location (Doctrine Art.8: never a
// faked badge). No I/O here, so it's unit-testable.

const SUFFIXES = new Set(['inc', 'llc', 'ltd', 'co', 'corp', 'company', 'the', 'store', 'shop']);

// Normalize a business name to a comparable token set: lowercase, strip
// punctuation/diacritics-ish, drop generic suffix words.
export function nameTokens(name) {
  return String(name || '')
    .toLowerCase()
    .replace(/['’]/g, '')        // drop apostrophes so "Joe's" -> "joes"
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w && !SUFFIXES.has(w));
}

// Two names "match" when normalized-equal OR their token sets overlap strongly
// (Jaccard >= 0.6) — tolerant of "Joe's Pizza" vs "Joes Pizza Co".
export function nameMatches(a, b) {
  const ta = nameTokens(a), tb = nameTokens(b);
  if (ta.length === 0 || tb.length === 0) return false;
  if (ta.join(' ') === tb.join(' ')) return true;
  const sa = new Set(ta), sb = new Set(tb);
  let inter = 0;
  for (const w of sa) if (sb.has(w)) inter++;
  const union = new Set([...ta, ...tb]).size;
  return union > 0 && inter / union >= 0.6;
}

// Distance in metres between two lat/lng points (haversine).
export function haversineM(lat1, lng1, lat2, lng2) {
  if (![lat1, lng1, lat2, lng2].every(n => typeof n === 'number' && Number.isFinite(n))) return Infinity;
  const R = 6371000, toRad = d => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1), dLng = toRad(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(a)));
}

// Does this merchant match the search result? Name matches AND within `maxM`
// metres (default 150m — same storefront, not a same-named shop across town).
export function merchantMatches(result, merchant, maxM = 150) {
  if (!nameMatches(result.name, merchant.store_name)) return false;
  const d = haversineM(result.lat, result.lng, merchant.latitude, merchant.longitude);
  return d <= maxM;
}
