// INTENT RESOLUTION FOR SEARCH (Ehsan 2026-09-16) — replaces the m2m100 translator that was built-held on 2026-08-19
// («کاور»→"Kareem"). Requirement: the user writes in any language or script; the app works out WHICH PRODUCT they mean,
// then searches with English terms. NO LANGUAGE LIST: every query goes to the model (founder rule — a list is a thing
// someone forgets; the old 8-script list missed Hindi, Armenian and Spanish and read Pashto as Persian).
//
// Model: the same Workers AI llama-3.3-70b the assistant uses — on Cloudflare, no third-party egress. Live harness
// 2026-09-16 (throwaway AI-only worker, never deployed): نمک→salt, میز→table, کیف→bag, कुर्सी→chair, silla→chair,
// «کاور iPhone 15 Pro»→"iPhone 15 Pro case", «هدفون WH-1000XM5 بی‌سیم»→"WH-1000XM5 wireless headphones";
// Arabic «كيف» (how), «سلام», "asdfgh" and Pashto «مالګه» → [[UNKNOWN]]; Armenian աթոռ→"armchair" (chair — close, not
// exact). With the sentence rule, [[UNKNOWN]] came back with a sentence in Arabic, Persian, Spanish, Pashto, Tagalog and
// English; Armenian and Bengali were cut at 80 tokens (hence 100); Amharic was garbled but in its own script. ~170 prompt + 2-9 output tokens ≈ 5 neurons ≈ $0.000055 per uncached query; 15 of 17 answered in < 1 s,
// two took ~3.7-4.0 s.
//
// MODEL NUMBERS ARE CHECKED, NOT TRUSTED: every token of the query that contains a digit must appear verbatim in the
// answer, the answer must be one line of Latin-script text, and [[UNKNOWN]] means the model could not tell. Anything
// else is UNRESOLVED — never a guess passed on as the user's product.
import { sha256 } from './lib.js';

// EXAMPLES (2026-09-16): no worked "could not tell" example. With the Japanese one the model copied that sentence for
// Tagalog, Chinese, Korean and English inputs; without it, 115/120 twice and 2 wrong products (with it 114/113, 3);
// two examples (Spanish + Russian) gave English sentences to Tagalog queries — same script, so no check can catch it.
// MODEL (founder 2026-09-16, from the 20-language eval, docs/intent-eval): llama-4-scout + this prompt scored 114 and 113
// of 120 (llama-3.3-70b + the first prompt: 106 and 105), 3 wrong products (vs 5–6), p90 ~670–800 ms (vs 1.1–1.7 s), at
// ~$0.000095 per uncached query (vs ~$0.000082). It fixed Pashto (2→5/6) and Amharic (3→6/6). NO retry: a second ask
// turned abstentions into wrong products (llama 5→13, scout 3→7).
export const INTENT_MODEL = '@cf/meta/llama-4-scout-17b-16e-instruct';
export const UNKNOWN = '[[UNKNOWN]]';
export const INTENT_PROMPT = `You are the query-understanding step of a shopping search engine used by people all over the world.
The text you receive was typed into a shop's search box. It is almost always the name of a product someone wants to buy, usually one to five words, written in whatever language the person thinks in — any of the world's languages and scripts, including less widely spoken ones.
Your job: work out which product they want, and output the search terms an English-language online store needs to find that product.
How to decide:
- First identify the language from the words themselves (not from the script alone — several languages share a script and the same spelling can mean different things). Then identify the product in that language.
- A single everyday noun is almost always the product itself: output its plain English name.
- Keep brand names, model names, model numbers, sizes and units exactly as written.
- Output ONLY the English search terms on one line: no explanation, no quotes, no trailing punctuation.
- If the text is not a product at all (a greeting, a question, random letters), output ${UNKNOWN} followed, on the same line, by one short sentence in the language the person wrote in, saying you could not tell which product they meant.
Examples:
چای → tea
sartén → frying pan
कप → cup
кроссовки Nike 42 → Nike sneakers size 42
کاور iPhone 15 Pro → iPhone 15 Pro case`;

// A reply is in the user's writing system when it contains a letter from the same area of Unicode as the FIRST LETTER
// of what the user typed. A property of the text, not a language list: Latin (U+0000–U+02FF) counts as one area, the
// big ideographic/syllabic ranges from U+3000 are grouped by 0x1000, everything else by its 0x100 block. The live
// harness answered a Persian question in Chinese; this is what catches that.
const areaOf = cp => (cp < 0x300 ? 0 : cp >= 0x3000 ? 0x3000 + ((cp - 0x3000) >> 12) * 0x1000 : (cp >> 8) << 8);
const firstLetterArea = text => { for (const ch of String(text || '')) if (/\p{L}/u.test(ch)) return areaOf(ch.codePointAt(0)); return null; };
export function sharesWritingSystem(question, reply) {
  const area = firstLetterArea(question);
  if (area == null) return false;
  for (const ch of String(reply || '')) if (/\p{L}/u.test(ch) && areaOf(ch.codePointAt(0)) === area) return true;
  return false;
}

// The model's "could not tell" sentence, in the user's language — or undefined when it is missing, runs past one short
// line, carries the token again, or is not in the user's writing system (the app then uses its own sentence).
function unknownMessage(query, text) {
  const msg = String(text || '').replace(/\s+/g, ' ').trim();
  if (!msg || msg.length > 240 || /\[\[|\]\]|https?:/i.test(msg)) return undefined;
  return sharesWritingSystem(query, msg) ? msg : undefined;
}

const UNKNOWN_LOOSE = /\[+\s*UNKNOWN\s*\]+/i;

// PURE + unit-tested: accept or refuse a model answer for a query.
export function acceptIntent(query, raw) {
  const all = String(raw || '');
  const u = all.match(UNKNOWN_LOOSE);
  if (u) {
    const message = unknownMessage(query, all.slice(u.index + u[0].length));
    return message ? { resolved: false, reason: 'unknown', message } : { resolved: false, reason: 'unknown' };
  }
  const out = all.split('\n')[0].trim().replace(/^["'“”«»]+|["'“”«».]+$/g, '').trim();
  if (!out) return { resolved: false, reason: 'empty' };
  if (out.length > 200) return { resolved: false, reason: 'rejected' };
  // Latin-script answer only: a letter from any other script means the model echoed or half-translated.
  if (/[^\P{L}\p{Script=Latin}]/u.test(out)) return { resolved: false, reason: 'rejected' };
  const low = out.toLowerCase();
  for (const tok of String(query || '').split(/\s+/)) {
    if (/\d/.test(tok) && !low.includes(tok.toLowerCase())) return { resolved: false, reason: 'rejected' };
  }
  return { resolved: true, query: out };
}

// One model call. Throws only on a model/runtime error (the route maps it to unresolved).
export async function resolveIntent(env, query) {
  const r = await env.AI.run(INTENT_MODEL, {
    messages: [{ role: 'system', content: INTENT_PROMPT }, { role: 'user', content: query }],
    max_tokens: 100,   // room for the "could not tell" sentence in scripts that cost more tokens
    temperature: 0,
  });
  return acceptIntent(query, r?.response);
}

// ── cache: GLOBAL and identifier-free ────────────────────────────────────────
// Keyed by sha256(namespace || query) — the resolver's namespace is 'intent' — the RAW query is never stored (only its hash), there is
// no user id and no IP, and there is no per-user anything. A query translation is a language fact,
// not private user content (founder), so a repeated Persian query is free after the first — same
// discipline as the Places cache: caching for latency/cost, never a per-user record.
// RETENTION (Ehsan 2026-09-16): an entry older than this is not used and is deleted on the next write.
export const CACHE_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
async function cacheKey(query, source) {
  return sha256(`${source}\u0000${query}`);
}
export async function cacheGet(env, query, source) {
  try {
    const row = await env.DB.prepare('SELECT translated FROM translation_cache WHERE k = ? AND at >= ?')
      .bind(await cacheKey(query, source), Date.now() - CACHE_RETENTION_MS).first();
    return row && typeof row.translated === 'string' ? row.translated : null;
  } catch {
    return null;
  }
}
export async function cacheSet(env, query, source, translated, at) {
  try {
    const k = await cacheKey(query, source);
    await env.DB.prepare(
      'INSERT INTO translation_cache (k, translated, at) VALUES (?, ?, ?) ' +
      'ON CONFLICT(k) DO UPDATE SET translated = ?, at = ?',
    ).bind(k, translated, at, translated, at).run();
    await env.DB.prepare('DELETE FROM translation_cache WHERE at < ?').bind(at - CACHE_RETENTION_MS).run();
  } catch {
    // A cache write failure is non-fatal — the translation still returns.
  }
}
