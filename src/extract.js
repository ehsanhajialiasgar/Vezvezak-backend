/**
 * PUBLIC PAGE READER — the lawful answer to "SerpApi doesn't show the local
 * car-rental / salon / supermarket prices, but their website does."
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY IT IS NOT "SILENT AND UNDETECTABLE"
 *
 * Ehsan asked for the AI to read sites "بی‌صدا و نامحسوس" (silently, undetectably).
 * His own Public Data Intelligence brief forbids exactly that: "must never evade
 * access controls… never violate website terms intentionally." Doctrine Art.6
 * (lawful data only) says the same. So this reader does the opposite of hiding:
 *
 *   • It IDENTIFIES ITSELF in the User-Agent, with a contact URL.
 *   • It OBEYS robots.txt — if a site disallows a path, we do not fetch it.
 *   • It RATE-LIMITS per host so we are never a burden.
 *   • It reads ONLY public pages — no login, no cookies, no paywall, no token.
 *   • It stores FACTS (a price, an hour) + the source URL, never copyrighted prose.
 *
 * This is what separates a durable data moat from a lawsuit. A crawler that
 * hides gets blocked the day it matters — usually during diligence.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY IT REFUSES MORE THAN IT ACCEPTS
 *
 * The failure mode that destroys trust is not missing data — it is CONFIDENT
 * WRONG data. A wrong price shown as fact is worse than no price. So every
 * extraction carries a confidence score, and anything below the threshold is
 * returned as "unsure" rather than shown as a number. (Doctrine Art.2/Art.12.)
 */

import { json, ok, fail, rateLimit, ipHash, readJson, nowIso, sha256 } from './lib.js';

const UA = 'VezvezakBot/1.0 (+https://vezvezak.com/bot; respects robots.txt)';
const MAX_BYTES = 600_000;          // never ingest more than a page's worth
const FETCH_TIMEOUT_MS = 12_000;
const CONFIDENCE_THRESHOLD = 0.6;   // below this we say "unsure", never a number

/** Minimal robots.txt parser: returns true if `path` is allowed for our UA. */
export function isAllowedByRobots(robotsTxt, path, ua = 'VezvezakBot') {
  if (!robotsTxt) return true;                     // no robots.txt = allowed
  const lines = robotsTxt.split('\n').map(l => l.replace(/#.*$/, '').trim()).filter(Boolean);
  const groups = [];
  let current = null;
  for (const line of lines) {
    const m = line.match(/^([A-Za-z-]+)\s*:\s*(.*)$/);
    if (!m) continue;
    const field = m[1].toLowerCase();
    const value = m[2].trim();
    if (field === 'user-agent') {
      if (!current || current.rules.length) { current = { agents: [], rules: [] }; groups.push(current); }
      current.agents.push(value.toLowerCase());
    } else if (current && (field === 'disallow' || field === 'allow')) {
      current.rules.push({ allow: field === 'allow', path: value });
    }
  }
  // Most specific group wins: our UA beats '*'.
  const mine = groups.find(g => g.agents.some(a => a !== '*' && ua.toLowerCase().includes(a)));
  const star = groups.find(g => g.agents.includes('*'));
  const group = mine || star;
  if (!group) return true;

  let verdict = true, best = -1;
  for (const rule of group.rules) {
    if (rule.path === '') continue;                // "Disallow:" empty = allow all
    if (path.startsWith(rule.path) && rule.path.length > best) {
      best = rule.path.length;
      verdict = rule.allow;
    }
  }
  return verdict;
}

/** Strip a page down to the text an extractor can reason over. */
export function pageToText(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&#\d+;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 12_000);
}

/**
 * Structured data first. Most real businesses already publish machine-readable
 * prices via schema.org JSON-LD — reading that is exact, free, and explicitly
 * meant to be read by machines. We only fall back to the model when it's absent.
 */
export function extractJsonLd(html) {
  const out = [];
  // Offer objects reached via a parent's `offers` are recorded there; remember
  // them so the generic walk below does not collect the SAME published price a
  // second time (a Product inlines its Offer, so every price was appearing
  // twice — once named, once anonymous, which dedupe-by-name could not catch).
  const consumed = new WeakSet();
  for (const m of html.matchAll(/<script[^>]+application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi)) {
    try {
      const parsed = JSON.parse(m[1].trim());
      for (const node of Array.isArray(parsed) ? parsed : [parsed]) collectOffers(node, out, consumed);
    } catch { /* malformed JSON-LD is common; ignore it */ }
  }
  return out;
}

function pushOffer(out, name, o) {
  const price = o?.price ?? o?.lowPrice ?? o?.priceSpecification?.price;
  if (price === undefined || price === null || String(price).trim() === '') return;
  const n = parseFloat(String(price).replace(/[^0-9.]/g, ''));
  if (!Number.isFinite(n) || n <= 0) return;
  out.push({
    name: String(name || o?.name || '').slice(0, 200) || undefined,
    price: n,
    currency: o?.priceCurrency || o?.priceSpecification?.priceCurrency || undefined,
    availability: o?.availability ? String(o.availability).split('/').pop() : undefined,
  });
}

// ── Microdata (itemscope/itemprop) ───────────────────────────────────────────
// Many sites publish schema.org via HTML attributes instead of JSON-LD. This
// pulls itemprop="price"/"name" pairs — still a machine-intended standard, still
// exact, no guessing.
export function extractMicrodata(html) {
  const out = [];
  // Find every itemprop="price" and pair it with the nearest preceding name.
  const priceRe = /itemprop=["']price["'][^>]*?(?:content=["']([\d.,]+)["']|>\s*([^<]*))/gi;
  for (const m of html.matchAll(priceRe)) {
    const raw = (m[1] || m[2] || '').replace(/[^0-9.]/g, '');
    const n = parseFloat(raw);
    if (!Number.isFinite(n) || n <= 0) continue;
    // nearest itemprop="name" in the 2KB before this price
    const before = html.slice(Math.max(0, m.index - 2000), m.index);
    const nameM = [...before.matchAll(/itemprop=["']name["'][^>]*?(?:content=["']([^"']+)["']|>\s*([^<]{1,120}))/gi)].pop();
    const name = nameM ? (nameM[1] || nameM[2] || '').trim() : undefined;
    // Currency can sit just before OR just after the price (both are valid),
    // so look in a window spanning both sides.
    const around = html.slice(Math.max(0, m.index - 400), m.index + 400);
    const curM = around.match(/itemprop=["']priceCurrency["'][^>]*content=["']([A-Z]{3})["']/i);
    out.push({ name: name || undefined, price: n, currency: curM ? curM[1] : undefined });
  }
  return out;
}

// ── Open Graph product meta (og:price:amount) ────────────────────────────────
export function extractOpenGraph(html) {
  const amt = html.match(/<meta[^>]+property=["'](?:og|product):price:amount["'][^>]+content=["']([\d.,]+)["']/i)
    || html.match(/<meta[^>]+content=["']([\d.,]+)["'][^>]+property=["'](?:og|product):price:amount["']/i);
  if (!amt) return [];
  const n = parseFloat(amt[1].replace(/[^0-9.]/g, ''));
  if (!Number.isFinite(n) || n <= 0) return [];
  const cur = html.match(/property=["'](?:og|product):price:currency["'][^>]+content=["']([A-Z]{3})["']/i);
  const title = html.match(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']/i);
  return [{ name: title ? title[1].trim() : undefined, price: n, currency: cur ? cur[1] : undefined }];
}

function collectOffers(node, out, consumed, depth = 0) {
  if (!node || typeof node !== 'object' || depth > 6) return;
  if (Array.isArray(node)) { for (const n of node) collectOffers(n, out, consumed, depth + 1); return; }
  if (consumed.has(node)) return;

  const type = String(node['@type'] || '').toLowerCase();
  const isPriceBearing = type.includes('product') || type.includes('offer') || type.includes('service');

  if (isPriceBearing) {
    if (node.offers) {
      // The parent names the thing; the offer carries the price.
      const list = Array.isArray(node.offers) ? node.offers : [node.offers];
      for (const o of list) {
        if (o && typeof o === 'object') consumed.add(o);
        pushOffer(out, node.name, o);
      }
    } else {
      pushOffer(out, node.name, node);
    }
  }

  for (const k of Object.keys(node)) {
    if (k.startsWith('@')) continue;
    collectOffers(node[k], out, consumed, depth + 1);
  }
}

async function fetchText(url, signal) {
  const res = await fetch(url, { headers: { 'User-Agent': UA, Accept: 'text/html,text/plain,*/*' }, signal, redirect: 'follow' });
  if (!res.ok) return { ok: false, status: res.status };
  const len = parseInt(res.headers.get('content-length') || '0', 10);
  if (len > MAX_BYTES) return { ok: false, status: 413 };
  return { ok: true, text: (await res.text()).slice(0, MAX_BYTES), finalUrl: res.url };
}

/**
 * Read one PUBLIC page and return normalized offers with confidence + provenance.
 *
 * POST /extract { url }
 *  -> { ok, allowed, offers:[{name,price,currency,confidence,method}], source, fetchedAt, unsure? }
 */
export async function extractPublicPage(request, env) {
  const body = await readJson(request);
  if (!body?.url) return fail(400, 'A url is required.');

  let target;
  try { target = new URL(String(body.url)); } catch { return fail(400, 'That is not a valid URL.'); }
  if (!['http:', 'https:'].includes(target.protocol)) return fail(400, 'Only http(s) pages can be read.');
  // Never let this become an SSRF tool against internal networks.
  // Block private / link-local / loopback ranges so this can't be turned into an
  // SSRF tool against internal infrastructure. Covers IPv4 RFC1918 incl. the
  // 172.16/12 block, 0.0.0.0, and IPv6 loopback/ULA.
  const host = target.hostname.replace(/^\[|\]$/g, '');
  const isPrivate =
    /^(localhost|0\.0\.0\.0|127\.|10\.|192\.168\.|169\.254\.|::1|fe80:|f[cd][0-9a-f]{2}:)/i.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host);
  if (isPrivate) return fail(400, 'That address cannot be read.');

  // Be a polite citizen of every host we touch.
  const hostBucket = `extract:${await sha256(target.hostname)}`;
  const rl = await rateLimit(env, hostBucket, 20, 60_000);
  if (!rl.allowed) return fail(429, 'Slow down — we rate-limit how often we read any one site.');
  const userRl = await rateLimit(env, `extractuser:${await ipHash(request, env)}`, 30, 60_000);
  if (!userRl.allowed) return fail(429, 'Too many requests.');

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
  try {
    // 1) robots.txt is a rule, not a suggestion.
    const robots = await fetchText(`${target.origin}/robots.txt`, ac.signal).catch(() => ({ ok: false }));
    if (robots.ok && !isAllowedByRobots(robots.text, target.pathname)) {
      return json(200, {
        ok: true, allowed: false, offers: [], source: target.href, fetchedAt: nowIso(),
        reason: 'robots_disallowed',
        note: 'This site asks not to be read automatically, so Vezvezak does not read it.',
      });
    }

    // 2) Fetch the public page.
    const page = await fetchText(target.href, ac.signal);
    if (!page.ok) return json(200, { ok: true, allowed: true, offers: [], source: target.href, fetchedAt: nowIso(), reason: `http_${page.status}` });

    // 3) Structured data first — exact, published to be machine-read, no guessing.
    //    Try every open standard a cooperative site might use, in order of fidelity:
    //    JSON-LD → Microdata → Open Graph product meta.
    const structured =
      extractJsonLd(page.text).map(o => ({ ...o, method: 'schema.org/json-ld' }));
    if (!structured.length) structured.push(...extractMicrodata(page.text).map(o => ({ ...o, method: 'schema.org/microdata' })));
    if (!structured.length) structured.push(...extractOpenGraph(page.text).map(o => ({ ...o, method: 'opengraph' })));

    if (structured.length) {
      // Dedupe across formats (a page can carry the same price in two of them).
      const seen = new Set();
      const offers = structured.filter(o => {
        const k = `${(o.name || '').toLowerCase()}|${o.price}|${o.currency || ''}`;
        if (seen.has(k)) return false; seen.add(k); return true;
      });
      return json(200, {
        ok: true, allowed: true, source: page.finalUrl || target.href, fetchedAt: nowIso(),
        offers: offers.slice(0, 25).map(o => ({ ...o, confidence: 0.92 })),
      });
    }

    // 4) Semantic fallback — layouts differ, so we ask the model to read the
    //    visible text. It is instructed to return NOTHING rather than guess.
    if (!env.AI) {
      return json(200, { ok: true, allowed: true, offers: [], source: target.href, fetchedAt: nowIso(), reason: 'no_structured_data', unsure: true });
    }
    const text = pageToText(page.text);
    const r = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
      messages: [
        {
          role: 'system',
          content:
            'You extract published prices from the visible text of a business web page. ' +
            'Return ONLY compact JSON: {"offers":[{"name":"...","price":0,"currency":"USD","confidence":0.0}]}. ' +
            'confidence is YOUR certainty 0-1 that this is a real, current, published price for that named item. ' +
            'If the page shows no clear price, return {"offers":[]}. ' +
            'NEVER invent, estimate, average or infer a price. It is correct and expected to return an empty list. ' +
            'A wrong price is far worse than no price.',
        },
        { role: 'user', content: text },
      ],
      max_tokens: 700,
    });

    let offers = [];
    try {
      const m = String(r?.response || '').match(/\{[\s\S]*\}/);
      const parsed = m ? JSON.parse(m[0]) : { offers: [] };
      offers = (parsed.offers || [])
        .filter(o => Number.isFinite(Number(o.price)) && Number(o.price) > 0)
        .map(o => ({
          name: String(o.name || '').slice(0, 200) || undefined,
          price: Number(o.price),
          currency: o.currency || undefined,
          confidence: Math.max(0, Math.min(1, Number(o.confidence) || 0)),
          method: 'ai',
        }))
        // The whole point: refuse rather than mislead.
        .filter(o => o.confidence >= CONFIDENCE_THRESHOLD)
        .slice(0, 25);
    } catch { offers = []; }

    return json(200, {
      ok: true, allowed: true, source: page.finalUrl || target.href, fetchedAt: nowIso(),
      offers,
      unsure: offers.length === 0,
    });
  } catch (err) {
    return json(200, { ok: true, allowed: true, offers: [], source: target.href, fetchedAt: nowIso(), reason: 'fetch_failed', unsure: true });
  } finally {
    clearTimeout(timer);
  }
}
