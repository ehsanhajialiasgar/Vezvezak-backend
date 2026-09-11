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

import { json, fail, rateLimit, readJson, nowIso, sha256, requireAuth, planFor } from './lib.js';
import { billableAiAllowed } from './usage.js';

const UA = 'VezvezakBot/1.0 (+https://vezvezak.com/bot; respects robots.txt)';
const MAX_BYTES = 600_000;          // never ingest more than a page's worth
const FETCH_TIMEOUT_MS = 12_000;
const CONFIDENCE_THRESHOLD = 0.6;   // below this we say "unsure", never a number

// ── SSRF / cost hardening (Ehsan 2026-08-11) ─────────────────────────────────
const ALLOWED_PORTS = new Set(['', '80', '443']);   // no internal port scanning
const MAX_REDIRECTS = 3;             // follow at most 3 hops, re-validated each time
const GLOBAL_PER_MIN = 120;          // global rate cap, INDEPENDENT of per-user/per-IP
// Global daily ceiling on the BILLABLE Llama fallback. Derivation: the semantic
// fallback is the only cost driver — one @cf/meta/llama-3.3-70b call (~≤2k input +
// ≤700 output tokens). At Cloudflare Workers-AI list pricing that is on the order of
// ~$0.002–0.005 per call, so 500/day bounds worst-case spend to ~$1–2.5/day
// (~$30–75/mo) even under sustained abuse, with headroom for the (currently zero)
// legitimate demand. When the ceiling is hit we return `unavailable` and NEVER
// reach inference.
//
// ⚠️ CAVEAT (Ehsan 2026-08-11): the ~$0.002–0.005/call figure is CLOUDFLARE LIST
// PRICE, computed from token counts — it was NEVER verified against a real invoice.
// When we have an actual Workers-AI bill, re-derive this ceiling from measured cost
// per call and update this constant. $30–75/mo worst case is accepted as-is for now.
const AI_DAILY_CEILING = 500;

// CALL-HISTORY NOTE (Ehsan 2026-08-11): whether /extract was ever hit at volume
// cannot be reconstructed. The D1 `rate_limits` table is a FLOOR, not a history — it
// keeps only the current fixed window per bucket and overwrites older counts. The
// invocation logs that WOULD have been complete were captured while Workers
// observability was on (~2026-07-17 → 2026-08-11) but that retention window has since
// expired. A snapshot on 2026-08-11 showed 9 `extract*` buckets (count=1 each,
// clustered ~2026-07-17), consistent with development self-testing, with no sign of
// external abuse — but that is a lower bound, not proof of the total.

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

// Parse an octet/number in decimal, hex (0x..) or octal (0..) — the encodings an
// attacker uses to smuggle 127.0.0.1 past a string check (2130706433, 0x7f000001…).
function parseIntFlexible(s) {
  if (/^0x[0-9a-f]+$/i.test(s)) return parseInt(s, 16);
  if (/^0[0-7]+$/.test(s)) return parseInt(s, 8);
  if (/^\d+$/.test(s)) return parseInt(s, 10);
  return null;
}
// If `host` is an IPv4 literal in ANY encoding, return its 32-bit int; else null.
function ipv4ToInt(host) {
  const parts = host.split('.');
  if (parts.length === 1) {
    const n = parseIntFlexible(host);
    return n !== null && n >= 0 && n <= 0xffffffff ? n >>> 0 : null;
  }
  if (parts.length !== 4) return null;
  let int = 0;
  for (const p of parts) {
    const n = parseIntFlexible(p);
    if (n === null || n < 0 || n > 255) return null;
    int = ((int << 8) | n) >>> 0;
  }
  return int >>> 0;
}
// Why this target must NOT be fetched, or null if it's allowed. Enforced on the
// initial URL AND on every redirect Location — checked NUMERICALLY on the resolved
// integer so decimal/hex/octal encodings can't smuggle an internal address past a
// string match. Scheme http(s) only; ports 80/443 only.
export function blockedReason(u) {
  if (!['http:', 'https:'].includes(u.protocol)) return 'scheme';
  if (!ALLOWED_PORTS.has(u.port)) return 'port';
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost')) return 'internal';
  if (host.includes(':')) {                              // IPv6 literal
    if (/^(::1|::|f[cd][0-9a-f]{2}:|fe80:|0*:)/i.test(host)) return 'internal';
    return null;                                         // other global IPv6 — allowed
  }
  const int = ipv4ToInt(host);
  if (int !== null) {                                    // IPv4 literal (any encoding)
    const a = (int >>> 24) & 255, b = (int >>> 16) & 255;
    if (a === 0 || a === 10 || a === 127) return 'internal';        // this-host / private / loopback
    if (a === 169 && b === 254) return 'internal';                  // link-local incl. 169.254.169.254
    if (a === 172 && b >= 16 && b <= 31) return 'internal';         // 172.16/12
    if (a === 192 && b === 168) return 'internal';                  // 192.168/16
    if (a === 100 && b >= 64 && b <= 127) return 'internal';        // CGNAT 100.64/10
    return null;
  }
  // A hostname (not an IP literal): block the obvious private spellings.
  //
  // ⚠️ KNOWN LIMITATION — DNS REBINDING (accepted, Ehsan 2026-08-11): a real name
  // that RESOLVES to an internal IP cannot be caught here. Mitigating it requires
  // resolving the host ourselves, PINNING that IP, and fetching that exact IP — and
  // the Cloudflare Workers runtime exposes NO API to resolve a name or pin a
  // connection to an IP (fetch() resolves internally). Accepted because on Workers
  // internal/loopback/metadata addresses are not reachable as they are from a cloud
  // VM, and this endpoint is now authenticated.
  // ‼️ IF THIS CODE EVER MOVES TO NODE / A VM / A CONTAINER: DNS rebinding becomes a
  // real, exploitable SSRF. Before any such migration you MUST add resolve-then-pin
  // (look up the host, reject if the resolved IP is private/link-local, then fetch
  // that pinned IP with the Host header preserved). Do not port this file as-is.
  if (/^(0\.0\.0\.0|127\.|10\.|192\.168\.|169\.254\.)/.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host)) return 'internal';
  return null;
}

// ── THE ROUTE AND ITS PLUMBING WERE DELETED 2026-09-11 (7.5, dead-code gate) ────────────────
// `extractPublicPage` was a SPEND-CAPABLE function (env.AI.run) that HAD a caller — the route
// dispatch in index.js — and that NO USER PATH REACHED: /extract had zero client references in
// the whole app. That is the exact shape 7.5 exists to forbid, and a caller-count rule would have
// been green on it. Deleting it lets the dead-code gate ship with an EMPTY exemption registry,
// which is strictly stronger than a registry with one entry and a mechanism nobody exercises.
//
// WHAT STAYED, and why: everything above this line. The parsers and BOTH guards
// (isAllowedByRobots, blockedReason) are tested and are the substance of ledger 3.1 Part 3 — the
// merchant extract bridge. Deleting a working, tested guard because its caller went is the
// opposite error, so they stay.
//
// WHAT WENT WITH IT: `fetchWithGuard`, an UNTESTED 20-line wrapper whose only two callers were
// inside the handler. Its one non-obvious property is recorded in the ledger rather than kept as
// dead code: it followed redirects MANUALLY and re-ran blockedReason on EVERY hop, so a public URL
// could not 302 onto an internal address. blockedReason — the hard half, the IP/CIDR logic — is
// still here and still tested; the per-hop re-check is a three-line requirement the bridge must
// re-implement deliberately, not a subtlety anyone has to rediscover.
