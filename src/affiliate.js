// Pure helpers for commission attribution — no I/O, so they're unit-testable.
//
// Money-safety (Doctrine Art.4): these only NORMALIZE and RECORD what a network
// reports. Vezvezak never computes a charge, never moves funds. The amount /
// commission are informational; settlement happens inside the affiliate network.

import { timingSafeEqual } from './lib.js';

const CONFIRMED = new Set(['confirmed', 'approved', 'sale', 'paid', 'closed', 'valid', 'completed']);
const REJECTED = new Set(['rejected', 'reversed', 'cancelled', 'canceled', 'invalid', 'void', 'returned']);

// Map a network's free-form status to our three states. Unknown → 'pending'
// (conservative: never bank an unrecognized event as confirmed money).
export function normalizeStatus(raw) {
  const s = String(raw || '').trim().toLowerCase();
  if (CONFIRMED.has(s)) return 'confirmed';
  if (REJECTED.has(s)) return 'rejected';
  return 'pending';
}

function num(v) {
  if (v === undefined || v === null || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function str(v, max) {
  const s = String(v ?? '').trim();
  return s ? s.slice(0, max) : '';
}

// Validate + normalize a conversion payload gathered from query params and/or a
// JSON body. Returns { ok, value } or { ok:false, error }.
export function normalizeConversion(input) {
  const network = str(input.network, 40).toLowerCase();
  const orderId = str(input.orderId ?? input.order_id ?? input.oid, 120);
  if (!network) return { ok: false, error: 'network required' };
  if (!orderId) return { ok: false, error: 'orderId required' };

  return {
    ok: true,
    value: {
      network,
      orderId,
      clickId: str(input.clickId ?? input.subid ?? input.sub_id ?? input.click_id, 120) || null,
      amount: num(input.amount ?? input.sale_amount ?? input.total),
      commission: num(input.commission ?? input.payout ?? input.comm),
      currency: (str(input.currency ?? input.cur, 8) || '').toUpperCase() || null,
      status: normalizeStatus(input.status ?? input.event ?? input.state),
    },
  };
}

// Authenticate a postback by shared secret. FAILS CLOSED: an unconfigured
// secret rejects everything, so a money event is never accepted unauthenticated.
export function verifyPostbackSecret(provided, configured) {
  if (!configured) return false;            // not configured => reject all
  if (!provided) return false;
  return timingSafeEqual(String(provided), String(configured));
}
