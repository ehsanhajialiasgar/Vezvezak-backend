// WHY AN EMAIL DID NOT ARRIVE — the part that used to be thrown away (Ehsan 2026-09-22).
//
// `/auth/otp/request` answered every provider failure with one sentence, "Could not send the code. Please try
// again later.", and discarded Resend's response. So when the founder asked for a password reset and nothing
// came, there was nothing anywhere — no log, no code, no message — that said why. Request logging is off in
// production by design, so the response IS the only channel; it has to carry a reason.
//
// MEASURED, not assumed (2026-09-22, real requests to https://api.resend.com/emails):
//   no key / bad key → HTTP 401 {"statusCode":401,"name":"validation_error","message":"API key is invalid"}
// The remaining statuses are mapped from Resend's documented codes and are left deliberately coarse: this maps
// the STATUS, which is stable, and carries Resend's own `name` back only as a machine-readable detail. The
// provider's prose is never shown to a person — it is written for a developer, not for someone locked out.
export const MAIL_FAIL = {
  notConfigured: 'notConfigured',       // no API key on this Worker — waiting cannot fix it
  providerRejected: 'providerRejected', // the key or the sending domain is wrong — ours to fix, not the user's
  recipientRefused: 'recipientRefused', // the address itself was refused
  rateLimited: 'rateLimited',           // too many sends right now
  unreachable: 'unreachable',           // the request never got an answer
};

// What a PERSON is told. Each sentence names something they can actually do, or says plainly that the problem is
// ours — never "please try again later" for a fault that no amount of later will change.
export const MAIL_MESSAGE = {
  notConfigured: 'We cannot send email codes yet, so this cannot be your way in right now. Sign in with your password instead.',
  providerRejected: 'Our email is misconfigured on our side, so the code could not be sent. This is not something you can fix — sign in with your password instead.',
  recipientRefused: 'That address was refused by our email provider. Check it for a typo, or use another address.',
  rateLimited: 'Too many codes have been sent just now. Wait a minute and ask again.',
  unreachable: 'We could not reach our email provider. Try again in a minute.',
};

export function classifyMailStatus(status) {
  if (status === 401 || status === 403) return MAIL_FAIL.providerRejected;   // bad key, or a domain Resend has not verified
  if (status === 422 || status === 400) return MAIL_FAIL.recipientRefused;   // the payload Resend would not accept
  if (status === 429) return MAIL_FAIL.rateLimited;
  return MAIL_FAIL.providerRejected;                                         // 5xx from the provider is still not the user's fault
}

// One place that turns a Resend answer into our answer. `body` is whatever came back, parsed or not.
export function mailFailure(reason, detail) {
  return { ok: false, reason, error: MAIL_MESSAGE[reason], detail: detail || undefined };
}
