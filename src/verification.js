// WHO HAS TO CONFIRM THEIR EMAIL ADDRESS, AND WHO WAS NEVER ASKED (Ehsan 2026-09-22).
//
// Email verification at sign-up is on from today. It was off for one reason, written down at the time: blocking
// sign-up on a code would have locked every new user out while RESEND_API_KEY did not exist. It exists now, so
// the reason expired and the decision was reversed.
//
// THE ACCOUNTS THAT ALREADY EXIST WERE NEVER ASKED. Every one of the nine rows in production is verified = 0,
// including the founder's own, because otpVerify — the only writer of that column — was unreachable from the
// app. Turning the requirement on without this rule would lock out every existing account, which is the
// opposite of a security improvement: it punishes people for a door we never opened.
//
// The cutoff is a fact about OUR history, not about any user: accounts created before verification was asked
// for are grandfathered, permanently. It is a timestamp rather than a hand-kept list of addresses so that
// nothing has to be remembered when another old account turns up.
// The value is in the PAST, deliberately. A cutoff in the future grandfathers every account created before it
// arrives — including the ones made to prove the gate works, which would then sign in freely and show the
// opposite of what was being proved. It sits after the newest row that existed when the decision was taken
// (shiva@vez.test, 2026-09-22T09:59:23Z) and before the change shipped.
export const VERIFY_REQUIRED_FROM = '2026-09-22T12:00:00.000Z';

// THREE answers, not two. 'unknown' exists because a row we could not read must never be treated as verified —
// nor as a lockout, which is the caller's decision to make with the rest of what it knows.
export function verificationState(user, requiredFrom = VERIFY_REQUIRED_FROM) {
  if (!user) return 'unknown';
  if (user.verified === 1 || user.verified === true) return 'verified';
  const created = typeof user.created_at === 'string' ? user.created_at : '';
  if (!created) return 'unknown';               // no date to judge by — do not guess in either direction
  return created < requiredFrom ? 'grandfathered' : 'unverified';
}

// May this account be used? Grandfathered accounts may: they were never asked.
export function mayUseAccount(user, requiredFrom = VERIFY_REQUIRED_FROM) {
  const s = verificationState(user, requiredFrom);
  return s === 'verified' || s === 'grandfathered';
}

// HOW LONG TO WAIT, in the words a person uses. rateLimit() has always returned retryAfterMs and no caller had
// ever read it, so every ceiling said "Please wait an hour" whether the wait was fifty-nine minutes or four.
export function waitPhrase(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return 'a moment';
  const mins = Math.ceil(ms / 60000);
  if (mins <= 1) return 'a minute';
  if (mins < 60) return `${mins} minutes`;
  const hours = Math.round(mins / 60);
  return hours <= 1 ? 'an hour' : `${hours} hours`;
}
