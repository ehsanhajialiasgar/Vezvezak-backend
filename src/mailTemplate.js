// THE EMAIL A PERSON ACTUALLY RECEIVES (Ehsan 2026-09-22).
//
// It was one line of plain text — "Your Vezvezak code is 123456" — from a name nobody had heard of, which is the
// shape of a phishing message and the shape of a message a mail client is happy to file under junk. It now looks
// like it comes from a company, while asserting nothing that is not true.
//
// THE CONSTRAINTS, all deliberate:
//   · NO IMAGES. Not a logo, not a spacer, not a pixel — no third-party host is contacted when this is opened, so
//     opening it tells us and tells nobody else anything. The wordmark is text in the brand colour.
//   · NO LINKS AND NO TRACKING. There is no click to measure and no open to measure. A code is typed, not clicked,
//     which also means there is no link in here for anyone to imitate.
//   · A PLAIN-TEXT ALTERNATIVE with the same words, so a text-only client loses nothing.
//   · The code is large, monospaced and on its own line, so it survives a double-tap and a screenshot.
//   · Inline styles only: every mail client strips <style> blocks, and half of them strip <head> entirely.
//   · Dark mode is left to the client. A hard-coded dark palette is inverted a second time by some clients and
//     comes out unreadable; a light card with real contrast renders correctly everywhere.
const BRAND = '#1AA29B';          // vzBrand — the same value tokens.ts holds for the app and the icon
const INK = '#14201F';
const DIM = '#5A6B69';
const RULE = '#E3E9E8';
const PAPER = '#FFFFFF';
const BACKDROP = '#F4F7F6';

export const SUPPORT_EMAIL = 'support@vezvezak.com';
export const COMPANY_LINE = 'Vezvezak LLC, San Jose, California';

// What the code is FOR, in the person's words, not ours. An unexpected code has to be safe to ignore, and the
// message has to say so — that sentence is the whole difference between a security email and a phishing email.
const PURPOSE = {
  reset: {
    subject: 'Your Vezvezak password reset code',
    heading: 'Reset your password',
    lead: 'Enter this code in the Vezvezak app to choose a new password.',
  },
  signup: {
    subject: 'Your Vezvezak verification code',
    heading: 'Confirm your email',
    lead: 'Enter this code in the Vezvezak app to finish creating your account.',
  },
  signin: {
    subject: 'Your Vezvezak sign-in code',
    heading: 'Sign in to Vezvezak',
    lead: 'Enter this code in the Vezvezak app to sign in.',
  },
};

export function purposeCopy(purpose) {
  return PURPOSE[purpose] || PURPOSE.signin;
}

const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

export function codeEmail(code, purpose, minutes = 10) {
  const { subject, heading, lead } = purposeCopy(purpose);
  const c = esc(code);
  const expiry = `This code expires in ${minutes} minutes.`;
  const ignore = 'If you did not ask for it, you can ignore this email — nothing changes until the code is used.';

  const text = [
    'VEZVEZAK',
    '',
    heading,
    lead,
    '',
    c,
    '',
    expiry,
    ignore,
    '',
    `Questions: ${SUPPORT_EMAIL}`,
    COMPANY_LINE,
    '',
    'We never ask for your password by email.',
  ].join('\n');

  // Tables, not flexbox: Outlook renders neither grid nor flex, and this has to survive every client, not most.
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${esc(subject)}</title></head>
<body style="margin:0;padding:0;background:${BACKDROP};">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:${BACKDROP};padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:480px;background:${PAPER};border:1px solid ${RULE};border-radius:14px;">
  <tr><td style="padding:28px 28px 0 28px;">
    <div style="font:700 19px/1.2 -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;letter-spacing:.14em;color:${BRAND};">VEZVEZAK</div>
  </td></tr>
  <tr><td style="padding:18px 28px 0 28px;">
    <div style="font:700 21px/1.3 -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:${INK};">${esc(heading)}</div>
    <div style="font:400 15px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:${DIM};padding-top:8px;">${esc(lead)}</div>
  </td></tr>
  <tr><td style="padding:20px 28px 0 28px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:${BACKDROP};border:1px solid ${RULE};border-radius:10px;">
      <tr><td align="center" style="padding:18px 12px;">
        <div style="font:700 34px/1.1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.22em;color:${INK};">${c}</div>
      </td></tr>
    </table>
    <div style="font:400 13px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:${DIM};padding-top:10px;">${esc(expiry)}</div>
  </td></tr>
  <tr><td style="padding:14px 28px 0 28px;">
    <div style="font:400 13px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:${DIM};">${esc(ignore)}</div>
  </td></tr>
  <tr><td style="padding:20px 28px 26px 28px;">
    <div style="border-top:1px solid ${RULE};padding-top:14px;font:400 12px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:${DIM};">
      Questions? Write to ${esc(SUPPORT_EMAIL)}.<br>
      We never ask for your password by email.<br>
      ${esc(COMPANY_LINE)}
    </div>
  </td></tr>
</table>
</td></tr>
</table>
</body></html>`;

  return { subject, html, text };
}
