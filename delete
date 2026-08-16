// api/monitor-log.js
// Place this file at /api/monitor-log.js in your repo root.
//
// Requires the FIREBASE_SERVICE_ACCOUNT environment variable in Vercel
// (same one used by /api/ip-gate.js).
//
// ScBSSVis.html calls this to log:
//   1. Page visits (before sign-in) — IP, device, browser, OS, country.
//   2. Login attempts — email entered, success/failure, and Firebase's
//      error code on failure (e.g. "auth/wrong-password").
//
// IMPORTANT: this endpoint deliberately never accepts or stores a password
// field, even for failed attempts. Storing entered passwords — even wrong
// ones, even in a private database — creates real risk if that data is
// ever leaked or misused, since people commonly reuse passwords across
// sites. Do not add password logging to this file.

export const config = { runtime: 'edge' };

async function getAccessToken(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: serviceAccount.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now,
  };

  const enc = (obj) => btoa(JSON.stringify(obj)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const unsigned = `${enc(header)}.${enc(claim)}`;

  const keyData = serviceAccount.private_key
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');
  const binaryKey = Uint8Array.from(atob(keyData), (c) => c.charCodeAt(0));

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8', binaryKey, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', cryptoKey, new TextEncoder().encode(unsigned)
  );
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');

  const jwt = `${unsigned}.${sigB64}`;
  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });
  if (!tokenRes.ok) return null;
  const tokenData = await tokenRes.json();
  return tokenData.access_token || null;
}

function parseUA(ua) {
  ua = ua || '';

  let device = 'Desktop';
  if (/iPad|Tablet(?!.*Mobile)/i.test(ua)) device = 'Tablet';
  else if (/Mobi|Android|iPhone/i.test(ua)) device = 'Mobile';

  let browser = 'Unknown';
  if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/OPR\/|Opera/i.test(ua)) browser = 'Opera';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';
  else if (/CriOS\//i.test(ua)) browser = 'Chrome (iOS)';
  else if (/Chrome\//i.test(ua)) browser = 'Chrome';
  else if (/Safari\//i.test(ua) && !/Chrome/i.test(ua)) browser = 'Safari';

  let os = 'Unknown';
  if (/Windows/i.test(ua)) os = 'Windows';
  else if (/Mac OS X/i.test(ua) && !/iPhone|iPad/i.test(ua)) os = 'macOS';
  else if (/Android/i.test(ua)) os = 'Android';
  else if (/iPhone|iPad|iOS/i.test(ua)) os = 'iOS';
  else if (/Linux/i.test(ua)) os = 'Linux';

  return { device, browser, os };
}

export default async function handler(request) {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ ok: false, error: 'method not allowed' }), { status: 405 });
  }

  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'unknown';
  const ua = request.headers.get('user-agent') || '';
  const country = request.headers.get('x-vercel-ip-country') || 'unknown';
  const { device, browser, os } = parseUA(ua);

  let body = {};
  try { body = await request.json(); } catch { /* ignore malformed body */ }

  // Only these two event types are accepted. Note there is no branch,
  // anywhere in this file, that reads or forwards a password field.
  const event = body.event === 'login_attempt' ? 'login_attempt' : 'visit';
  const email = typeof body.email === 'string' ? body.email.slice(0, 200) : 'unknown';
  const success = body.success === true;
  const errorCode = typeof body.errorCode === 'string' ? body.errorCode.slice(0, 100) : null;

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || '{}');
  } catch {
    return new Response(JSON.stringify({ ok: false, note: 'config missing' }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }
  if (!serviceAccount.private_key) {
    return new Response(JSON.stringify({ ok: false, note: 'config missing' }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const token = await getAccessToken(serviceAccount);
  if (!token) {
    return new Response(JSON.stringify({ ok: false, note: 'auth failed' }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const dbUrl = 'https://bytestorm-friebase-server-default-rtdb.europe-west1.firebasedatabase.app';

  const entry = {
    event,
    ip,
    device,
    browser,
    os,
    country,
    timestamp: Date.now(),
  };
  if (event === 'login_attempt') {
    entry.email = email;
    entry.success = success;
    if (!success && errorCode) entry.errorCode = errorCode;
  }

  try {
    await fetch(`${dbUrl}/monitorLog.json`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(entry),
    });
  } catch {
    // don't block the client on a logging failure
  }

  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
