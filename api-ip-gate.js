// api/ip-gate.js
// Place this file at /api/ip-gate.js in your repo root (Vercel auto-detects
// anything under /api as a serverless function — no framework needed).
//
// Requires the FIREBASE_SERVICE_ACCOUNT environment variable in Vercel
// (Project Settings → Environment Variables, see setup steps).
//
// admin.html and ScBSSVis.html call this at the very start of their script,
// before rendering anything sensitive. It:
//   1. Reads the visitor's IP from Vercel's request headers.
//   2. Checks /bannedIPs in Firebase RTDB.
//   3. Logs the IP + path + timestamp to /ipLog.
//   4. Returns { allowed: true/false, ip } as JSON.

export const config = { runtime: 'edge' };

let banCache = { list: null, fetchedAt: 0 };
const CACHE_TTL_MS = 30000;

async function getAccessToken(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: serviceAccount.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.database',
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

export default async function handler(request) {
  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'unknown';

  const url = new URL(request.url);
  const path = url.searchParams.get('path') || 'unknown';
  const dbUrl = 'https://bytestorm-friebase-server-default-rtdb.europe-west1.firebasedatabase.app';

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || '{}');
  } catch {
    return new Response(JSON.stringify({ allowed: true, ip, note: 'config missing, failing open' }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }
  if (!serviceAccount.private_key) {
    return new Response(JSON.stringify({ allowed: true, ip, note: 'config missing, failing open' }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const token = await getAccessToken(serviceAccount);
  if (!token) {
    return new Response(JSON.stringify({ allowed: true, ip, note: 'auth failed, failing open' }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (!banCache.list || Date.now() - banCache.fetchedAt > CACHE_TTL_MS) {
    try {
      const res = await fetch(`${dbUrl}/bannedIPs.json`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      banCache = { list: res.ok ? await res.json() : {}, fetchedAt: Date.now() };
    } catch {
      banCache = { list: {}, fetchedAt: Date.now() };
    }
  }

  const ipKey = ip.replace(/\./g, '_');
  const isBanned = !!(banCache.list && banCache.list[ipKey]);

  fetch(`${dbUrl}/ipLog/${ipKey}.json`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, lastPath: path, lastSeen: Date.now() }),
  }).catch(() => {});

  return new Response(JSON.stringify({ allowed: !isBanned, ip }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
