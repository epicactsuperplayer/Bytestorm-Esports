// api/ip-gate.js
// Place this file at /api/ip-gate.js in your repo root (Vercel auto-detects
// anything under /api as a serverless function — no framework needed).
//
// Requires the FIREBASE_SERVICE_ACCOUNT environment variable in Vercel
// (Project Settings → Environment Variables, see setup steps).
//
// Optional: PROXYCHECK_API_KEY environment variable. Without it, VPN/proxy
// detection still works via proxycheck.io's free unauthenticated tier
// (lower daily query limit). Register a free key at proxycheck.io to raise it.
//
// admin.html and ScBSSVis.html call this at the very start of their script,
// before rendering anything sensitive. It:
//   1. Reads the visitor's IP, device, browser, and country from request headers.
//   2. Checks that IP against proxycheck.io for VPN/proxy/hosting usage.
//   3. Checks /bannedIPs in Firebase RTDB.
//   4. Logs IP + path + device + browser + country + VPN status + timestamp to /ipLog.
//   5. Returns { allowed: true/false, ip } as JSON.

export const config = { runtime: 'edge' };

let banCache = { list: null, fetchedAt: 0 };
const CACHE_TTL_MS = 30000;

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

// ── Device + Browser parsing from User-Agent ──
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

// ── VPN / proxy / hosting check via proxycheck.io ──
async function checkVpn(ip) {
  if (!ip || ip === 'unknown') return 'unknown';
  try {
    const key = process.env.PROXYCHECK_API_KEY;
    const url = `https://proxycheck.io/v2/${ip}?vpn=1&asn=1${key ? `&key=${key}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) return 'unknown';
    const data = await res.json();
    const entry = data && data[ip];
    if (!entry) return 'unknown';
    return entry.proxy === 'yes' ? (entry.type || 'VPN/Proxy') : 'clean';
  } catch {
    return 'unknown';
  }
}

export default async function handler(request) {
  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'unknown';

  const ua = request.headers.get('user-agent') || '';
  const country = request.headers.get('x-vercel-ip-country') || 'unknown';
  const { device, browser, os } = parseUA(ua);

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

  // VPN check runs in parallel with nothing blocking the response beyond this await,
  // since we need the result to store it, but it's a single fast external call.
  const vpn = await checkVpn(ip);

  let writeDebug = null;
  try {
    const writeRes = await fetch(`${dbUrl}/ipLog/${ipKey}.json`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ip,
        lastPath: path,
        lastSeen: Date.now(),
        device,
        browser,
        os,
        country,
        vpn,
      }),
    });
    const writeBody = await writeRes.text();
    writeDebug = { status: writeRes.status, body: writeBody };
  } catch (e) {
    writeDebug = { error: String(e) };
  }

  const debug = url.searchParams.get('debug') === '1';
  return new Response(JSON.stringify({
    allowed: !isBanned,
    ip,
    ...(debug ? { writeDebug, dbUrl, ipKey } : {}),
  }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
