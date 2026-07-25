/**
 * Voice Studio — Cloudflare Worker (all-in-one)
 * -------------------------------------------------------------------------
 * This single Worker serves BOTH pages and ALL backend logic:
 *   GET  /          -> the user-facing Voice Studio page
 *   GET  /admin     -> the admin approval panel
 *   ...  /auth/telegram, /me, /generate, /plans, /submit-payment,
 *        /admin/orders, /admin/approve, /admin/reject  -> API routes
 *
 * Nothing is hosted on Blogger anymore, so there is no cross-origin call
 * and no risk of Blogger mangling quotes in your JavaScript. Just open
 * your Worker's own URL.
 *
 * This Worker is the ONLY place that knows:
 *   - your RunPod API key
 *   - your RunPod endpoint id
 *   - your Firebase service account (Firestore admin access)
 *   - your admin password
 *   - your Telegram bot token
 * None of these ever reach the browser.
 *
 * Required secrets (Cloudflare dashboard -> Worker -> Settings ->
 * Variables and Secrets -> Add variable -> type "Secret"):
 *   RUNPOD_API_KEY
 *   RUNPOD_ENDPOINT_ID
 *   TELEGRAM_BOT_TOKEN
 *   TELEGRAM_BOT_USERNAME         -> your bot's username, no @ (e.g. voicestudio_login_bot)
 *   ADMIN_SECRET                  -> any password you choose, for /admin
 *   SESSION_SECRET                -> any random long string, signs login sessions
 *   FIREBASE_PROJECT_ID
 *   FIREBASE_CLIENT_EMAIL         -> from your service account JSON
 *   FIREBASE_PRIVATE_KEY          -> from your service account JSON (keep the \n's)
 *
 * Also: in @BotFather, run /setdomain and give it this Worker's own
 * domain (e.g. ads.yoursubdomain.workers.dev) — Telegram Login only
 * works on a domain registered this way.
 */
const PLANS = [
  { id: 'plan_1000', name: '1,000 Tokens', tokens: 1000, price_mmk: 5000 },
  { id: 'plan_5000', name: '5,000 Tokens', tokens: 5000, price_mmk: 20000 },
  { id: 'plan_20000', name: '20,000 Tokens', tokens: 20000, price_mmk: 65000 },
];

const FREE_TOKENS_ON_SIGNUP = 500;
// Cost model: 1 token per character of the text being spoken.
// (Reference audio for voice cloning does not cost extra.)
function tokenCostFor(text) {
  return text.length;
}

// Fill in your real KBZPay / WavePay number + name here — shown to users
// in the "Buy tokens" screen.
const PAYMENT_INSTRUCTIONS_HTML =
  'Transfer to <b>KBZPay / Wave Pay: 09XXXXXXXXX (Your Name)</b>';

const ALLOWED_ORIGIN = '*'; // same-origin now, but harmless to keep for API flexibility

// ===========================================================================
// Router
// ===========================================================================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return withCors(new Response(null, { status: 204 }));
    }

    try {
      // ---- Pages ----
      if (url.pathname === '/' && request.method === 'GET') {
        return htmlResponse(renderUserPage(env));
      }
      if ((url.pathname === '/admin' || url.pathname === '/admin/') && request.method === 'GET') {
        return htmlResponse(HTML_ADMIN);
      }

      // ---- API ----
      if (url.pathname === '/auth/telegram' && request.method === 'POST') {
        return withCors(await handleTelegramAuth(request, env));
      }
      if (url.pathname === '/me' && request.method === 'GET') {
        return withCors(await handleMe(request, env));
      }
      if (url.pathname === '/generate' && request.method === 'POST') {
        return withCors(await handleGenerate(request, env));
      }
      if (url.pathname === '/plans' && request.method === 'GET') {
        return withCors(jsonResponse({ plans: PLANS, payment_instructions: PAYMENT_INSTRUCTIONS_HTML }));
      }
      if (url.pathname === '/submit-payment' && request.method === 'POST') {
        return withCors(await handleSubmitPayment(request, env));
      }
      if (url.pathname === '/admin/orders' && request.method === 'GET') {
        return withCors(await handleAdminListOrders(request, env));
      }
      if (url.pathname === '/admin/approve' && request.method === 'POST') {
        return withCors(await handleAdminApprove(request, env));
      }
      if (url.pathname === '/admin/reject' && request.method === 'POST') {
        return withCors(await handleAdminReject(request, env));
      }

      return withCors(jsonResponse({ error: 'Not found' }, 404));
    } catch (err) {
      console.error(err);
      const status = err.status || 500;
      return withCors(jsonResponse({ error: err.message || 'Internal error' }, status));
    }
  },
};

function withCors(res) {
  const headers = new Headers(res.headers);
  headers.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Secret');
  return new Response(res.body, { status: res.status, headers });
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function htmlResponse(html) {
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
}

// ===========================================================================
// Telegram Login verification
// https://core.telegram.org/widgets/login#checking-authorization
// ===========================================================================
async function handleTelegramAuth(request, env) {
  const data = await request.json();
  const { hash, ...fields } = data;
  if (!hash || !fields.id) return jsonResponse({ error: 'Invalid Telegram payload' }, 400);

  const authDate = Number(fields.auth_date || 0);
  if (!authDate || Date.now() / 1000 - authDate > 86400) {
    return jsonResponse({ error: 'Telegram login expired, please try again.' }, 401);
  }

  const dataCheckString = Object.keys(fields)
    .sort()
    .map((k) => `${k}=${fields[k]}`)
    .join('\n');

  const secretKey = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(env.TELEGRAM_BOT_TOKEN));
  const hmacKey = await crypto.subtle.importKey(
    'raw', secretKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(dataCheckString));
  const computedHash = bufToHex(sigBuf);

  if (computedHash !== hash) {
    return jsonResponse({ error: 'Telegram signature invalid.' }, 401);
  }

  const telegramId = String(fields.id);

  let user = await firestoreGet(env, `users/${telegramId}`);
  if (!user) {
    user = {
      telegram_id: telegramId,
      first_name: fields.first_name || '',
      username: fields.username || '',
      tokens: FREE_TOKENS_ON_SIGNUP,
      created_at: new Date().toISOString(),
    };
    await firestoreSet(env, `users/${telegramId}`, user);
  }

  const sessionToken = await createSession(env, telegramId);

  return jsonResponse({
    session_token: sessionToken,
    telegram_id: telegramId,
    first_name: user.first_name,
    tokens: user.tokens,
  });
}

async function handleMe(request, env) {
  const telegramId = await requireSession(request, env);
  const user = await firestoreGet(env, `users/${telegramId}`);
  if (!user) return jsonResponse({ error: 'User not found' }, 404);
  return jsonResponse({ telegram_id: telegramId, tokens: user.tokens, first_name: user.first_name });
}

// ===========================================================================
// Generate speech (proxies to RunPod, deducts tokens)
// ===========================================================================
async function handleGenerate(request, env) {
  const telegramId = await requireSession(request, env);
  const body = await request.json();
  const text = (body.text || '').trim();
  if (!text) return jsonResponse({ error: 'Text is required.' }, 400);

  const user = await firestoreGet(env, `users/${telegramId}`);
  if (!user) return jsonResponse({ error: 'User not found' }, 404);

  const cost = tokenCostFor(text);
  if ((user.tokens || 0) < cost) {
    return jsonResponse({ error: 'insufficient_tokens', tokens: user.tokens, required: cost }, 402);
  }

  const input = { text };
  if (body.reference_audio_base64) input.reference_audio_base64 = body.reference_audio_base64;
  if (body.prompt_text) input.prompt_text = body.prompt_text;

  const runRes = await fetch(`https://api.runpod.ai/v2/${env.RUNPOD_ENDPOINT_ID}/run`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${env.RUNPOD_API_KEY}`,
    },
    body: JSON.stringify({ input }),
  });
  const runData = await runRes.json();
  if (!runRes.ok || !runData.id) {
    return jsonResponse({ error: runData.error || 'RunPod request failed.' }, 502);
  }

  const output = await pollRunPod(env, runData.id);

  await firestoreIncrement(env, `users/${telegramId}`, 'tokens', -cost);

  return jsonResponse({ ...output, tokens_used: cost, tokens_remaining: (user.tokens || 0) - cost });
}

async function pollRunPod(env, jobId) {
  const started = Date.now();
  const timeoutMs = 5 * 60 * 1000;

  while (Date.now() - started < timeoutMs) {
    const res = await fetch(`https://api.runpod.ai/v2/${env.RUNPOD_ENDPOINT_ID}/status/${jobId}`, {
      headers: { Authorization: `Bearer ${env.RUNPOD_API_KEY}` },
    });
    const data = await res.json();

    if (data.status === 'COMPLETED') {
      if (!data.output || !data.output.audio_base64) throw new Error('Worker returned no audio.');
      return data.output;
    }
    if (data.status === 'FAILED') throw new Error(data.error || 'Worker failed.');
    if (data.status === 'CANCELLED') throw new Error('Job cancelled.');

    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error('Timed out waiting for the voice worker.');
}

// ===========================================================================
// Manual payment: user submits a claim, admin approves/rejects it later
// ===========================================================================
async function handleSubmitPayment(request, env) {
  const telegramId = await requireSession(request, env);
  const body = await request.json();
  const plan = PLANS.find((p) => p.id === body.plan_id);
  if (!plan) return jsonResponse({ error: 'Unknown plan.' }, 400);

  const orderId = crypto.randomUUID();
  const order = {
    telegram_id: telegramId,
    plan_id: plan.id,
    plan_name: plan.name,
    tokens: plan.tokens,
    price_mmk: plan.price_mmk,
    note: (body.note || '').slice(0, 300),
    status: 'pending',
    created_at: new Date().toISOString(),
  };
  await firestoreSet(env, `orders/${orderId}`, order);

  return jsonResponse({ order_id: orderId, status: 'pending' });
}

async function handleAdminListOrders(request, env) {
  requireAdmin(request, env);
  const statusFilter = new URL(request.url).searchParams.get('status') || 'pending';
  const orders = await firestoreQuery(env, 'orders', 'status', statusFilter);
  return jsonResponse({ orders });
}

async function handleAdminApprove(request, env) {
  requireAdmin(request, env);
  const { order_id } = await request.json();
  const order = await firestoreGet(env, `orders/${order_id}`);
  if (!order) return jsonResponse({ error: 'Order not found.' }, 404);
  if (order.status !== 'pending') return jsonResponse({ error: 'Order already processed.' }, 400);

  await firestoreIncrement(env, `users/${order.telegram_id}`, 'tokens', order.tokens);
  await firestoreUpdate(env, `orders/${order_id}`, { status: 'approved' });

  return jsonResponse({ ok: true });
}

async function handleAdminReject(request, env) {
  requireAdmin(request, env);
  const { order_id } = await request.json();
  await firestoreUpdate(env, `orders/${order_id}`, { status: 'rejected' });
  return jsonResponse({ ok: true });
}

function requireAdmin(request, env) {
  const secret = request.headers.get('X-Admin-Secret');
  if (!secret || secret !== env.ADMIN_SECRET) {
    throw Object.assign(new Error('Incorrect admin secret.'), { status: 401 });
  }
}

// ===========================================================================
// Stateless session tokens (HMAC-signed, no DB lookup needed to verify)
// ===========================================================================
async function createSession(env, telegramId) {
  const payload = { sub: telegramId, exp: Date.now() + 30 * 24 * 3600 * 1000 };
  const payloadB64 = base64url(JSON.stringify(payload));
  const sig = await hmacSign(env.SESSION_SECRET, payloadB64);
  return `${payloadB64}.${sig}`;
}

async function requireSession(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token || !token.includes('.')) throw new Error('Not logged in.');

  const [payloadB64, sig] = token.split('.');
  const expectedSig = await hmacSign(env.SESSION_SECRET, payloadB64);
  if (sig !== expectedSig) throw new Error('Invalid session.');

  const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
  if (payload.exp < Date.now()) throw new Error('Session expired, please log in again.');

  return payload.sub;
}

async function hmacSign(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return base64url(sigBuf);
}

function base64url(input) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);
  let bin = '';
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ===========================================================================
// Firestore REST client (authenticated as the service account)
// ===========================================================================
async function getGoogleAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: env.FIREBASE_CLIENT_EMAIL,
    scope: 'https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  };
  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claim))}`;

  const pem = env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
  const der = pemToDer(pem);
  const key = await crypto.subtle.importKey(
    'pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']
  );
  const sigBuf = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(unsigned));
  const jwt = `${unsigned}.${base64url(sigBuf)}`;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });
  const data = await res.json();
  if (!data.access_token) throw new Error('Could not authenticate with Firebase.');
  return data.access_token;
}

function pemToDer(pem) {
  const b64 = pem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s+/g, '');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function firestoreBase(env) {
  return `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents`;
}

function toFirestoreFields(obj) {
  const fields = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'number') fields[k] = Number.isInteger(v) ? { integerValue: v } : { doubleValue: v };
    else if (typeof v === 'boolean') fields[k] = { booleanValue: v };
    else fields[k] = { stringValue: String(v) };
  }
  return { fields };
}

function fromFirestoreFields(doc) {
  if (!doc || !doc.fields) return null;
  const obj = {};
  for (const [k, v] of Object.entries(doc.fields)) {
    if ('integerValue' in v) obj[k] = parseInt(v.integerValue, 10);
    else if ('doubleValue' in v) obj[k] = v.doubleValue;
    else if ('booleanValue' in v) obj[k] = v.booleanValue;
    else obj[k] = v.stringValue;
  }
  return obj;
}

async function firestoreGet(env, path) {
  const token = await getGoogleAccessToken(env);
  const res = await fetch(`${firestoreBase(env)}/${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('Firestore read failed.');
  return fromFirestoreFields(await res.json());
}

async function firestoreSet(env, path, obj) {
  const token = await getGoogleAccessToken(env);
  const res = await fetch(`${firestoreBase(env)}/${path}`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(toFirestoreFields(obj)),
  });
  if (!res.ok) throw new Error('Firestore write failed.');
}

async function firestoreUpdate(env, path, partialObj) {
  const token = await getGoogleAccessToken(env);
  const mask = Object.keys(partialObj).map((k) => `updateMask.fieldPaths=${encodeURIComponent(k)}`).join('&');
  const res = await fetch(`${firestoreBase(env)}/${path}?${mask}`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(toFirestoreFields(partialObj)),
  });
  if (!res.ok) throw new Error('Firestore update failed.');
}

async function firestoreIncrement(env, path, field, delta) {
  const current = (await firestoreGet(env, path)) || {};
  const newValue = (current[field] || 0) + delta;
  await firestoreUpdate(env, path, { [field]: newValue });
}

async function firestoreQuery(env, collectionId, field, value) {
  const token = await getGoogleAccessToken(env);
  const base = firestoreBase(env).replace('/documents', '');
  const res = await fetch(`${base}/documents:runQuery`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      structuredQuery: {
        from: [{ collectionId }],
        where: {
          fieldFilter: {
            field: { fieldPath: field },
            op: 'EQUAL',
            value: { stringValue: value },
          },
        },
      },
    }),
  });
  const rows = await res.json();
  return rows
    .filter((r) => r.document)
    .map((r) => ({ id: r.document.name.split('/').pop(), ...fromFirestoreFields(r.document) }));
}

// ===========================================================================
// HTML pages (served directly by this Worker — no Blogger involved)
// String.raw is used so backslashes/quotes inside the embedded page are
// preserved exactly as written, with no accidental escape-processing.
// ===========================================================================
function renderUserPage(env) {
  return HTML_USER.replace('__TELEGRAM_BOT_USERNAME__', env.TELEGRAM_BOT_USERNAME || '');
}

const HTML_USER = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Voice Studio — VoxCPM2</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500;9..144,600&family=IBM+Plex+Mono:wght@400;500&family=Inter:wght@400;500;600&display=swap');
  :root{
    --ink:#1c1b19; --paper:#f7f4ee; --panel:#ffffff; --line:#e3ddd0;
    --moss:#4a5d4a; --moss-dim:#7c8c7c; --wax:#b5482f; --wax-dim:#d9a190;
    --shadow:0 1px 0 rgba(28,27,25,0.05);
  }
  *{ box-sizing:border-box; }
  body{ margin:0; background:var(--paper); color:var(--ink); font-family:'Inter', sans-serif; -webkit-font-smoothing:antialiased; }
  .wrap{ max-width:760px; margin:0 auto; padding:56px 24px 90px; }
  header{ margin-bottom:32px; }
  .eyebrow{ font-family:'IBM Plex Mono', monospace; font-size:11px; letter-spacing:0.14em; text-transform:uppercase; color:var(--wax); display:flex; align-items:center; gap:8px; margin-bottom:14px; }
  .eyebrow .dot{ width:6px; height:6px; border-radius:50%; background:var(--moss-dim); display:inline-block; }
  .eyebrow .dot.live{ background:var(--wax); box-shadow:0 0 0 3px rgba(181,72,47,0.15); }
  h1{ font-family:'Fraunces', serif; font-weight:600; font-size:clamp(32px, 5vw, 44px); line-height:1.05; margin:0 0 10px; letter-spacing:-0.01em; }
  .sub{ font-size:15px; color:#57534a; max-width:46ch; line-height:1.5; }
  .account-bar{ display:flex; align-items:center; justify-content:space-between; gap:16px; background:var(--panel); border:1px solid var(--line); padding:14px 20px; margin-bottom:24px; }
  .account-left{ display:flex; align-items:center; gap:12px; }
  .avatar{ width:34px; height:34px; border-radius:50%; background:var(--line); overflow:hidden; flex-shrink:0; }
  .avatar img{ width:100%; height:100%; object-fit:cover; }
  .account-name{ font-size:14px; font-weight:600; }
  .account-tokens{ font-family:'IBM Plex Mono', monospace; font-size:12px; color:var(--moss); }
  .buy-link{ font-family:'IBM Plex Mono', monospace; font-size:11.5px; letter-spacing:0.06em; text-transform:uppercase; color:var(--wax); background:none; border:1px solid var(--wax-dim); padding:8px 14px; cursor:pointer; }
  .buy-link:hover{ background:var(--wax); color:#fff; border-color:var(--wax); }
  .logout-link{ font-family:'IBM Plex Mono', monospace; font-size:11px; color:#a39c8c; background:none; border:none; cursor:pointer; text-decoration:underline; }
  .panel{ background:var(--panel); border:1px solid var(--line); border-radius:2px; box-shadow:var(--shadow); }
  .row{ padding:22px 24px; border-bottom:1px solid var(--line); }
  .row:last-child{ border-bottom:none; }
  label{ display:flex; align-items:baseline; justify-content:space-between; font-family:'IBM Plex Mono', monospace; font-size:11px; letter-spacing:0.08em; text-transform:uppercase; color:#7a756a; margin-bottom:10px; }
  textarea{ width:100%; background:transparent; border:none; border-bottom:1px solid var(--line); padding:8px 0 10px; font-family:'Fraunces', serif; font-size:17px; color:var(--ink); outline:none; resize:vertical; min-height:88px; line-height:1.5; }
  textarea:focus{ border-color:var(--moss); }
  textarea::placeholder{ color:#b7b0a2; }
  .charcount{ text-align:right; font-family:'IBM Plex Mono', monospace; font-size:11px; color:#a39c8c; margin-top:6px; }
  .dropzone{ border:1px dashed #cfc7b6; border-radius:2px; padding:20px; display:flex; align-items:center; gap:14px; cursor:pointer; transition:border-color .15s, background .15s; }
  .dropzone:hover, .dropzone.drag{ border-color:var(--moss); background:#fbfaf6; }
  .dropzone .glyph{ width:38px; height:38px; border-radius:50%; border:1px solid var(--line); display:flex; align-items:center; justify-content:center; flex-shrink:0; color:var(--moss); font-size:16px; }
  .dropzone .text{ flex:1; min-width:0; }
  .dropzone .filename{ font-family:'IBM Plex Mono', monospace; font-size:13px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .dropzone .hint{ font-size:12.5px; color:#8f8879; margin-top:2px; }
  .dropzone .clear{ background:none; border:none; color:var(--wax); font-size:18px; cursor:pointer; padding:4px; display:none; }
  .dropzone.has-file .clear{ display:block; }
  #refAudioInput{ display:none; }
  .promptline{ margin-top:12px; }
  .promptline input{ font-size:13.5px; width:100%; background:transparent; border:none; border-bottom:1px solid var(--line); padding:8px 0 10px; outline:none; }
  .promptline label{ margin-bottom:6px; }
  .optional{ color:#a39c8c; font-weight:400; }
  .actions{ padding:24px; display:flex; flex-direction:column; gap:14px; }
  button.generate{ background:var(--ink); color:var(--paper); border:none; padding:16px 20px; font-family:'IBM Plex Mono', monospace; font-size:13px; letter-spacing:0.1em; text-transform:uppercase; cursor:pointer; display:flex; align-items:center; justify-content:center; gap:10px; transition:background .15s; }
  button.generate:hover:not(:disabled){ background:var(--wax); }
  button.generate:disabled{ background:#cfc7b6; cursor:not-allowed; }
  .spinner{ width:13px; height:13px; border-radius:50%; border:2px solid rgba(247,244,238,0.35); border-top-color:var(--paper); animation:spin .7s linear infinite; display:none; }
  .spinner.on{ display:inline-block; }
  @keyframes spin{ to{ transform:rotate(360deg); } }
  .status{ font-family:'IBM Plex Mono', monospace; font-size:12px; color:#7a756a; min-height:16px; display:flex; align-items:center; gap:8px; }
  .status.err{ color:var(--wax); }
  .status.ok{ color:var(--moss); }
  .output{ margin-top:28px; border:1px solid var(--line); background:var(--panel); padding:24px; display:none; }
  .output.show{ display:block; }
  .output .eyebrow{ margin-bottom:16px; }
  audio{ width:100%; height:42px; }
  .output-foot{ display:flex; justify-content:space-between; align-items:center; margin-top:16px; gap:12px; }
  .meta{ font-family:'IBM Plex Mono', monospace; font-size:11.5px; color:#8f8879; }
  a.download{ font-family:'IBM Plex Mono', monospace; font-size:12px; letter-spacing:0.06em; text-transform:uppercase; color:var(--ink); text-decoration:none; border:1px solid var(--ink); padding:10px 18px; display:inline-flex; align-items:center; gap:8px; transition:all .15s; flex-shrink:0; }
  a.download:hover{ background:var(--ink); color:var(--paper); }
  .gate{ background:var(--panel); border:1px solid var(--line); padding:48px 32px; text-align:center; }
  .gate p{ color:#57534a; font-size:14px; margin-bottom:22px; }
  .modal-backdrop{ position:fixed; inset:0; background:rgba(28,27,25,0.45); display:none; align-items:center; justify-content:center; z-index:50; padding:20px; }
  .modal-backdrop.show{ display:flex; }
  .modal{ background:var(--panel); max-width:460px; width:100%; max-height:88vh; overflow-y:auto; border:1px solid var(--line); }
  .modal-head{ padding:20px 24px; border-bottom:1px solid var(--line); display:flex; justify-content:space-between; align-items:center; }
  .modal-head h3{ font-family:'Fraunces', serif; font-size:20px; margin:0; }
  .modal-close{ background:none; border:none; font-size:20px; cursor:pointer; color:#8f8879; }
  .modal-body{ padding:24px; }
  .plan-option{ border:1px solid var(--line); padding:14px 16px; margin-bottom:10px; cursor:pointer; display:flex; justify-content:space-between; align-items:center; transition:border-color .15s; }
  .plan-option:hover, .plan-option.selected{ border-color:var(--moss); }
  .plan-option .name{ font-weight:600; font-size:14px; }
  .plan-option .price{ font-family:'IBM Plex Mono', monospace; font-size:13px; color:var(--moss); }
  .pay-instructions{ background:#fbfaf6; border:1px solid var(--line); padding:14px 16px; font-size:13px; line-height:1.6; margin:16px 0; display:none; }
  .pay-instructions.show{ display:block; }
  .pay-instructions b{ color:var(--wax); }
  .modal-body textarea.note{ width:100%; border:1px solid var(--line); padding:10px; font-family:'Inter',sans-serif; font-size:13.5px; min-height:60px; margin-top:6px; }
  .modal-actions{ display:flex; gap:10px; margin-top:18px; }
  .btn-submit{ flex:1; background:var(--ink); color:var(--paper); border:none; padding:12px; font-family:'IBM Plex Mono', monospace; font-size:12px; text-transform:uppercase; letter-spacing:0.08em; cursor:pointer; }
  .btn-submit:disabled{ background:#cfc7b6; cursor:not-allowed; }
  footer{ text-align:center; margin-top:48px; font-family:'IBM Plex Mono', monospace; font-size:11px; color:#b7b0a2; letter-spacing:0.04em; }
  @media (max-width:520px){
    .wrap{ padding:36px 16px 60px; }
    .row{ padding:18px 18px; }
    .output-foot{ flex-direction:column; align-items:stretch; }
    a.download{ justify-content:center; }
    .account-bar{ flex-direction:column; align-items:stretch; }
  }
</style>
</head>
<body>

<div class="wrap">
  <header>
    <div class="eyebrow"><span class="dot" id="liveDot"></span>VoxCPM2 Voice Cloning</div>
    <h1>Voice Studio</h1>
    <p class="sub">Type a line, hand it a short voice sample, and it speaks it back in that voice.</p>
  </header>

  <div class="account-bar" id="accountBar" style="display:none;">
    <div class="account-left">
      <div class="avatar"><img id="avatarImg" src="" alt=""></div>
      <div>
        <div class="account-name" id="accountName">-</div>
        <div class="account-tokens"><span id="tokenCount">0</span> tokens left</div>
      </div>
    </div>
    <div style="display:flex; align-items:center; gap:14px;">
      <button class="buy-link" id="buyBtn">Buy tokens</button>
      <button class="logout-link" id="logoutBtn">Log out</button>
    </div>
  </div>

  <div class="gate" id="gate">
    <p>Log in with Telegram to get 500 free tokens and start generating.</p>
    <div id="tgLoginContainer" style="display:flex; justify-content:center;"></div>
  </div>

  <div id="toolArea" style="display:none;">
    <div class="panel">
      <div class="row">
        <label for="textInput">Text to speak <span style="color:#b5482f">*</span></label>
        <textarea id="textInput" placeholder="Write what you want the voice to say..."></textarea>
        <div class="charcount"><span id="charLen">0</span> / 2000</div>
      </div>
      <div class="row">
        <label>Voice sample <span class="optional">(optional - for cloning)</span></label>
        <div class="dropzone" id="dropzone">
          <div class="glyph">&#9834;</div>
          <div class="text">
            <div class="filename" id="fileNameLabel">Choose an audio file, or drop one here</div>
            <div class="hint">WAV or MP3, a clean few seconds of one speaker works best</div>
          </div>
          <button class="clear" id="clearFile" type="button" title="Remove">&times;</button>
        </div>
        <input type="file" id="refAudioInput" accept="audio/*">
        <div class="promptline" id="promptLine" style="display:none;">
          <label for="promptText">What the sample says <span class="optional">(improves cloning)</span></label>
          <input type="text" id="promptText" placeholder="Transcript of the voice sample...">
        </div>
      </div>
    </div>

    <div class="actions">
      <button class="generate" id="generateBtn">
        <span class="spinner" id="spinner"></span>
        <span id="generateLabel">Generate speech</span>
      </button>
      <div class="status" id="statusLine"></div>
    </div>

    <div class="output" id="output">
      <div class="eyebrow"><span class="dot live"></span>Result</div>
      <audio id="audioPlayer" controls></audio>
      <div class="output-foot">
        <div class="meta" id="outputMeta">-</div>
        <a class="download" id="downloadLink" download="voxcpm-output.wav">Download</a>
      </div>
    </div>
  </div>

  <footer>VoxCPM2 &middot; Voice Studio</footer>
</div>

<div class="modal-backdrop" id="buyModal">
  <div class="modal">
    <div class="modal-head">
      <h3>Buy tokens</h3>
      <button class="modal-close" id="closeModal">&times;</button>
    </div>
    <div class="modal-body">
      <div id="plansList"></div>
      <div class="pay-instructions" id="payInstructions">
        <span id="payLine">Transfer <b>-</b> and follow the instructions below:</span><br>
        <span id="payMethod"></span><br>
        Then write your transaction note / last 4 digits so we can confirm it.
        <textarea class="note" id="payNote" placeholder="e.g. Transferred at 3:15pm, ref 8842..."></textarea>
      </div>
      <div class="modal-actions">
        <button class="btn-submit" id="submitOrderBtn" disabled>Submit for approval</button>
      </div>
      <div class="status" id="orderStatus" style="margin-top:10px;"></div>
    </div>
  </div>
</div>

<script async src="https://telegram.org/js/telegram-widget.js?22"
  data-telegram-login="__TELEGRAM_BOT_USERNAME__"
  data-size="large"
  data-onauth="onTelegramAuth(user)"
  data-request-access="write"></script>

<script>
(function(){
  var $ = function(id){ return document.getElementById(id); };

  var liveDot = $('liveDot');
  var accountBar = $('accountBar');
  var gate = $('gate');
  var toolArea = $('toolArea');
  var accountName = $('accountName');
  var tokenCountEl = $('tokenCount');
  var buyBtn = $('buyBtn');
  var logoutBtn = $('logoutBtn');

  var textEl = $('textInput');
  var charLenEl = $('charLen');
  var dropzone = $('dropzone');
  var refAudioInput = $('refAudioInput');
  var fileNameLabel = $('fileNameLabel');
  var clearFileBtn = $('clearFile');
  var promptLine = $('promptLine');
  var promptTextEl = $('promptText');

  var generateBtn = $('generateBtn');
  var generateLabel = $('generateLabel');
  var spinner = $('spinner');
  var statusLine = $('statusLine');

  var output = $('output');
  var audioPlayer = $('audioPlayer');
  var outputMeta = $('outputMeta');
  var downloadLink = $('downloadLink');

  var buyModal = $('buyModal');
  var closeModalBtn = $('closeModal');
  var plansList = $('plansList');
  var payInstructions = $('payInstructions');
  var payLine = $('payLine');
  var payMethod = $('payMethod');
  var payNote = $('payNote');
  var submitOrderBtn = $('submitOrderBtn');
  var orderStatus = $('orderStatus');

  var session = null;
  try { session = JSON.parse(localStorage.getItem('vs_session') || 'null'); } catch(e) { session = null; }
  var refAudioBase64 = null;
  var selectedPlan = null;

  window.onTelegramAuth = function(user){
    fetch('/auth/telegram', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(user)
    })
    .then(function(res){ return res.json().then(function(data){ return { ok: res.ok, data: data }; }); })
    .then(function(r){
      if(!r.ok) throw new Error(r.data.error || 'Login failed.');
      session = r.data;
      localStorage.setItem('vs_session', JSON.stringify(session));
      renderLoggedIn();
    })
    .catch(function(err){ alert(err.message); });
  };

  function renderLoggedIn(){
    gate.style.display = 'none';
    accountBar.style.display = 'flex';
    toolArea.style.display = 'block';
    liveDot.classList.add('live');
    accountName.textContent = session.first_name || 'You';
    tokenCountEl.textContent = session.tokens;
  }

  function renderLoggedOut(){
    gate.style.display = 'block';
    accountBar.style.display = 'none';
    toolArea.style.display = 'none';
    liveDot.classList.remove('live');
  }

  logoutBtn.addEventListener('click', function(){
    localStorage.removeItem('vs_session');
    session = null;
    renderLoggedOut();
  });

  function refreshBalance(){
    if(!session) return;
    fetch('/me', { headers: { Authorization: 'Bearer ' + session.session_token } })
      .then(function(res){ return res.json().then(function(data){ return { ok: res.ok, data: data }; }); })
      .then(function(r){
        if(r.ok){
          session.tokens = r.data.tokens;
          localStorage.setItem('vs_session', JSON.stringify(session));
          tokenCountEl.textContent = r.data.tokens;
        }
      })
      .catch(function(){ /* non-fatal */ });
  }

  if(session){ renderLoggedIn(); refreshBalance(); } else { renderLoggedOut(); }

  function updateCharAndCost(){
    var len = textEl.value.length;
    charLenEl.textContent = len;
    if(!generateBtn.disabled){
      generateLabel.textContent = len > 0 ? ('Generate speech (' + len + ' token' + (len === 1 ? '' : 's') + ')') : 'Generate speech';
    }
  }
  textEl.addEventListener('input', updateCharAndCost);

  function handleFile(file){
    if(!file) return;
    if(!file.type.indexOf('audio/') === 0){ setStatus('That file does not look like audio.', 'err'); return; }
    var reader = new FileReader();
    reader.onload = function(){
      refAudioBase64 = reader.result.split(',')[1];
      fileNameLabel.textContent = file.name;
      dropzone.classList.add('has-file');
      promptLine.style.display = 'block';
    };
    reader.onerror = function(){ setStatus('Could not read that file.', 'err'); };
    reader.readAsDataURL(file);
  }
  dropzone.addEventListener('click', function(){ refAudioInput.click(); });
  refAudioInput.addEventListener('change', function(e){ handleFile(e.target.files[0]); });
  ['dragenter','dragover'].forEach(function(evt){
    dropzone.addEventListener(evt, function(e){ e.preventDefault(); dropzone.classList.add('drag'); });
  });
  ['dragleave','drop'].forEach(function(evt){
    dropzone.addEventListener(evt, function(e){ e.preventDefault(); dropzone.classList.remove('drag'); });
  });
  dropzone.addEventListener('drop', function(e){ if(e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]); });
  clearFileBtn.addEventListener('click', function(e){
    e.stopPropagation();
    refAudioBase64 = null;
    refAudioInput.value = '';
    fileNameLabel.textContent = 'Choose an audio file, or drop one here';
    dropzone.classList.remove('has-file');
    promptLine.style.display = 'none';
    promptTextEl.value = '';
  });

  function setStatus(msg, kind){
    statusLine.textContent = msg || '';
    statusLine.className = 'status' + (kind ? ' ' + kind : '');
  }
  function setBusy(isBusy){
    generateBtn.disabled = isBusy;
    spinner.classList.toggle('on', isBusy);
    if(isBusy){ generateLabel.textContent = 'Generating...'; } else { updateCharAndCost(); }
  }

  generateBtn.addEventListener('click', function(){
    if(!session){ setStatus('Please log in first.', 'err'); return; }
    var text = textEl.value.trim();
    if(!text){ setStatus('Write something for the voice to say.', 'err'); return; }

    output.classList.remove('show');
    setBusy(true);
    setStatus('Sending request...');

    var input = { text: text };
    if(refAudioBase64){
      input.reference_audio_base64 = refAudioBase64;
      if(promptTextEl.value.trim()) input.prompt_text = promptTextEl.value.trim();
    }

    fetch('/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + session.session_token },
      body: JSON.stringify(input)
    })
    .then(function(res){ return res.json().then(function(data){ return { status: res.status, ok: res.ok, data: data }; }); })
    .then(function(r){
      if(r.status === 402){
        setStatus('Needs ' + r.data.required + ' tokens, you have ' + r.data.tokens + ' - buy more to keep going.', 'err');
        openBuyModal();
        return;
      }
      if(!r.ok) throw new Error(r.data.error || 'Generation failed.');

      renderAudio(r.data);
      setStatus('Done - used ' + r.data.tokens_used + ' token' + (r.data.tokens_used === 1 ? '' : 's') + '.', 'ok');
      tokenCountEl.textContent = r.data.tokens_remaining;
      session.tokens = r.data.tokens_remaining;
      localStorage.setItem('vs_session', JSON.stringify(session));
    })
    .catch(function(err){ setStatus(err.message || 'Something went wrong.', 'err'); })
    .then(function(){ setBusy(false); });
  });

  function renderAudio(out){
    var fmt = out.format || 'wav';
    var mime = fmt === 'mp3' ? 'audio/mpeg' : ('audio/' + fmt);
    var src = 'data:' + mime + ';base64,' + out.audio_base64;
    audioPlayer.src = src;
    downloadLink.href = src;
    downloadLink.download = 'voxcpm-output.' + fmt;
    outputMeta.textContent = out.sample_rate ? (out.sample_rate + ' Hz, ' + fmt.toUpperCase()) : fmt.toUpperCase();
    output.classList.add('show');
    output.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function openBuyModal(){
    buyModal.classList.add('show');
    orderStatus.textContent = '';
    selectedPlan = null;
    submitOrderBtn.disabled = true;
    payInstructions.classList.remove('show');
    plansList.innerHTML = 'Loading plans...';

    fetch('/plans')
      .then(function(res){ return res.json(); })
      .then(function(data){
        plansList.innerHTML = '';
        payMethod.innerHTML = data.payment_instructions || '';
        data.plans.forEach(function(plan){
          var el = document.createElement('div');
          el.className = 'plan-option';
          var nameSpan = document.createElement('span');
          nameSpan.className = 'name';
          nameSpan.textContent = plan.name;
          var priceSpan = document.createElement('span');
          priceSpan.className = 'price';
          priceSpan.textContent = plan.price_mmk.toLocaleString() + ' MMK';
          el.appendChild(nameSpan);
          el.appendChild(priceSpan);
          el.addEventListener('click', function(){
            var all = plansList.querySelectorAll('.plan-option');
            for(var i=0;i<all.length;i++){ all[i].classList.remove('selected'); }
            el.classList.add('selected');
            selectedPlan = plan;
            payLine.innerHTML = 'Transfer <b>' + plan.price_mmk.toLocaleString() + ' MMK</b> and follow the instructions below:';
            payInstructions.classList.add('show');
            submitOrderBtn.disabled = false;
          });
          plansList.appendChild(el);
        });
      });
  }

  buyBtn.addEventListener('click', openBuyModal);
  closeModalBtn.addEventListener('click', function(){ buyModal.classList.remove('show'); });
  buyModal.addEventListener('click', function(e){ if(e.target === buyModal) buyModal.classList.remove('show'); });

  submitOrderBtn.addEventListener('click', function(){
    if(!selectedPlan) return;
    submitOrderBtn.disabled = true;
    orderStatus.textContent = 'Submitting...';
    orderStatus.className = 'status';

    fetch('/submit-payment', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + session.session_token },
      body: JSON.stringify({ plan_id: selectedPlan.id, note: payNote.value.trim() })
    })
    .then(function(res){ return res.json().then(function(data){ return { ok: res.ok, data: data }; }); })
    .then(function(r){
      if(!r.ok) throw new Error(r.data.error || 'Could not submit.');
      orderStatus.textContent = 'Submitted! We will add your tokens once payment is confirmed.';
      orderStatus.className = 'status ok';
    })
    .catch(function(err){
      orderStatus.textContent = err.message;
      orderStatus.className = 'status err';
      submitOrderBtn.disabled = false;
    });
  });
})();
</script>
</body>
</html>`;

const HTML_ADMIN = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin - Voice Studio</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Inter:wght@400;500;600&display=swap');
  :root{ --ink:#1c1b19; --paper:#f7f4ee; --panel:#fff; --line:#e3ddd0; --moss:#4a5d4a; --wax:#b5482f; }
  *{ box-sizing:border-box; }
  body{ margin:0; background:var(--paper); color:var(--ink); font-family:'Inter',sans-serif; }
  .wrap{ max-width:820px; margin:0 auto; padding:40px 20px 80px; }
  h1{ font-family:'IBM Plex Mono',monospace; font-size:15px; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:24px; }
  .gate{ background:var(--panel); border:1px solid var(--line); padding:40px; text-align:center; max-width:360px; margin:80px auto; }
  .gate input{ width:100%; padding:10px; border:1px solid var(--line); margin:14px 0; font-family:'IBM Plex Mono',monospace; }
  .gate button{ width:100%; background:var(--ink); color:var(--paper); border:none; padding:12px; font-family:'IBM Plex Mono',monospace; text-transform:uppercase; letter-spacing:0.08em; cursor:pointer; }
  .gate .err{ color:var(--wax); font-size:12.5px; margin-top:8px; }
  table{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); }
  th, td{ text-align:left; padding:12px 14px; border-bottom:1px solid var(--line); font-size:13.5px; }
  th{ font-family:'IBM Plex Mono',monospace; font-size:11px; text-transform:uppercase; letter-spacing:0.06em; color:#7a756a; }
  tr:last-child td{ border-bottom:none; }
  .note{ color:#7a756a; font-size:12.5px; max-width:220px; }
  .actions button{ font-family:'IBM Plex Mono',monospace; font-size:11px; text-transform:uppercase; letter-spacing:0.05em; border:1px solid var(--line); background:none; padding:6px 12px; cursor:pointer; margin-right:6px; }
  .approve{ border-color:var(--moss) !important; color:var(--moss); }
  .approve:hover{ background:var(--moss); color:#fff; }
  .reject{ border-color:var(--wax) !important; color:var(--wax); }
  .reject:hover{ background:var(--wax); color:#fff; }
  .empty{ padding:30px; text-align:center; color:#a39c8c; font-family:'IBM Plex Mono',monospace; font-size:12.5px; }
  .refresh{ float:right; font-family:'IBM Plex Mono',monospace; font-size:11.5px; background:none; border:1px solid var(--line); padding:6px 12px; cursor:pointer; margin-bottom:14px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="gate" id="gate">
    <h1 style="margin-bottom:6px;">Admin Login</h1>
    <input type="password" id="adminSecretInput" placeholder="Admin secret">
    <button id="unlockBtn">Unlock</button>
    <div class="err" id="gateErr"></div>
  </div>

  <div id="panel" style="display:none;">
    <h1>Pending Payment Orders</h1>
    <button class="refresh" id="refreshBtn">Refresh</button>
    <div style="clear:both;"></div>
    <table id="ordersTable" style="display:none;">
      <thead>
        <tr><th>Telegram ID</th><th>Plan</th><th>Price</th><th>Note</th><th>Date</th><th>Action</th></tr>
      </thead>
      <tbody id="ordersBody"></tbody>
    </table>
    <div class="empty" id="emptyMsg" style="display:none;">No pending orders.</div>
  </div>
</div>

<script>
(function(){
  var $ = function(id){ return document.getElementById(id); };
  var gate = $('gate');
  var panel = $('panel');
  var adminSecretInput = $('adminSecretInput');
  var unlockBtn = $('unlockBtn');
  var gateErr = $('gateErr');
  var ordersTable = $('ordersTable');
  var ordersBody = $('ordersBody');
  var emptyMsg = $('emptyMsg');
  var refreshBtn = $('refreshBtn');

  var adminSecret = sessionStorage.getItem('vs_admin_secret') || '';

  function loadOrders(){
    gateErr.textContent = '';
    fetch('/admin/orders?status=pending', { headers: { 'X-Admin-Secret': adminSecret } })
      .then(function(res){
        return res.json().then(function(data){ return { ok: res.ok, status: res.status, data: data }; });
      })
      .then(function(r){
        if(!r.ok) throw new Error(r.data.error || ('Request failed (' + r.status + ')'));
        renderOrders(r.data.orders || []);
        gate.style.display = 'none';
        panel.style.display = 'block';
        sessionStorage.setItem('vs_admin_secret', adminSecret);
      })
      .catch(function(err){ gateErr.textContent = err.message; });
  }

  function renderOrders(orders){
    if(!orders.length){
      ordersTable.style.display = 'none';
      emptyMsg.style.display = 'block';
      return;
    }
    ordersTable.style.display = 'table';
    emptyMsg.style.display = 'none';
    ordersBody.innerHTML = '';
    orders.forEach(function(order){
      var tr = document.createElement('tr');

      var tdId = document.createElement('td'); tdId.textContent = order.telegram_id;
      var tdPlan = document.createElement('td'); tdPlan.textContent = order.plan_name + ' (' + order.tokens + ' tokens)';
      var tdPrice = document.createElement('td'); tdPrice.textContent = Number(order.price_mmk).toLocaleString() + ' MMK';
      var tdNote = document.createElement('td'); tdNote.className = 'note'; tdNote.textContent = order.note || '-';
      var tdDate = document.createElement('td'); tdDate.textContent = new Date(order.created_at).toLocaleString();
      var tdActions = document.createElement('td'); tdActions.className = 'actions';

      var approveBtn = document.createElement('button');
      approveBtn.className = 'approve';
      approveBtn.textContent = 'Approve';
      approveBtn.addEventListener('click', function(){ actOnOrder(order.id, 'approve'); });

      var rejectBtn = document.createElement('button');
      rejectBtn.className = 'reject';
      rejectBtn.textContent = 'Reject';
      rejectBtn.addEventListener('click', function(){ actOnOrder(order.id, 'reject'); });

      tdActions.appendChild(approveBtn);
      tdActions.appendChild(rejectBtn);

      tr.appendChild(tdId); tr.appendChild(tdPlan); tr.appendChild(tdPrice);
      tr.appendChild(tdNote); tr.appendChild(tdDate); tr.appendChild(tdActions);
      ordersBody.appendChild(tr);
    });
  }

  function actOnOrder(orderId, action){
    fetch('/admin/' + action, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Admin-Secret': adminSecret },
      body: JSON.stringify({ order_id: orderId })
    })
    .then(function(res){ return res.json().then(function(data){ return { ok: res.ok, data: data }; }); })
    .then(function(r){
      if(!r.ok) throw new Error(r.data.error || 'Action failed.');
      loadOrders();
    })
    .catch(function(err){ alert(err.message); });
  }

  unlockBtn.addEventListener('click', function(){
    adminSecret = adminSecretInput.value.trim();
    if(!adminSecret){ gateErr.textContent = 'Enter the admin secret.'; return; }
    loadOrders();
  });
  refreshBtn.addEventListener('click', loadOrders);

  if(adminSecret) loadOrders();
})();
</script>
</body>
</html>`;
