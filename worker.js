// ===========================================================================
// Cloudflare Worker - Voice Studio Backend & Admin Frontend
// ===========================================================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS Headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // 1. Frontend Page (HTML Interface)
      if (url.pathname === '/' || url.pathname === '/index.html') {
        return new Response(getAdminHtml(), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }

      // 2. Telegram Auth Route
      if (url.pathname === '/api/auth/telegram' && request.method === 'POST') {
        return await handleTelegramAuth(request, env, corsHeaders);
      }

      // 3. Admin Auth Route
      if (url.pathname === '/api/auth/admin' && request.method === 'POST') {
        return await handleAdminAuth(request, env, corsHeaders);
      }

      // 4. User Data Sync Route
      if (url.pathname === '/api/user/sync' && request.method === 'POST') {
        return await handleUserSync(request, env, corsHeaders);
      }

      // 5. RunPod Voice Generation Route
      if (url.pathname === '/api/generate' && request.method === 'POST') {
        return await handleGenerate(request, env, corsHeaders);
      }

      return new Response(JSON.stringify({ error: 'Not Found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    } catch (err) {
      console.error('Worker Request Error:', err);
      return new Response(JSON.stringify({ error: err.message || 'Internal Error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }
  },
};

// ===========================================================================
// Firebase Auth & REST Engine
// ===========================================================================

async function getGoogleAccessToken(env) {
  if (!env.FIREBASE_CLIENT_EMAIL || !env.FIREBASE_PRIVATE_KEY) {
    throw new Error('Firebase Configuration Variables မပြည့်စုံပါ။');
  }

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  
  const claim = {
    iss: env.FIREBASE_CLIENT_EMAIL,
    scope: 'https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/cloud-platform',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  };

  const unsignedToken = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claim))}`;

  let pem = env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
  const der = pemToDer(pem);

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    der,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    cryptoKey,
    new TextEncoder().encode(unsignedToken)
  );

  const jwt = `${unsignedToken}.${base64url(signature)}`;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });

  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) {
    console.error('Google OAuth Error Response:', tokenData);
    throw new Error(tokenData.error_description || tokenData.error || 'Could not authenticate with Firebase.');
  }

  return tokenData.access_token;
}

function pemToDer(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/[\r\n\s]/g, '');

  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes.buffer;
}

function base64url(source) {
  let encoded = '';
  if (typeof source === 'string') {
    encoded = btoa(unescape(encodeURIComponent(source)));
  } else {
    let binary = '';
    const bytes = new Uint8Array(source);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    encoded = btoa(binary);
  }
  return encoded.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function firestoreSet(env, collection, documentId, fields) {
  const token = await getGoogleAccessToken(env);
  const projectId = env.FIREBASE_PROJECT_ID;
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}/${documentId}`;

  const res = await fetch(url, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ fields }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error?.message || 'Firestore SET Failed');
  }
  return await res.json();
}

// ===========================================================================
// Request Handlers
// ===========================================================================

async function handleTelegramAuth(request, env, corsHeaders) {
  const body = await request.json();
  const { initData } = body;

  if (!initData) {
    return new Response(JSON.stringify({ error: 'Missing initData' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }

  const isValid = await verifyTelegramAuth(initData, env.TELEGRAM_BOT_TOKEN);
  if (!isValid) {
    return new Response(JSON.stringify({ error: 'Invalid Telegram authentication' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }

  const urlParams = new URLSearchParams(initData);
  const user = JSON.parse(urlParams.get('user'));

  return new Response(JSON.stringify({ success: true, user }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders },
  });
}

async function handleAdminAuth(request, env, corsHeaders) {
  const body = await request.json();
  const { password } = body;

  if (!password || password !== env.ADMIN_SECRET) {
    return new Response(JSON.stringify({ error: 'Invalid Password' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }

  // Verify Firebase Login Connection
  await getGoogleAccessToken(env);

  return new Response(JSON.stringify({ success: true, token: env.SESSION_SECRET }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders },
  });
}

async function handleUserSync(request, env, corsHeaders) {
  const body = await request.json();
  const { userId, userData } = body;

  if (!userId) {
    return new Response(JSON.stringify({ error: 'Missing userId' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }

  const fields = {
    updatedAt: { stringValue: new Date().toISOString() },
  };

  if (userData.name) fields.name = { stringValue: userData.name };
  if (userData.credits !== undefined) fields.credits = { integerValue: userData.credits };

  await firestoreSet(env, 'users', userId, fields);

  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders },
  });
}

async function handleGenerate(request, env, corsHeaders) {
  const body = await request.json();
  const { prompt, voiceId } = body;

  if (!env.RUNPOD_API_KEY || !env.RUNPOD_ENDPOINT_ID) {
    return new Response(JSON.stringify({ error: 'RunPod environment variables missing' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }

  const runpodUrl = `https://api.runpod.ai/v2/${env.RUNPOD_ENDPOINT_ID}/runsync`;
  const res = await fetch(runpodUrl, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RUNPOD_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ input: { prompt, voice_id: voiceId } }),
  });

  const data = await res.json();
  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders },
  });
}

async function verifyTelegramAuth(initData, botToken) {
  const urlParams = new URLSearchParams(initData);
  const hash = urlParams.get('hash');
  urlParams.delete('hash');

  const params = [];
  for (const [key, value] of urlParams.entries()) {
    params.push(`${key}=${value}`);
  }
  params.sort();
  const dataCheckString = params.join('\n');

  const encoder = new TextEncoder();
  const secretKey = await crypto.subtle.digest('SHA-256', encoder.encode(botToken));
  
  const key = await crypto.subtle.importKey(
    'raw',
    secretKey,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(dataCheckString));
  const hexSignature = Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return hexSignature === hash;
}

// ===========================================================================
// Admin UI HTML Template Generator
// ===========================================================================

function getAdminHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Studio UI</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background-color: #f7f6f0;
      margin: 0;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
    }
    .card {
      background: #ffffff;
      padding: 40px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.05);
      width: 100%;
      max-width: 360px;
      text-align: center;
    }
    h2 {
      letter-spacing: 2px;
      font-size: 18px;
      margin-bottom: 24px;
      text-transform: uppercase;
    }
    input[type="password"] {
      width: 100%;
      padding: 12px;
      margin-bottom: 16px;
      border: 1px solid #ccc;
      border-radius: 4px;
      box-sizing: border-box;
      font-size: 16px;
      text-align: center;
    }
    button {
      width: 100%;
      background-color: #1a1a1a;
      color: #ffffff;
      border: none;
      padding: 12px;
      font-size: 14px;
      letter-spacing: 1px;
      cursor: pointer;
      border-radius: 4px;
      text-transform: uppercase;
    }
    button:hover { background-color: #333; }
    .error { color: #d9534f; margin-top: 15px; font-size: 13px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Admin Login</h2>
    <input type="password" id="password" placeholder="••••••••••••">
    <button onclick="login()">Unlock</button>
    <div id="error" class="error"></div>
  </div>

  <script>
    async function login() {
      const password = document.getElementById('password').value;
      const errorDiv = document.getElementById('error');
      errorDiv.innerText = '';

      try {
        const res = await fetch('/api/auth/admin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        const data = await res.json();

        if (res.ok && data.success) {
          alert('Login Successful!');
        } else {
          errorDiv.innerText = data.error || 'Login Failed';
        }
      } catch (err) {
        errorDiv.innerText = 'Network error: ' + err.message;
      }
    }
  </script>
</body>
</html>`;
}
