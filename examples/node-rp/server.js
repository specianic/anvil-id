// Minimal OpenID Connect relying party for AnvilID.
//
// Authorization code flow with PKCE (S256), state and nonce, UserInfo and
// refresh-token rotation, built on openid-client 6 (which enforces the ID token,
// `iss`, `nonce` and PKCE checks) and Express 5.
//
// Configuration comes from environment variables only:
//   ISSUER          AnvilID issuer URL, e.g. http://localhost:8080 (default tenant)  (required)
//   CLIENT_ID       client id registered in AnvilID                            (required)
//   CLIENT_SECRET   client secret (client_secret_basic)                        (required)
//   PORT            listen port (default 3000)
//   BASE_URL        externally visible base URL (default http://localhost:$PORT)
//   SESSION_SECRET  key used to sign the session cookie (random per start when unset)

import crypto from 'node:crypto';
import express from 'express';
import * as client from 'openid-client';

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`missing required environment variable ${name}`);
    process.exit(1);
  }
  return value;
}

const ISSUER = new URL(requiredEnv('ISSUER'));
const CLIENT_ID = requiredEnv('CLIENT_ID');
const CLIENT_SECRET = requiredEnv('CLIENT_SECRET');
const PORT = Number.parseInt(process.env.PORT ?? '3000', 10);
const BASE_URL = (process.env.BASE_URL ?? `http://localhost:${PORT}`).replace(/\/+$/, '');
const SESSION_KEY = process.env.SESSION_SECRET
  ? Buffer.from(process.env.SESSION_SECRET, 'utf8')
  : crypto.randomBytes(32);
const REDIRECT_URI = `${BASE_URL}/callback`;
const COOKIE_NAME = 'rp_session';

// openid-client refuses plain-http endpoints. A locally running `anvilid serve`
// listens on http://localhost, so allow insecure requests for loopback issuers
// only (development). Any other issuer must use https.
const DEV_LOOPBACK = ISSUER.hostname === 'localhost' || ISSUER.hostname === '127.0.0.1';
const discoveryOptions = DEV_LOOPBACK ? { execute: [client.allowInsecureRequests] } : undefined;

const config = await client.discovery(
  ISSUER,
  CLIENT_ID,
  undefined,
  client.ClientSecretBasic(CLIENT_SECRET),
  discoveryOptions,
);
if (DEV_LOOPBACK) {
  // Dev mode only (loopback issuer over http); see the comment above.
  client.allowInsecureRequests(config);
}

// ---------------------------------------------------------------------------
// Sessions: an in-memory map keyed by a random id carried in a signed cookie.

const sessions = new Map();

function sign(id) {
  return crypto.createHmac('sha256', SESSION_KEY).update(id).digest('base64url');
}

function parseCookies(header) {
  const out = {};
  for (const part of (header ?? '').split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function getSession(req) {
  const raw = parseCookies(req.headers.cookie)[COOKIE_NAME];
  if (!raw) return undefined;
  const [id, mac] = raw.split('.');
  if (!id || !mac) return undefined;
  const expected = Buffer.from(sign(id));
  const given = Buffer.from(mac);
  if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) return undefined;
  return sessions.get(id);
}

function newSession(res) {
  const id = crypto.randomBytes(24).toString('base64url');
  const session = {};
  sessions.set(id, session);
  const secure = BASE_URL.startsWith('https://') ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=${id}.${sign(id)}; Path=/; HttpOnly; SameSite=Lax${secure}`,
  );
  return session;
}

// ---------------------------------------------------------------------------
// Rendering

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head>
<body>
<h1>${escapeHtml(title)}</h1>
${body}
</body>
</html>`;
}

function renderMe(session) {
  const user = session.user;
  return page(
    'Signed in',
    `<dl>
  <dt>sub</dt><dd id="sub">${escapeHtml(user.sub)}</dd>
  <dt>email</dt><dd id="email">${escapeHtml(user.email)}</dd>
  <dt>refresh count</dt><dd id="refresh-count">${session.refreshCount}</dd>
</dl>
<p><a id="refresh" href="/refresh">Refresh tokens</a> · <a href="/">Home</a></p>`,
  );
}

// ---------------------------------------------------------------------------
// Routes

const app = express();
app.disable('x-powered-by');

app.get('/healthz', (_req, res) => {
  res.type('text/plain').send('ok');
});

app.get('/', (req, res) => {
  const session = getSession(req);
  if (session?.user) {
    res.send(
      page(
        'AnvilID sample RP',
        `<p>Signed in as <span id="user">${escapeHtml(session.user.email ?? session.user.sub)}</span>.</p>
<p><a id="me" href="/me">Profile</a></p>`,
      ),
    );
    return;
  }
  res.send(page('AnvilID sample RP', '<p><a id="login" href="/login">Log in</a></p>'));
});

app.get('/login', async (req, res, next) => {
  try {
    const session = getSession(req) ?? newSession(res);
    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
    const state = client.randomState();
    const nonce = client.randomNonce();
    session.pending = { codeVerifier, state, nonce };

    const url = client.buildAuthorizationUrl(config, {
      redirect_uri: REDIRECT_URI,
      scope: 'openid profile email',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
      nonce,
    });
    res.redirect(url.href);
  } catch (err) {
    next(err);
  }
});

app.get('/callback', async (req, res, next) => {
  try {
    const session = getSession(req);
    if (!session?.pending) {
      res.status(400).send(page('Error', '<p>No login in progress.</p>'));
      return;
    }
    const { codeVerifier, state, nonce } = session.pending;
    delete session.pending;

    const currentUrl = new URL(req.originalUrl, BASE_URL);
    const tokens = await client.authorizationCodeGrant(config, currentUrl, {
      pkceCodeVerifier: codeVerifier,
      expectedState: state,
      expectedNonce: nonce,
      idTokenExpected: true,
    });
    const claims = tokens.claims();
    const user = await client.fetchUserInfo(config, tokens.access_token, claims.sub);

    session.tokens = {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      id_token: tokens.id_token,
    };
    session.sub = claims.sub;
    session.user = user;
    session.refreshCount = 0;
    res.redirect('/me');
  } catch (err) {
    next(err);
  }
});

app.get('/me', (req, res) => {
  const session = getSession(req);
  if (!session?.user) {
    res.redirect('/');
    return;
  }
  res.send(renderMe(session));
});

app.get('/refresh', async (req, res, next) => {
  try {
    const session = getSession(req);
    if (!session?.tokens?.refresh_token) {
      res.redirect('/');
      return;
    }
    const tokens = await client.refreshTokenGrant(config, session.tokens.refresh_token);
    // Refresh tokens are rotated: always keep the newly issued one. Reusing the
    // old one would be treated as replay by the OP.
    if (!tokens.refresh_token) {
      throw new Error('refresh response did not include a rotated refresh token');
    }
    session.tokens = {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      id_token: tokens.id_token ?? session.tokens.id_token,
    };
    session.refreshCount += 1;
    session.user = await client.fetchUserInfo(config, tokens.access_token, session.sub);
    res.send(renderMe(session));
  } catch (err) {
    next(err);
  }
});

// Error handler: report the error class and OAuth error code, never tokens.
app.use((err, _req, res, _next) => {
  const code = typeof err?.error === 'string' ? err.error : (err?.code ?? 'error');
  console.error(`request failed: ${err?.name ?? 'Error'} ${code}: ${err?.message ?? ''}`);
  res
    .status(500)
    .send(page('Error', `<p id="error">${escapeHtml(code)}: ${escapeHtml(err?.message)}</p>`));
});

app.listen(PORT, () => {
  console.log(`sample RP listening on ${BASE_URL} (issuer ${ISSUER.href})`);
});
