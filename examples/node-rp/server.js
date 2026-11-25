// Minimal OpenID Connect relying party for AnvilID.
//
// Authorization code flow with PKCE (S256), state and nonce, UserInfo,
// refresh-token rotation, RP-initiated logout and back-channel logout, built on
// openid-client 6 (which enforces the ID token, `iss`, `nonce` and PKCE checks)
// and Express 5. Logout tokens are verified with node:crypto against the
// issuer's JWKS (no extra dependency).
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
const POST_LOGOUT_REDIRECT_URI = `${BASE_URL}/logged-out`;
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

// Drops the signed-in state of every session matching a back-channel logout
// token: the `sid` (OP session) when the token has one, otherwise the `sub`.
function endSessionsFor({ sub, sid }) {
  for (const session of sessions.values()) {
    const matches = sid ? session.sid === sid : sub !== undefined && session.sub === sub;
    if (matches) {
      delete session.user;
      delete session.tokens;
      delete session.sub;
      delete session.sid;
    }
  }
}

// ---------------------------------------------------------------------------
// Back-channel logout token verification (OIDC Back-Channel Logout 1.0, section 2.6)

const BACKCHANNEL_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
const LOGOUT_TOKEN_MAX_AGE_S = 5 * 60;
const CLOCK_SKEW_S = 60;
// JWS algorithms the RP accepts, mapped to node:crypto verify parameters.
// `none` and HMAC algorithms are never accepted.
const JWS_ALGS = {
  RS256: { hash: 'sha256', kty: 'RSA' },
  PS256: { hash: 'sha256', kty: 'RSA', pss: true },
  ES256: { hash: 'sha256', kty: 'EC', crv: 'P-256' },
  Ed25519: { hash: null, kty: 'OKP', crv: 'Ed25519' },
};

// Accepted `jti` values, kept until the token would be too old anyway.
const seenJti = new Map();
// Accepted logout tokens, newest last, for the debugging endpoint.
const receivedLogouts = [];
const MAX_RECEIVED = 1000;

let jwksCache;

async function fetchJwks() {
  const uri = config.serverMetadata().jwks_uri;
  if (!uri) throw new Error('issuer metadata has no jwks_uri');
  const res = await fetch(uri, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`JWKS fetch failed: HTTP ${res.status}`);
  const body = await res.json();
  if (!Array.isArray(body?.keys)) throw new Error('JWKS has no keys array');
  jwksCache = { keys: body.keys, fetchedAt: Date.now() };
  return jwksCache.keys;
}

function selectKey(keys, header, spec) {
  const candidates = keys.filter(
    (k) =>
      k.kty === spec.kty &&
      (spec.crv === undefined || k.crv === spec.crv) &&
      (k.use === undefined || k.use === 'sig') &&
      (k.alg === undefined || k.alg === header.alg) &&
      (header.kid === undefined || k.kid === header.kid),
  );
  // Without a kid the key must be unambiguous.
  return candidates.length === 1 ? candidates[0] : undefined;
}

function decodeSegment(segment) {
  const value = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('JWS segment is not a JSON object');
  }
  return value;
}

// Verifies a logout token and returns its claims, or throws. The thrown
// message is logged by the RP, never sent to the caller.
async function verifyLogoutToken(token) {
  if (typeof token !== 'string') throw new Error('logout_token missing');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('logout_token is not a compact JWS');
  const header = decodeSegment(parts[0]);
  const claims = decodeSegment(parts[1]);

  const spec = Object.hasOwn(JWS_ALGS, header.alg) ? JWS_ALGS[header.alg] : undefined;
  if (!spec) throw new Error(`alg ${String(header.alg)} not accepted`);
  const supported = config.serverMetadata().id_token_signing_alg_values_supported;
  if (Array.isArray(supported) && !supported.includes(header.alg)) {
    throw new Error(`alg ${header.alg} not advertised by the issuer`);
  }
  if (header.typ !== undefined) {
    const typ = String(header.typ).toLowerCase();
    if (typ !== 'logout+jwt' && typ !== 'application/logout+jwt') throw new Error('typ is not logout+jwt');
  }
  if (header.crit !== undefined) throw new Error('crit header not supported');

  let key = selectKey(jwksCache?.keys ?? [], header, spec);
  // Unknown kid: refresh the JWKS once (key rotation), at most every 10 seconds.
  if (!key && (!jwksCache || Date.now() - jwksCache.fetchedAt > 10_000)) {
    key = selectKey(await fetchJwks(), header, spec);
  }
  if (!key) throw new Error('no matching key in the issuer JWKS');

  const publicKey = crypto.createPublicKey({ key, format: 'jwk' });
  const data = Buffer.from(`${parts[0]}.${parts[1]}`);
  const signature = Buffer.from(parts[2], 'base64url');
  let options = publicKey;
  if (spec.pss) {
    options = { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 };
  } else if (spec.kty === 'EC') {
    options = { key: publicKey, dsaEncoding: 'ieee-p1363' };
  }
  if (!crypto.verify(spec.hash, data, options, signature)) throw new Error('bad signature');

  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== config.serverMetadata().issuer) throw new Error('iss mismatch');
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(CLIENT_ID)) throw new Error('aud does not contain the client id');
  if (typeof claims.iat !== 'number') throw new Error('iat missing');
  if (claims.iat > now + CLOCK_SKEW_S) throw new Error('iat in the future');
  if (claims.iat < now - LOGOUT_TOKEN_MAX_AGE_S) throw new Error('logout token too old');
  if (claims.exp !== undefined && (typeof claims.exp !== 'number' || claims.exp <= now - CLOCK_SKEW_S)) {
    throw new Error('logout token expired');
  }
  if (typeof claims.jti !== 'string' || claims.jti === '') throw new Error('jti missing');
  const events = claims.events;
  if (
    typeof events !== 'object' ||
    events === null ||
    Array.isArray(events) ||
    typeof events[BACKCHANNEL_EVENT] !== 'object' ||
    events[BACKCHANNEL_EVENT] === null
  ) {
    throw new Error('events does not contain the back-channel logout event');
  }
  if (Object.hasOwn(claims, 'nonce')) throw new Error('logout token must not contain nonce');
  const hasSub = typeof claims.sub === 'string' && claims.sub !== '';
  const hasSid = typeof claims.sid === 'string' && claims.sid !== '';
  if (!hasSub && !hasSid) throw new Error('logout token has neither sub nor sid');
  return claims;
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
<p><a id="refresh" href="/refresh">Refresh tokens</a> · <a id="logout" href="/logout">Log out</a> · <a href="/">Home</a></p>`,
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
<p><a id="me" href="/me">Profile</a> · <a id="logout" href="/logout">Log out</a></p>`,
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
    session.sid = typeof claims.sid === 'string' ? claims.sid : undefined;
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

// RP-initiated logout: forget the local login, then send the browser to the
// OP's end_session_endpoint with id_token_hint, post_logout_redirect_uri and a
// fresh state that /logged-out checks.
app.get('/logout', (req, res, next) => {
  try {
    const session = getSession(req);
    const idToken = session?.tokens?.id_token;
    if (!session || !idToken) {
      res.redirect('/');
      return;
    }
    if (!config.serverMetadata().end_session_endpoint) {
      res
        .status(501)
        .send(page('Error', '<p id="error">The provider does not advertise an end_session_endpoint.</p>'));
      return;
    }
    const state = client.randomState();
    session.logoutState = state;
    delete session.user;
    delete session.tokens;
    delete session.sub;
    delete session.sid;
    const url = client.buildEndSessionUrl(config, {
      id_token_hint: idToken,
      post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
      state,
    });
    res.redirect(url.href);
  } catch (err) {
    next(err);
  }
});

app.get('/logged-out', (req, res) => {
  const session = getSession(req);
  const expected = session?.logoutState;
  if (session) delete session.logoutState;
  const given = typeof req.query.state === 'string' ? req.query.state : '';
  const ok =
    typeof expected === 'string' &&
    expected.length === given.length &&
    crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(given));
  if (!ok) {
    res.status(400).send(page('Error', '<p id="error">Logout state mismatch.</p>'));
    return;
  }
  res.send(page('Signed out of the sample app', '<p id="logged-out">You are signed out.</p><p><a href="/">Home</a></p>'));
});

// Back-channel logout (OIDC Back-Channel Logout 1.0): the OP POSTs a signed
// logout token. Answers 200 when accepted, 400 (no detail) otherwise.
app.post('/backchannel_logout', express.urlencoded({ extended: false, limit: '16kb' }), async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    if (!req.is('application/x-www-form-urlencoded')) throw new Error('not form-encoded');
    const claims = await verifyLogoutToken(req.body?.logout_token);
    const now = Math.floor(Date.now() / 1000);
    for (const [jti, until] of seenJti) if (until < now) seenJti.delete(jti);
    if (seenJti.has(claims.jti)) throw new Error('jti replay');
    seenJti.set(claims.jti, claims.iat + LOGOUT_TOKEN_MAX_AGE_S + CLOCK_SKEW_S);

    const entry = {
      sub: typeof claims.sub === 'string' ? claims.sub : undefined,
      sid: typeof claims.sid === 'string' ? claims.sid : undefined,
      jti: claims.jti,
      received_at: new Date().toISOString(),
    };
    receivedLogouts.push(entry);
    if (receivedLogouts.length > MAX_RECEIVED) receivedLogouts.shift();
    endSessionsFor(entry);
    res.status(200).end();
  } catch (err) {
    console.error(`back-channel logout rejected: ${err?.message ?? err}`);
    res.status(400).end();
  }
});

// Sample-app debugging endpoint: the logout tokens accepted so far, optionally
// filtered by `sub`. The e2e tests poll it. A production RP would not expose this.
app.get('/backchannel_logout/received', (req, res) => {
  const sub = typeof req.query.sub === 'string' ? req.query.sub : undefined;
  res.setHeader('Cache-Control', 'no-store');
  res.json(sub === undefined ? receivedLogouts : receivedLogouts.filter((e) => e.sub === sub));
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
