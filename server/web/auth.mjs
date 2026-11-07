// Admin sign-in: a signed session cookie, password accounts from the environment
// (scrypt hashes), and Encedo OIDC (authorization code + PKCE).
//
//   ADMIN_USERS     "admin:scrypt.<salt b64>.<hash b64>,..."   (node server/tools/hash-password.mjs)
//   ADMIN_EMAILS    "a@x.com,b@y.com"                          OIDC identities let in
//   SESSION_SECRET  any long random string

import crypto from 'node:crypto';

const SECRET = Buffer.from(process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'));
const sign = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const SESSION_TTL = 12 * 3600;

export function cookies(req) {
  const out = {};
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
const setCookie = (name, value, maxAge) => `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

function seal(obj) { const p = Buffer.from(JSON.stringify(obj)).toString('base64url'); return `${p}.${sign(p)}`; }
function unseal(v) {
  if (typeof v !== 'string') return null;
  const [p, s] = v.split('.');
  if (!p || !s || sign(p) !== s) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > Date.now() / 1000 ? o : null; } catch { return null; }
}

export function session(req) { return unseal(cookies(req).pg_s); }
export const sessionCookie = (user, via) => setCookie('pg_s', seal({ u: user, via, exp: Math.floor(Date.now() / 1000) + SESSION_TTL }), SESSION_TTL);
export const clearSession = () => setCookie('pg_s', '', 0);
export const csrfToken = (sess) => sign(`csrf:${sess.u}:${sess.exp}`);

// ---- passwords ----------------------------------------------------------------------------------
const users = new Map((process.env.ADMIN_USERS ?? '').split(',').map((x) => x.trim()).filter(Boolean).map((x) => {
  const i = x.indexOf(':'); return [x.slice(0, i), x.slice(i + 1)];
}));
const fails = new Map();                          // ip -> { n, until }

export function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  // dots, not dollars: docker compose would read "$..." in .env as a variable
  return `scrypt.${salt.toString('base64')}.${crypto.scryptSync(pw, salt, 32).toString('base64')}`;
}

export function checkPassword(ip, user, pw) {
  const f = fails.get(ip);
  if (f && f.until > Date.now()) return { locked: true };
  const stored = users.get(user);
  let ok = false;
  if (stored && typeof pw === 'string') {
    const [, salt, hash] = stored.split('.');
    const got = crypto.scryptSync(pw, Buffer.from(salt, 'base64'), 32);
    ok = crypto.timingSafeEqual(got, Buffer.from(hash, 'base64'));
  }
  if (ok) { fails.delete(ip); return { ok: true }; }
  const n = (f?.n ?? 0) + 1;
  fails.set(ip, { n, until: n >= 5 ? Date.now() + 15 * 60_000 : 0 });
  return { ok: false, locked: n >= 5 };
}

// ---- OIDC ---------------------------------------------------------------------------------------
const OIDC = {
  issuer: process.env.OIDC_ISSUER, clientId: process.env.OIDC_CLIENT_ID, secret: process.env.OIDC_CLIENT_SECRET,
  redirect: process.env.OIDC_REDIRECT_URI,
};
export const oidcEnabled = () => !!(OIDC.issuer && OIDC.clientId && OIDC.secret && OIDC.redirect);
export const oidcHost = () => (OIDC.issuer ? new URL(OIDC.issuer).host : '');
const admins = new Set((process.env.ADMIN_EMAILS ?? '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean));
let discovery = null;
async function disco() {
  if (!discovery) {
    const r = await fetch(`${OIDC.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`);
    if (!r.ok) throw new Error(`OIDC discovery: ${r.status}`);
    discovery = await r.json();
  }
  return discovery;
}

export async function oidcStart() {
  const d = await disco();
  const verifier = crypto.randomBytes(32).toString('base64url');
  const st = { state: crypto.randomBytes(16).toString('base64url'), nonce: crypto.randomBytes(16).toString('base64url'), verifier, exp: Math.floor(Date.now() / 1000) + 600 };
  const u = new URL(d.authorization_endpoint);
  u.search = new URLSearchParams({ response_type: 'code', client_id: OIDC.clientId, redirect_uri: OIDC.redirect, scope: 'openid email profile',
    state: st.state, nonce: st.nonce, code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
  return { location: u.toString(), cookie: setCookie('pg_o', seal(st), 600) };
}

/** Finish the code flow. Returns { email } of an administrator, or { error }. */
export async function oidcFinish(req, query) {
  const st = unseal(cookies(req).pg_o);
  if (!st || query.get('state') !== st.state) return { error: 'The sign-in took too long or was started elsewhere. Start it again.' };
  if (query.get('error')) return { error: `The identity provider said: ${query.get('error_description') || query.get('error')}.` };
  const d = await disco();
  const r = await fetch(d.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${Buffer.from(`${encodeURIComponent(OIDC.clientId)}:${encodeURIComponent(OIDC.secret)}`).toString('base64')}` },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: query.get('code') ?? '', redirect_uri: OIDC.redirect, code_verifier: st.verifier }),
  });
  if (!r.ok) return { error: `The identity provider refused the code (${r.status}).` };
  const tok = await r.json();
  // The ID token is trusted because it came straight from the token endpoint over TLS (encedo-oidc README).
  let claims;
  try { claims = JSON.parse(Buffer.from(tok.id_token.split('.')[1], 'base64url').toString()); } catch { return { error: 'The identity provider sent no usable ID token.' }; }
  const now = Date.now() / 1000;
  const audOk = Array.isArray(claims.aud) ? claims.aud.includes(OIDC.clientId) : claims.aud === OIDC.clientId;
  if (claims.iss !== d.issuer || !audOk || claims.nonce !== st.nonce || !(claims.exp > now)) return { error: 'The ID token did not check out.' };
  let email = claims.email;
  if (!email && tok.access_token && d.userinfo_endpoint) {
    const u = await fetch(d.userinfo_endpoint, { headers: { Authorization: `Bearer ${tok.access_token}` } });
    if (u.ok) email = (await u.json()).email;
  }
  if (!email || !admins.has(String(email).toLowerCase())) return { error: `${email ?? 'This identity'} is not on the administrator list.` };
  return { email: String(email).toLowerCase() };
}
export const clearOidc = () => setCookie('pg_o', '', 0);
