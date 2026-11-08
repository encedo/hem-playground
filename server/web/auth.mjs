// Sign-in: a link by e-mail (no passwords) or Encedo OIDC (authorization code + PKCE),
// then a signed session cookie that carries the role.
//
//   ADMIN_EMAILS    "a@x.com,b@y.com"   administrators (by sign-in link or Encedo OIDC);
//                   anyone else who signs in sees the modules registered with their e-mail
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

/** The signed-in person: { u, via, role: 'admin' | 'owner' }. Owners see their own modules only. */
export function session(req) { const s = unseal(cookies(req).pg_s); if (s && !s.role) s.role = 'admin'; return s; }
export const sessionCookie = (user, via, role = 'admin') => setCookie('pg_s', seal({ u: user, via, role, exp: Math.floor(Date.now() / 1000) + SESSION_TTL }), SESSION_TTL);
/** One address, one role: an administrator signs in at admin.<domain>, everyone else at account.<domain>. */
export const roleOf = (email) => (isAdminEmail(email) ? 'admin' : 'owner');
export const isAdminEmail = (email) => admins.has(String(email).toLowerCase());

// ---- sign-in link by e-mail (owners without an Encedo identity) ---------------------------------
const usedLinks = new Map();                       // link id -> expiry, so a link works once
const linkAsks = new Map();                        // ip -> { n, since }
/** At most 5 link requests per address in 15 minutes. */
export function linkThrottled(ip) {
  const now = Date.now(), r = linkAsks.get(ip);
  if (!r || now - r.since > 15 * 60_000) { linkAsks.set(ip, { n: 1, since: now }); return false; }
  return ++r.n > 5;
}
/** A one-time sign-in token: by e-mail (15 minutes), or the hand-off of an OIDC sign-in to account.<domain> (1 minute). */
export function linkToken(email, via = 'link') { return seal({ e: String(email).toLowerCase(), v: via, j: crypto.randomBytes(9).toString('base64url'), exp: Math.floor(Date.now() / 1000) + (via === 'link' ? 900 : 60) }); }
/** { email, via } of a token that has not been used yet, or null. */
export function redeemLink(token) {
  const t = unseal(token);
  if (!t || !t.e || usedLinks.has(t.j)) return null;
  const now = Date.now() / 1000;
  for (const [k, v] of usedLinks) if (v < now) usedLinks.delete(k);
  usedLinks.set(t.j, t.exp);
  return { email: t.e, via: t.v ?? 'link' };
}
export const clearSession = () => setCookie('pg_s', '', 0);
export const csrfToken = (sess) => sign(`csrf:${sess.u}:${sess.exp}`);

// ---- OIDC ---------------------------------------------------------------------------------------
const OIDC = {
  issuer: process.env.OIDC_ISSUER, clientId: process.env.OIDC_CLIENT_ID, secret: process.env.OIDC_CLIENT_SECRET,
  redirect: process.env.OIDC_REDIRECT_URI,
};
export const oidcEnabled = () => !!(OIDC.issuer && OIDC.clientId && OIDC.secret && OIDC.redirect);
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

/** Finish the code flow. Returns { email, role }, or { error }. */
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
  if (!email) return { error: 'The identity provider sent no e-mail address for this identity.' };
  email = String(email).toLowerCase();
  return { email, role: roleOf(email) };
}
export const clearOidc = () => setCookie('pg_o', '', 0);
