// /api/auth/*: personalisation, password sign-in, pairing and remote sign-in
// with a phone through the broker.

import crypto from 'node:crypto';
import { b64, unb64, jwtParse, jwtVerify, jwtSign, x25519, hmac, isPrintable } from './codec.mjs';
import { fail, validScope, scopes } from './http.mjs';
import { issueNonce, nonceValid, LOG } from './device.mjs';
import { genuineToken } from './attest.mjs';
import { typeCode, record } from './keys.mjs';
import { tlsRecords } from './tls.mjs';

const POLICIES = ['raw_ecdh_enabled', 'pubkey_in_search', 'pubkey_in_list'];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const eidPriv = (ctx) => Buffer.from(ctx.dev.eid.priv, 'base64');

/** The delay the module adds to sign-in replies: 500 ms, 1500 ms after more than 3 failures. */
async function throttle(ctx, t0, ok) {
  const b = ctx.boot;
  const min = b.authFails > 3 ? 1500 : 500;
  if (ok) { if (Date.now() - b.lastFail > 15000) b.authFails = 0; } else { b.authFails++; b.lastFail = Date.now(); }
  ctx.touch('boot');
  const wait = min - (Date.now() - t0);
  if (wait > 0) await sleep(wait);
}

/** Verify a client-signed request JWT keyed X25519(devPriv, iss). Returns the payload or fails 401. */
function verifySigned(ctx, token, devPriv) {
  const p = jwtParse(token);
  if (!p || p.header.ecdh !== 'x25519') fail(401);
  const iss = unb64(p.payload.iss);
  if (!iss || iss.length !== 32) fail(401);
  const key = x25519(devPriv, iss);
  if (!key) fail(401);
  const pl = jwtVerify(p, key, ctx.now);                 // exp / nbf checked when present
  if (!pl) fail(401);
  if (unb64(pl.jti)?.length !== 32 || !nonceValid(ctx.boot, pl.jti, true)) fail(401);
  ctx.touch('boot');
  return pl;
}

function ready(ctx, { inited = true, rtc = false } = {}) {
  if (inited ? !ctx.inited : ctx.inited) fail(409);
  if (ctx.busy || ctx.fls) fail(409);
  if (rtc && !ctx.boot.rtcSet) fail(403);
}

export async function getToken(ctx) {
  if (!ctx.inited || ctx.busy) fail(409);
  if (ctx.dev.cfg.trusted_ts && !ctx.boot.rtcSet) fail(403);
  ctx.touch('boot');
  return { json: { exp: ctx.now + 60, spk: ctx.boot.session.pub, jti: issueNonce(ctx.boot, 120), lbl: ctx.dev.cfg.user, eid: ctx.dev.eid.pub } };
}

export async function postToken(ctx) {
  if (!ctx.inited || ctx.busy) fail(409);
  if (ctx.dev.cfg.trusted_ts && !ctx.boot.rtcSet) fail(403);
  const t0 = Date.now();
  try {
    if (!ctx.body || typeof ctx.body.auth !== 'string') fail(400);
    const pl = verifySigned(ctx, ctx.body.auth, Buffer.from(ctx.boot.session.priv, 'base64'));
    let sub = null;
    if (pl.iss === ctx.dev.cfg.userkey && !ctx.dev.userLocked) sub = 'U';
    else if (pl.iss === ctx.dev.cfg.masterkey) sub = 'M';
    if (!sub) fail(401);
    if (!validScope(pl.scope)) fail(400);
    const iat = typeof pl.iat === 'number' ? pl.iat : null;
    let exp = typeof pl.exp === 'number' && pl.exp > 0 ? pl.exp : (iat ?? ctx.now) + 60;
    if (iat !== null && exp < iat) exp = iat + 30;
    const token = ctx.issueToken({ scope: pl.scope, sub, exp, ctx: pl.ctx });
    await ctx.log(LOG.AUTH_SUCCESS_INTERNAL, 0, sub, scopes({ scope: pl.scope }).join(' '));
    await throttle(ctx, t0, true);
    return { json: { token } };
  } catch (e) {
    await throttle(ctx, t0, false);
    throw e;
  }
}

export async function getInit(ctx) {
  if (!ctx.boot.rtcSet) fail(403);
  ready(ctx, { inited: false });
  ctx.touch('boot');
  return { json: { exp: ctx.now + 60, spk: ctx.boot.session.pub, jti: issueNonce(ctx.boot, 120), genuine: genuineToken(ctx.dev), eid: ctx.dev.eid.pub } };
}

export async function postInit(ctx) {
  if (!ctx.boot.rtcSet) fail(403);
  ready(ctx, { inited: false });
  if (!ctx.body || typeof ctx.body.init !== 'string') fail(400);
  const pl = verifySigned(ctx, ctx.body.init, Buffer.from(ctx.boot.session.priv, 'base64'));
  const c = pl.cfg;
  if (!c || typeof c !== 'object') fail(400);
  const str = (v) => typeof v === 'string';
  const key32 = (v) => unb64(v)?.length === 32;
  const bool = (v) => typeof v === 'boolean';
  if (!str(c.user) || !str(c.email) || !key32(c.masterkey) || !key32(c.userkey) || !str(c.hostname) || !str(c.origin)
    || !bool(c.trusted_ts) || !bool(c.trusted_backend) || !bool(c.allow_keysearch)) fail(400);
  if (ctx.ppa) {
    if (!str(c.ip) || !/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(c.ip) || typeof c.storage_mode !== 'number' || typeof c.storage_disk0size !== 'number' || !bool(c.dnsd)) fail(400);
  }
  if (c.cc_mode !== undefined && !(Number.isInteger(c.cc_mode) && c.cc_mode >= 0 && c.cc_mode <= 15)) fail(400);
  if (c.policy !== undefined && !(Array.isArray(c.policy) && c.policy.every((p) => POLICIES.includes(p)))) fail(400);
  const [ip, pfx] = ctx.ppa ? c.ip.split('/') : ['192.168.7.1', '24'];
  const cfg = {
    user: c.user.slice(0, 63), email: c.email.slice(0, 63), masterkey: c.masterkey, userkey: c.userkey,
    hostname: c.hostname.slice(0, 55), origin: c.origin.slice(0, 127),
    trusted_ts: c.trusted_ts, trusted_backend: c.trusted_backend, allow_keysearch: c.allow_keysearch,
    ip: `${ip}/${pfx ?? 24}`, dnsd: ctx.ppa ? c.dnsd : false,
    storage_mode: ctx.ppa ? c.storage_mode & 0xff : 0, storage_disk0size: ctx.ppa ? c.storage_disk0size : 0,
    ctx: typeof c.ctx === 'number' ? c.ctx : 0, cc_mode: c.cc_mode ?? 0, policy: [...new Set(c.policy ?? [])],
    http_option_hsts: true, http_option_dosprot_mode: 0,
  };
  const d = ctx.dev;
  const rebootRequired = cfg.hostname !== d.hostname;
  d.cfg = cfg; d.inited = ctx.now; d.uts = ctx.now;
  d.httpsUp = true;                                       // the playground has the TLS of the module's name
  if (ctx.ppa) {
    const disk0 = Math.min(cfg.storage_disk0size, d.storage[0].sectors + d.storage[1].sectors - 65536);
    const total = d.storage[0].sectors + d.storage[1].sectors;
    d.storage[0].sectors = disk0; d.storage[1].sectors = total - disk0;
    ctx.boot.busyUntil = Date.now() + 4000;            // the post-init disk format
    ctx.boot.formatPolls = 0;
  }
  ctx.touch('dev', 'boot');
  // the system TLS records (key generated here, certificate as imported by the playground)
  const tls = await tlsRecords(cfg.hostname, cfg.email, ctx.now);
  tls.key.seq = Date.now(); tls.cert.seq = Date.now() + 1;
  await ctx.putKey(tls.key); await ctx.putKey(tls.cert);
  await ctx.log(LOG.DEVICE_INITED, 0, 'U');
  const json = { instanceid: d.instanceid, token: ctx.issueToken({ scope: 'system:config', sub: 'U', exp: ctx.now + 8 * 3600 }), genuine: genuineToken(d) };
  if (c.gen_csr === true) json.csr = tls.csr;
  if (rebootRequired) json.reboot_required = true;
  return { json };
}

// ---- external authenticator (phone) -------------------------------------------------------
async function extAccess(ctx) {
  if (ctx.fls || !ctx.inited || ctx.busy) fail(409);
  ctx.needToken();
  await ctx.needScope(['auth:ext:pair', 'system:config']);
  if (ctx.token.sub !== 'U') { await ctx.log(LOG.FAILED_SCOPE_CHECK, 1, ctx.token.sub, 'auth:ext:pair'); fail(403); }
}
function epkOf(v) {
  const epk = unb64(v);
  if (!epk || epk.length !== 32) fail(400);
  return epk;
}

export async function extInit(ctx) {
  await extAccess(ctx);
  if (!ctx.body) fail(400);
  const epk = epkOf(ctx.body.epk);
  const key = x25519(eidPriv(ctx), epk);
  if (!key) fail(400);
  const request = jwtSign({ jti: issueNonce(ctx.boot, 86400), exp: ctx.now + 86400, aud: ctx.body.epk, iss: ctx.dev.eid.pub }, key, { ecdh: 'x25519' });
  ctx.touch('boot');
  return { json: { request, eid: ctx.dev.eid.pub } };
}

export async function extValidate(ctx) {
  await extAccess(ctx);
  const b = ctx.body;
  if (!b || typeof b.pid !== 'string' || typeof b.reply !== 'string') fail(400);
  const pid = unb64(b.pid);
  if (!pid || pid.length !== 32) fail(400);
  const pl = verifySigned(ctx, b.reply, eidPriv(ctx));
  if (!isPrintable(pl.label, 1, 64)) fail(400);
  const appPub = unb64(pl.iss);
  const descr = Buffer.concat([Buffer.from('EXTAID'), pid]);
  const rec = record('CURVE25519', { priv: null, pub: appPub }, { att: false, label: pl.label, descr: b64(descr.subarray(0, 128)), now: ctx.now });
  // DEV-501: epk is checked before the key is stored
  const epk = unb64(pl.epk);
  if (!epk || epk.length !== 32) fail(400);
  const k = x25519(eidPriv(ctx), epk);
  if (!k) fail(400);
  if (await ctx.key(rec.kid)) fail(409);
  rec.seq = Date.now();
  await ctx.putKey(rec);
  await ctx.log(LOG.AUTH_PAIRED_EXTERNAL, 0, 'U', rec.kid);
  return { json: { kid: rec.kid, code: b64(hmac('sha256', k, b.reply)) } };
}

export async function extMac(ctx) {
  await extAccess(ctx);
  if (!ctx.body) fail(400);
  const epk = epkOf(ctx.body.epk);
  const key = x25519(eidPriv(ctx), epk);
  if (!key) fail(400);
  const nonce = issueNonce(ctx.boot);
  ctx.touch('boot');
  return { json: { nonce, mac: b64(hmac('sha256', key, Buffer.from(nonce, 'base64'))), eid: ctx.dev.eid.pub } };
}

/** Paired apps: imported X25519 keys whose description is EXTAID + pid. */
async function pairedApps(ctx) {
  const out = [];
  for (const k of await ctx.keys()) {
    const d = k.descr ? Buffer.from(k.descr, 'base64') : null;
    if (k.type === 'CURVE25519' && !k.pkey && d && d.length > 6 && d.subarray(0, 6).toString() === 'EXTAID') out.push({ k, pid: b64(d.subarray(6)) });
  }
  return out;
}

function sealScope(eid, appPub, jti, scopeText) {
  const K = hmac('sha256', x25519(eid, appPub), jti);
  const c = crypto.createCipheriv('aes-128-cbc', K.subarray(0, 16), K.subarray(16, 32));
  const ct = Buffer.concat([c.update(scopeText), c.final()]);
  return 'A' + b64(Buffer.concat([ct, hmac('sha256', K, scopeText)]));
}

export async function extRequest(ctx) {
  if (!ctx.boot.rtcSet) fail(403);
  ready(ctx);
  const b = ctx.body;
  if (!b) fail(400);
  const epk = epkOf(b.epk);
  const key = x25519(eidPriv(ctx), epk);
  if (!key) fail(400);
  if (b.ctx !== undefined && !(typeof b.ctx === 'string' && b.ctx.length >= 1 && b.ctx.length <= 64)) fail(400);
  if (b.note !== undefined && !(typeof b.note === 'string' && b.note.length >= 1 && b.note.length <= 128)) fail(400);
  if (!validScope(b.scope)) fail(400);
  const vals = scopes({ scope: b.scope });
  let text = vals.join(' ');
  let life = 3600;
  for (const v of vals) {
    const m = /^keymgmt:use:([0-9a-fA-F]{32})$/.exec(v);
    if (!m) continue;
    const k = await ctx.key(m[1]);
    if (k) {
      text += '#' + b64(Buffer.from(JSON.stringify({ t: typeCode(k).toString(16).padStart(4, '0'), l: k.label })));
      life = 900;
      break;
    }
  }
  const jti = issueNonce(ctx.boot, 86400);
  const sealed = {};
  for (const { k, pid } of (await pairedApps(ctx)).slice(0, 8)) sealed[pid] = sealScope(eidPriv(ctx), Buffer.from(k.pub, 'base64'), Buffer.from(jti, 'base64'), Buffer.from(text));
  const claims = { iss: ctx.dev.eid.pub, aud: b.epk, iat: ctx.now, exp: ctx.now + life, jti, scope: sealed };
  if (b.ctx) claims.ctx = b.ctx;
  if (b.note) claims.note = b.note;
  ctx.touch('boot');
  return { json: { authreq: jwtSign(claims, key, { ecdh: 'x25519' }), epk: b.epk } };
}

export async function extToken(ctx) {
  if (!ctx.boot.rtcSet) fail(403);
  ready(ctx);
  if (!ctx.body || typeof ctx.body.authreply !== 'string') fail(400);
  const t0 = Date.now();
  try {
    const pl = verifySigned(ctx, ctx.body.authreply, eidPriv(ctx));
    const app = (await pairedApps(ctx)).find((a) => a.pid === pl.pid);
    if (!app || unb64(pl.pid)?.length !== 32) fail(406);
    if (pl.iss !== app.k.pub) fail(406);
    if (typeof pl.scope !== 'string' || !pl.scope.startsWith('A')) fail(406);
    const raw = unb64(pl.scope.slice(1));
    if (!raw || raw.length < 48 || (raw.length - 32) % 16) fail(406);
    const K = hmac('sha256', x25519(eidPriv(ctx), Buffer.from(app.k.pub, 'base64')), Buffer.from(pl.jti, 'base64'));
    let text;
    try {
      const d = crypto.createDecipheriv('aes-128-cbc', K.subarray(0, 16), K.subarray(16, 32));
      text = Buffer.concat([d.update(raw.subarray(0, raw.length - 32)), d.final()]);
    } catch { fail(406); }
    if (!hmac('sha256', K, text).equals(raw.subarray(raw.length - 32))) fail(406);
    const vals = text.toString().split('#')[0].split(' ').filter(Boolean);
    if (!vals.length) fail(406);
    const exp = typeof pl.exp === 'number' && pl.exp > 0 ? pl.exp : ctx.now + 60;
    const token = ctx.issueToken({ scope: vals.length === 1 ? vals[0] : vals, sub: b64(Buffer.from(app.k.kid, 'hex')), exp, ctx: pl.ctx });
    await ctx.log(LOG.AUTH_SUCCESS_EXTERNAL, 0, app.k.kid, vals.join(' '));
    await throttle(ctx, t0, true);
    return { json: { token } };
  } catch (e) {
    await throttle(ctx, t0, false);
    throw e;
  }
}
