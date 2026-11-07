// /api/crypto/*

import crypto from 'node:crypto';
import { b64, unb64, isHex32, sha, hmac, ctEq, rand } from './codec.mjs';
import { fail, hasScope } from './http.mjs';
import { LOG } from './device.mjs';
import * as K from './keys.mjs';
import { signDigest, verifyDigest } from './ec.mjs';
import * as X from './mldsa-ext.mjs';

const HMAC_ALG = { 'SHA2-256': 'sha256', 'SHA2-384': 'sha384', 'SHA2-512': 'sha512', 'SHA3-256': 'sha3-256', 'SHA3-384': 'sha3-384', 'SHA3-512': 'sha3-512' };
const MAX_MSG = 2048;

/** Common access: 409 → 401 → 418 → JSON → kid format → scope (keymgmt:use:<kid> for every kid) / role. */
async function common(ctx, kidFields = ['kid']) {
  if (ctx.fls || !ctx.inited || ctx.busy) fail(409);
  ctx.needToken();
  ctx.needTls();
  const b = ctx.body;
  if (!b) fail(400);
  for (const f of kidFields) if (!isHex32(b[f])) fail(400);
  const ok = kidFields.every((f) => hasScope(ctx.token, `keymgmt:use:${b[f]}`)) && ctx.token.sub !== 'M';
  if (!ok) { await ctx.log(LOG.FAILED_SCOPE_CHECK, 1, ctx.token.sub, `keymgmt:use:${b[kidFields[0]]}`); fail(403); }
  return b;
}

/** A base64 field: absent → null; non-string → null (ignored) unless strict; else lo..hi decoded bytes or 400. */
function bin(v, lo, hi, { required = false, strictType = true } = {}) {
  if (v === undefined || v === null) { if (required) fail(400); return null; }
  if (typeof v !== 'string') { if (required || strictType) fail(400); return null; }
  const d = unb64(v);
  if (!d || d.length < lo || d.length > hi) fail(400);
  return d;
}
function hkdfParts(b) {
  const salt = bin(b.hkdf_salt, 1, 128);
  const info = bin(b.hkdf_ctx, 1, 128);
  if (info && info.subarray(0, 7).toString() === 'encedo-') fail(400);
  return { salt: salt ?? Buffer.alloc(0), info: info ?? Buffer.alloc(0) };
}

/**
 * Key mode: 0 = the stored key; 1 = ECDH with ext_kid; 2 = ECDH with pubkey.
 * Returns { mode, key, secret } (secret only in modes 1/2). `nf`: the code for "kid not found",
 * `ecdhFail`: the code for every ECDH / peer problem.
 */
async function keyMode(ctx, b, { nf = 404, ecdhFail = 406 } = {}) {
  const hasExt = b.ext_kid !== undefined, hasPub = b.pubkey !== undefined;
  if (hasExt && !isHex32(b.ext_kid)) fail(400);
  let peer = null;
  if (hasPub) { peer = typeof b.pubkey === 'string' ? unb64(b.pubkey) : null; if (!peer || peer.length > 70) fail(400); }
  const key = await ctx.key(b.kid);
  if (!hasExt && !hasPub) { if (!key) fail(nf); return { mode: 0, key }; }
  if (!key) fail(nf);
  if (!key.pkey || !key.ecdh) fail(ecdhFail === 406 ? 400 : ecdhFail);
  if (hasExt) {
    const e = await ctx.key(b.ext_kid);
    if (!e || !e.ecdh || K.ecdhFamily(e) !== K.ecdhFamily(key)) fail(ecdhFail);
    peer = K.peerBytesOf(e);
  } else if (peer.length !== K.peerLen(key)) fail(ecdhFail);
  try { return { mode: hasExt ? 1 : 2, key, secret: K.ecdh(key, peer) }; } catch { fail(ecdhFail); }
}

// ---- HMAC ----------------------------------------------------------------------------------
async function hmacCore(ctx, verify) {
  const b = await common(ctx);
  const msg = bin(b.msg, 1, MAX_MSG, { required: true });
  if (b.alg !== undefined && !(typeof b.alg === 'string' && HMAC_ALG[b.alg])) fail(400);
  const mac = verify ? bin(b.mac, 0, 68, { required: true }) : null;
  let m;
  try { m = await keyMode(ctx, b, { nf: verify ? 404 : 406, ecdhFail: verify ? 'F' : 406 }); } catch (e) { if (verify && e.status === 'F') return { json: { verified: false } }; throw e; }
  let key, alg;
  if (m.mode === 0) {
    if (!(m.key.type in K.HMACK)) { if (verify) fail(404); fail(406); }
    key = Buffer.from(m.key.priv, 'base64'); alg = K.HMACK[m.key.type][0];
  } else {
    if (!b.alg) { if (verify) return { json: { verified: false } }; fail(406); }
    key = m.secret; alg = HMAC_ALG[b.alg];
  }
  const out = hmac(alg, key, msg);
  await ctx.log(verify ? LOG.HMAC_VERIFY : LOG.HMAC_HASH, 0, ctx.token.sub, b.kid);
  return verify ? { json: { verified: mac.length === out.length && ctEq(mac, out) } } : { json: { mac: b64(out) } };
}
export const hmacHash = (ctx) => hmacCore(ctx, false);
export const hmacVerify = (ctx) => hmacCore(ctx, true);

// ---- ExDSA ---------------------------------------------------------------------------------
const ECDSA_ALGS = { SHA256WithECDSA: 'sha256', SHA384WithECDSA: 'sha384', SHA512WithECDSA: 'sha512', ECDSA: null };
const ED_ALGS = { ED25519: ['Ed25519', 'Ed25519ph', 'Ed25519ctx'], ED448: ['Ed448', 'Ed448ph'] };
const SIG_LEN = { SECP256R1: 64, SECP256K1: 64, SECP384R1: 96, SECP521R1: 132 };

function exdsaArgs(b, k, verify) {
  if (!(typeof b.alg === 'string' && b.alg.length <= 24)) fail(400);
  const nist = K.NIST.includes(k.type);
  if (nist ? !(b.alg in ECDSA_ALGS) : !(ED_ALGS[k.type]?.includes(b.alg))) fail(400);
  if (!k.exdsa || (!verify && !k.pkey) || !k.pub) fail(400);
  const msg = bin(b.msg, 1, MAX_MSG, { required: true });
  const ctxv = typeof b.ctx === 'string' ? bin(b.ctx, 1, 255) : null;
  if (b.alg === 'ECDSA' && (msg.length < 20 || msg.length > 64)) fail(400);
  return { nist, msg, ctxv };
}

export async function exdsaSign(ctx) {
  const b = await common(ctx);
  const k = await ctx.key(b.kid);
  if (!k) fail(404);
  const { nist, msg, ctxv } = exdsaArgs(b, k, false);
  if (b.det !== undefined && typeof b.det !== 'boolean') fail(400);
  let sig;
  if (nist) {
    const h = ECDSA_ALGS[b.alg];
    if (b.det && !h && ![32, 48, 64].includes(msg.length)) fail(400);
    const digest = h ? sha(h, msg) : msg;
    const detHash = h ?? { 32: 'sha256', 48: 'sha384', 64: 'sha512' }[msg.length];
    sig = signDigest(k.type, Buffer.from(k.priv, 'base64'), digest, b.det === true, detHash);
  } else {
    if (b.alg === 'Ed25519ctx' && !ctxv) fail(400);
    try {
      if (b.alg.endsWith('ph')) sig = await X.edphSign(K.privateKeyObject(k), b.alg, msg, ctxv);
      else {
        const opts = { key: K.privateKeyObject(k) };
        if (ctxv && (b.alg === 'Ed25519ctx' || b.alg === 'Ed448')) opts.context = ctxv;
        sig = crypto.sign(null, msg, opts);
      }
    } catch { fail(406); }
  }
  await ctx.log(LOG.EXDSA_SIGN, 0, ctx.token.sub, b.kid);
  return { json: { sign: b64(sig) } };
}

export async function exdsaVerify(ctx) {
  const b = await common(ctx);
  const k = await ctx.key(b.kid);
  if (!k) fail(404);
  const { nist, msg, ctxv } = exdsaArgs(b, k, true);
  const sig = bin(b.sign, 1, 148, { required: true });
  let ok = false;
  if (nist) {
    if (sig.length !== SIG_LEN[k.type]) fail(400);
    const h = ECDSA_ALGS[b.alg];
    ok = verifyDigest(k.type, Buffer.from(k.pub, 'base64'), h ? sha(h, msg) : msg, sig);
  } else if (b.alg.endsWith('ph')) {
    try { ok = await X.edphVerify(K.publicKeyObject(k), b.alg, msg, sig, ctxv); } catch { ok = false; }
  } else {
    const opts = { key: K.publicKeyObject(k) };
    if (ctxv && (b.alg === 'Ed25519ctx' || b.alg === 'Ed448')) opts.context = ctxv;
    try { ok = crypto.verify(null, msg, opts, sig); } catch { ok = false; }
  }
  await ctx.log(LOG.EXDSA_VERIFY, ok ? 0 : 1, ctx.token.sub, b.kid);
  return { json: { verified: ok } };
}

// ---- ciphers -------------------------------------------------------------------------------
const CIPHERS = { 'AES128-CBC': [16, 'cbc'], 'AES192-CBC': [24, 'cbc'], 'AES256-CBC': [32, 'cbc'], 'AES128-GCM': [16, 'gcm'], 'AES192-GCM': [24, 'gcm'], 'AES256-GCM': [32, 'gcm'], 'CHACHA20-POLY1305': [32, 'chacha'] };
const cipherName = (c) => (c[1] === 'chacha' ? 'chacha20-poly1305' : `aes-${c[0] * 8}-${c[1]}`);
const aead = (c) => c[1] !== 'cbc';

async function symKey(ctx, b, size, label) {
  const { salt, info } = hkdfParts(b);
  const m = await keyMode(ctx, b);
  if (m.mode === 0) {
    if (!(m.key.type in K.AESK) || K.AESK[m.key.type] < size) fail(400);
    if (label.includes('chacha20') && m.key.type !== 'AES256') fail(400);
    return Buffer.from(m.key.priv, 'base64').subarray(0, size);
  }
  return Buffer.from(crypto.hkdfSync('sha512', m.secret, salt, Buffer.concat([Buffer.from(label), info]), size));
}

export async function encrypt(ctx) {
  const b = await common(ctx);
  const msg = bin(b.msg, 1, MAX_MSG, { required: true });
  const c = CIPHERS[b.alg];
  if (!c) fail(400);
  const aad = bin(b.aad, 1, 256);
  const key = await symKey(ctx, b, c[0], `encedo-encrypt:v1:${b.alg.toLowerCase()}:`);
  const iv = rand(aead(c) ? 12 : 16);
  const ci = crypto.createCipheriv(cipherName(c), key, iv, aead(c) ? { authTagLength: 16 } : undefined);
  if (aead(c) && aad) ci.setAAD(aad, { plaintextLength: msg.length });
  const ct = Buffer.concat([ci.update(msg), ci.final()]);
  const j = { ciphertext: b64(ct), iv: b64(iv) };
  if (aead(c)) j.tag = b64(ci.getAuthTag());
  await ctx.log(LOG.ENCRYPT, 0, ctx.token.sub, b.kid);
  return { json: j };
}

export async function decrypt(ctx) {
  const b = await common(ctx);
  const msg = bin(b.msg, 1, MAX_MSG + 16, { required: true });
  const c = CIPHERS[b.alg];
  if (!c) fail(400);
  const iv = bin(b.iv, 1, 64, { required: true });
  let tag = null;
  if (c[1] === 'cbc') { if (iv.length !== 16 || msg.length % 16) fail(400); bin(b.tag, 16, 16); } else {
    if (c[1] === 'chacha' ? iv.length !== 12 : iv.length !== 12 && iv.length !== 16) fail(400);
    tag = bin(b.tag, 16, 16, { required: true });
  }
  const aad = bin(b.aad, 1, 256);
  const key = await symKey(ctx, b, c[0], `encedo-encrypt:v1:${b.alg.toLowerCase()}:`);
  let pt;
  try {
    const d = crypto.createDecipheriv(cipherName(c), key, iv, tag ? { authTagLength: 16 } : undefined);
    if (tag) { d.setAuthTag(tag); if (aad) d.setAAD(aad, { plaintextLength: msg.length }); }
    pt = Buffer.concat([d.update(msg), d.final()]);
  } catch { await ctx.log(LOG.DECRYPT, 1, ctx.token.sub, b.kid); fail(406); }
  await ctx.log(LOG.DECRYPT, 0, ctx.token.sub, b.kid);
  return { json: { plaintext: b64(pt) } };
}

const WRAP = { AES128: 16, AES192: 24, AES256: 32 };
async function wrapCore(ctx, unwrap) {
  const b = await common(ctx);
  const msg = bin(b.msg, 1, unwrap ? MAX_MSG + 16 : MAX_MSG, { required: true });
  const alg = b.alg === undefined ? 'AES256' : b.alg;
  if (!WRAP[alg]) fail(400);
  if (msg.length % 8) fail(400);
  const iv = b.iv === undefined ? Buffer.from('A6A6A6A6A6A6A6A6', 'hex') : bin(b.iv, 8, 8, { required: true });
  const key = await symKey(ctx, b, WRAP[alg], 'encedo-wrap:v1:');
  if (msg.length < (unwrap ? 24 : 16)) fail(406);
  let out;
  try {
    const f = unwrap ? crypto.createDecipheriv : crypto.createCipheriv;
    const c = f(`id-aes${WRAP[alg] * 8}-wrap`, key, iv);
    out = Buffer.concat([c.update(msg), c.final()]);
  } catch { fail(406); }
  await ctx.log(unwrap ? LOG.UNWRAP : LOG.WRAP, 0, ctx.token.sub, b.kid);
  return { json: unwrap ? { unwrapped: b64(out) } : { wrapped: b64(out) } };
}
export const wrap = (ctx) => wrapCore(ctx, false);
export const unwrap = (ctx) => wrapCore(ctx, true);

// ---- ECDH ----------------------------------------------------------------------------------
const ECDH_HASH = { 'SHA2-256': 'sha256', 'SHA2-384': 'sha384', 'SHA2-512': 'sha512', 'SHA3-256': 'sha3-256', 'SHA3-384': 'sha3-384', 'SHA3-512': 'sha3-512' };
const ECDH_HKDF = { 'HKDF-SHA2-256': ['sha256', 32], 'HKDF-SHA2-384': ['sha384', 48], 'HKDF-SHA2-512': ['sha512', 64] };

function hkdfItem(o, hashLen) {
  const salt = bin(o.hkdf_salt, 1, 128, { strictType: true });
  const info = bin(o.hkdf_ctx, 1, 128, { strictType: true });
  if (info && info.subarray(0, 7).toString() === 'encedo-') fail(400);
  let len = hashLen;
  if (o.hkdf_len !== undefined) { if (!Number.isInteger(o.hkdf_len) || o.hkdf_len < 16 || o.hkdf_len > 128) fail(400); len = o.hkdf_len; }
  return { salt: salt ?? Buffer.alloc(0), info: info ?? Buffer.alloc(0), len };
}

export async function ecdh(ctx) {
  const b = await common(ctx);
  if (b.ext_kid !== undefined && !isHex32(b.ext_kid)) fail(400);
  if (b.alg !== undefined && !(ECDH_HASH[b.alg] || ECDH_HKDF[b.alg])) fail(400);
  if (b.pubkey !== undefined) { const pk = typeof b.pubkey === 'string' ? unb64(b.pubkey) : null; if (!pk || pk.length > 70) fail(400); }
  if (!b.alg && !(ctx.dev.cfg.policy ?? []).includes('raw_ecdh_enabled')) { await ctx.log(LOG.FAILED_SCOPE_CHECK, 1, ctx.token.sub, 'raw_ecdh_enabled'); fail(403); }
  const hk = ECDH_HKDF[b.alg];
  let items = null, single = null;
  if (b.hkdf_args !== undefined) {
    if (!hk || !Array.isArray(b.hkdf_args) || b.hkdf_args.length < 1 || b.hkdf_args.length > 8) fail(400);
    if (b.hkdf_salt !== undefined || b.hkdf_ctx !== undefined || b.hkdf_len !== undefined) fail(400);
    items = b.hkdf_args.map((o) => { if (!o || typeof o !== 'object' || Array.isArray(o)) fail(400); return hkdfItem(o, hk[1]); });
  } else if (hk) single = hkdfItem(b, hk[1]);
  if (b.ext_kid === undefined && b.pubkey === undefined) fail(400);
  const key = await ctx.key(b.kid);
  if (!key) fail(404);
  if (!key.pkey || !key.ecdh) fail(400);
  let peer;
  if (b.ext_kid !== undefined) {
    const e = await ctx.key(b.ext_kid);
    if (!e) fail(404);
    if (!e.ecdh || K.ecdhFamily(e) !== K.ecdhFamily(key)) fail(400);
    peer = K.peerBytesOf(e);
  } else {
    peer = unb64(b.pubkey);
    if (!peer || peer.length > 70 || peer.length !== K.peerLen(key)) fail(400);
  }
  let ss;
  try { ss = K.ecdh(key, peer); } catch { fail(400); }
  await ctx.log(LOG.ECDH, 0, ctx.token.sub, b.kid);
  if (items) return { json: { hkdf: items.map((i) => b64(Buffer.from(crypto.hkdfSync(hk[0], ss, i.salt, i.info, i.len)))) } };
  if (single) return { json: { ecdh: b64(Buffer.from(crypto.hkdfSync(hk[0], ss, single.salt, single.info, single.len))) } };
  if (b.alg) return { json: { ecdh: b64(sha(ECDH_HASH[b.alg], ss)) } };
  return { json: { ecdh: b64(ss) } };
}

// ---- KDF / OTP / random --------------------------------------------------------------------
export async function kdf(ctx) {
  const b = await common(ctx);
  if (b.alg !== 'HKDF' && b.alg !== 'SP800-108') fail(400);
  if (!Number.isInteger(b.len) || b.len < 16 || b.len > 128) fail(400);
  const salt = b.salt === undefined ? null : bin(b.salt, 1, 128, { strictType: true });
  if (salt && b.alg === 'SP800-108') fail(400);
  const info = b.info === undefined ? Buffer.alloc(0) : bin(b.info, 1, 128, { strictType: true });
  if (info.subarray(0, 7).toString() === 'encedo-') fail(400);
  const k = await ctx.key(b.kid);
  if (!k) fail(404);
  if (!['SHA2-256', 'SHA2-384', 'SHA2-512'].includes(k.type)) fail(400);
  const h = K.HMACK[k.type][0], key = Buffer.from(k.priv, 'base64');
  let okm;
  if (b.alg === 'HKDF') okm = Buffer.from(crypto.hkdfSync(h, key, salt ?? Buffer.alloc(0), info, b.len));
  else {
    const parts = [];
    const L = Buffer.alloc(4); L.writeUInt32BE(b.len * 8);
    for (let i = 1; Buffer.concat(parts).length < b.len; i++) { const c = Buffer.alloc(4); c.writeUInt32BE(i); parts.push(hmac(h, key, c, info, L)); }
    okm = Buffer.concat(parts).subarray(0, b.len);
  }
  await ctx.log(LOG.KDF, 0, ctx.token.sub, b.kid);
  return { json: { okm: b64(okm) } };
}

function hotp(key, counter, digits) {
  const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(counter));
  const h = hmac('sha1', key, c);
  const o = h[19] & 0xf;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 10 ** digits).padStart(digits, '0');
}

export async function otp(ctx) {
  const b = await common(ctx);
  if (b.mode !== 'TOTP' && b.mode !== 'HOTP') fail(400);
  const digits = b.digits ?? 6;
  if (digits !== 6 && digits !== 8) fail(400);
  const int = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
  const totp = b.mode === 'TOTP';
  if (totp && (b.counter !== undefined)) fail(400);
  if (!totp && (b.period !== undefined || b.time !== undefined)) fail(400);
  const period = b.period ?? 30;
  if (totp && !int(period, 15, 300)) fail(400);
  if (b.time !== undefined && !int(b.time, 0, 2 ** 53 - 1)) fail(400);
  if (!totp && !int(b.counter, 0, 2 ** 53 - 1)) fail(400);
  if (b.code !== undefined && !(typeof b.code === 'string' && new RegExp(`^\\d{${digits}}$`).test(b.code))) fail(400);
  if (b.window !== undefined && (b.code === undefined || !int(b.window, 0, 10))) fail(400);
  const k = await ctx.key(b.kid);
  if (!k) fail(404);
  if (k.type !== 'SHA1') fail(400);
  if (totp && b.time === undefined && !ctx.boot.rtcSet) fail(409);
  const key = Buffer.from(k.priv, 'base64');
  const T = totp ? Math.floor((b.time ?? ctx.now) / period) : b.counter;
  if (b.code === undefined) { await ctx.log(LOG.OTP, 0, ctx.token.sub, b.kid); return { json: { code: hotp(key, T, digits), step: T } }; }
  const w = b.window ?? 1;
  const steps = totp ? Array.from({ length: 2 * w + 1 }, (_, i) => T - w + i) : Array.from({ length: w + 1 }, (_, i) => T + i);
  const hit = steps.find((s) => s >= 0 && ctEq(Buffer.from(hotp(key, s, digits)), Buffer.from(b.code)));
  await ctx.log(LOG.OTP, hit === undefined ? 1 : 0, ctx.token.sub, b.kid);
  return { json: hit === undefined ? { verified: false } : { verified: true, step: hit } };
}

export async function random(ctx, rest) {
  if (ctx.fls || ctx.busy) fail(409);
  ctx.needTls();
  if (ctx.inited && !ctx.token) fail(401);
  if (rest !== '' && !rest.startsWith('/')) fail(404);
  let n = 32;
  if (rest) { if (!/^\/\d{1,9}$/.test(rest)) fail(400); n = Number(rest.slice(1)); if (n < 1 || n > 8192) fail(400); }
  return { json: { rnd: b64(rand(n)) } };
}

// ---- PQC -----------------------------------------------------------------------------------
export async function mlkemEncaps(ctx) {
  const b = await common(ctx);
  const k = await ctx.key(b.kid);
  if (!k) fail(404);
  if (!(k.type in K.MLKEM)) fail(400);
  const { sharedKey, ciphertext } = crypto.encapsulate(K.publicKeyObject(k));
  await ctx.log(LOG.MLKEM_ENCAPS, 0, ctx.token.sub, b.kid);
  return { json: { alg: k.type, ss: b64(sharedKey), ct: b64(ciphertext) } };
}

export async function mlkemDecaps(ctx) {
  const b = await common(ctx);
  const ct = bin(b.ct, 1, 1568, { required: true });
  const k = await ctx.key(b.kid);
  if (!k) fail(404);
  if (!(k.type in K.MLKEM) || !k.att || !k.pkey || k.hpke) fail(400);
  if (ct.length !== K.KEM_CT[k.type]) fail(400);
  let ss;
  try { ss = crypto.decapsulate(K.privateKeyObject(k), ct); } catch { fail(406); }
  await ctx.log(LOG.MLKEM_DECAPS, 0, ctx.token.sub, b.kid);
  return { json: { alg: k.type, ss: b64(ss) } };
}

const XWING_LABEL = Buffer.from('5c2e2f2f5e5c', 'hex');      // "\.//^\"
async function xwingKeys(ctx, b, decaps) {
  const m = await ctx.key(b.kid), x = await ctx.key(b.ext_kid);
  if (!m || !x) fail(404);
  if (m.type !== 'MLKEM768' || x.type !== 'CURVE25519' || !x.ecdh) fail(400);
  if (decaps && (!m.att || !m.pkey || !x.pkey || m.hpke || x.hpke)) fail(400);
  return { m, x };
}
export async function xwingEncaps(ctx) {
  const b = await common(ctx, ['kid', 'ext_kid']);
  const { m, x } = await xwingKeys(ctx, b, false);
  const { sharedKey: ssM, ciphertext: ctM } = crypto.encapsulate(K.publicKeyObject(m));
  const { privateKey: e, publicKey: ep } = crypto.generateKeyPairSync('x25519');
  const ctX = ep.export({ format: 'raw-public' });
  const pkX = Buffer.from(x.pub, 'base64');
  let ssX;
  try { ssX = crypto.diffieHellman({ privateKey: e, publicKey: K.publicKeyObject(x) }); } catch { fail(406); }
  const ss = sha('sha3-256', ssM, ssX, ctX, pkX, XWING_LABEL);
  await ctx.log(LOG.XWING_ENCAPS, 0, ctx.token.sub, b.kid);
  return { json: { alg: 'X-Wing', ss: b64(ss), ct: b64(Buffer.concat([ctM, ctX])) } };
}
export async function xwingDecaps(ctx) {
  const b = await common(ctx, ['kid', 'ext_kid']);
  const ct = bin(b.ct, 1120, 1120, { required: true });
  const { m, x } = await xwingKeys(ctx, b, true);
  const ctM = ct.subarray(0, 1088), ctX = ct.subarray(1088);
  let ssM, ssX;
  try { ssM = crypto.decapsulate(K.privateKeyObject(m), ctM); ssX = K.ecdh(x, ctX); } catch { fail(406); }
  const ss = sha('sha3-256', ssM, ssX, ctX, Buffer.from(x.pub, 'base64'), XWING_LABEL);
  await ctx.log(LOG.XWING_DECAPS, 0, ctx.token.sub, b.kid);
  return { json: { alg: 'X-Wing', ss: b64(ss) } };
}

const DSA_MODES = { 'ML-DSA': null, 'HashML-DSA-SHA256': 32, 'HashML-DSA-SHA384': 48, 'HashML-DSA-SHA512': 64, 'ML-DSA-mu': 64 };
function mldsaArgs(b) {
  const msg = bin(b.msg, 1, MAX_MSG, { required: true });
  const ctxv = b.ctx === undefined ? null : bin(b.ctx, 1, 255, { strictType: true });
  const mode = b.mode ?? 'ML-DSA';
  if (typeof mode !== 'string' || !(mode in DSA_MODES)) fail(400);
  if (DSA_MODES[mode] && msg.length !== DSA_MODES[mode]) fail(400);
  if (mode === 'ML-DSA-mu' && ctxv) fail(400);
  return { msg, ctxv, mode };
}
export async function mldsaSign(ctx) {
  const b = await common(ctx);
  const { msg, ctxv, mode } = mldsaArgs(b);
  const k = await ctx.key(b.kid);
  if (!k) fail(404);
  if (!(k.type in K.MLDSA) || !k.att || !k.pkey) fail(400);
  let sig;
  try {
    if (mode === 'ML-DSA') sig = crypto.sign(null, msg, ctxv ? { key: K.privateKeyObject(k), context: ctxv } : K.privateKeyObject(k));
    else if (mode === 'ML-DSA-mu') sig = await X.signRaw(K.privateKeyObject(k), msg, true);
    else sig = await X.signRaw(K.privateKeyObject(k), X.hashMessage(mode, ctxv, msg), false);
  } catch { fail(406); }
  await ctx.log(LOG.MLDSA_SIGN, 0, ctx.token.sub, b.kid);
  return { json: { alg: k.type, sign: b64(sig) } };
}
export async function mldsaVerify(ctx) {
  const b = await common(ctx);
  const { msg, ctxv, mode } = mldsaArgs(b);
  const sig = bin(b.sign, 1, 4627, { required: true });
  const k = await ctx.key(b.kid);
  if (!k) fail(404);
  if (!(k.type in K.MLDSA)) fail(400);
  let ok = false;
  try {
    if (mode === 'ML-DSA') ok = crypto.verify(null, msg, ctxv ? { key: K.publicKeyObject(k), context: ctxv } : K.publicKeyObject(k), sig);
    else if (mode === 'ML-DSA-mu') ok = await X.verifyRaw(K.publicKeyObject(k), msg, sig, true);
    else ok = await X.verifyRaw(K.publicKeyObject(k), X.hashMessage(mode, ctxv, msg), sig, false);
  } catch { ok = false; }
  await ctx.log(LOG.MLDSA_VERIFY, ok ? 0 : 1, ctx.token.sub, b.kid);
  return { json: { verified: ok } };
}

// ---- HPKE (DEV-503) --------------------------------------------------------------------------
import * as H from './hpke.mjs';

function hpkeSuite(b, kemName) {
  if (b.kdf !== undefined && !(typeof b.kdf === 'string' && H.KDFS[b.kdf])) fail(400);
  if (b.aead !== undefined && !(typeof b.aead === 'string' && H.AEADS[b.aead])) fail(400);
  const k = H.KEMS[kemName];
  return { kdf: b.kdf ?? k.kdf, aead: b.aead ?? k.aead };
}

/** The recipient KEM of stored key(s): { name, pkR, x } */
function kemOfKeys(m, x) {
  if (x) {
    if (m.type !== 'MLKEM768' || x.type !== 'CURVE25519') fail(400);
    return { name: 'X-Wing', x: { pkM: Buffer.from(m.pub, 'base64'), pkX: Buffer.from(x.pub, 'base64') } };
  }
  const name = H.KEM_BY_TYPE[m.type];
  if (!name || name === 'X-Wing') fail(400);
  return { name, pkR: H.serializePub(H.KEMS[name], Buffer.from(m.pub, 'base64')) };
}

export async function hpkeSeal(ctx) {
  if (ctx.fls || !ctx.inited || ctx.busy) fail(409);
  ctx.needToken();
  ctx.needTls();
  const b = ctx.body;
  if (!b) fail(400);
  const hasKid = b.kid !== undefined, hasPub = b.pubkey !== undefined;
  if (hasKid === hasPub) fail(400);
  if (b.ext_kid !== undefined && !hasKid) fail(400);
  let kemName, pkR = null, x = null, kidLog = '';
  if (hasKid) {
    const kids = b.ext_kid !== undefined ? ['kid', 'ext_kid'] : ['kid'];
    for (const f of kids) {
      if (!isHex32(b[f])) fail(400);
      if (!hasScope(ctx.token, `keymgmt:use:${b[f]}`) || ctx.token.sub === 'M') { await ctx.log(LOG.FAILED_SCOPE_CHECK, 1, ctx.token.sub, `keymgmt:use:${b[f]}`); fail(403); }
    }
    const m = await ctx.key(b.kid), xk = b.ext_kid !== undefined ? await ctx.key(b.ext_kid) : null;
    if (!m || (b.ext_kid !== undefined && !xk)) fail(404);
    for (const k of [m, xk].filter(Boolean)) if (k.pkey && !k.hpke) { await ctx.log(LOG.FAILED_SCOPE_CHECK, 1, ctx.token.sub, 'hpke'); fail(403); }
    ({ name: kemName, pkR, x } = kemOfKeys(m, xk));
    kidLog = b.kid;
  } else {
    if (typeof b.kem !== 'string' || !H.KEMS[b.kem]) fail(400);
    kemName = b.kem;
    const raw = bin(b.pubkey, 1, 1568, { required: true });
    const k = H.KEMS[kemName];
    if (kemName === 'X-Wing') { if (raw.length !== 1216) fail(400); x = { pkM: raw.subarray(0, 1184), pkX: raw.subarray(1184) }; } else if (k.curve) {
      if (raw.length !== k.enc && raw.length !== { 65: 33, 97: 49, 133: 67 }[k.enc]) fail(400);
      try { pkR = H.serializePub(k, raw); } catch { fail(406); }
    } else {
      if (raw.length !== ({ 'DHKEM-X25519': 32, 'DHKEM-X448': 56, MLKEM512: 800, MLKEM768: 1184, MLKEM1024: 1568 })[kemName]) fail(400);
      pkR = raw;
    }
  }
  const { kdf, aead: aeadName } = hpkeSuite(b, kemName);
  const info = bin(b.info, 1, 128) ?? Buffer.alloc(0);
  const aad = bin(b.aad, 1, 256) ?? Buffer.alloc(0);
  const msg = bin(b.msg, 1, MAX_MSG, { required: true });
  let enc, ss;
  try { ({ ss, enc } = H.encap(kemName, pkR, x)); } catch { fail(406); }
  const { key, nonce } = H.schedule(kemName, kdf, aeadName, ss, info);
  const ct = H.seal(aeadName, key, nonce, aad, msg);
  await ctx.log(LOG.HPKE_SEAL, 0, ctx.token.sub, kidLog);
  return { json: { mode: 'base', suite: H.suiteHex(kemName, kdf, aeadName), kem: kemName, kdf, aead: aeadName, enc: b64(enc), ct: b64(ct) } };
}

export async function hpkeOpen(ctx) {
  const b = await common(ctx, ctx.body?.ext_kid !== undefined ? ['kid', 'ext_kid'] : ['kid']);
  const m = await ctx.key(b.kid), xk = b.ext_kid !== undefined ? await ctx.key(b.ext_kid) : null;
  if (!m || (b.ext_kid !== undefined && !xk)) fail(404);
  for (const k of [m, xk].filter(Boolean)) if (!k.pkey) fail(400);
  const { name: kemName } = kemOfKeys(m, xk);
  for (const k of [m, xk].filter(Boolean)) if (!k.hpke) { await ctx.log(LOG.FAILED_SCOPE_CHECK, 1, ctx.token.sub, 'hpke'); fail(403); }
  const { kdf, aead: aeadName } = hpkeSuite(b, kemName);
  const K_ = H.KEMS[kemName];
  const enc = bin(b.enc, 1, 1568, { required: true });
  if (enc.length !== K_.enc) fail(400);
  const ct = bin(b.ct, 17, MAX_MSG + 16, { required: true });
  const info = bin(b.info, 1, 128) ?? Buffer.alloc(0);
  const aad = bin(b.aad, 1, 256) ?? Buffer.alloc(0);
  let ss;
  try { ss = hpkeDecap(kemName, m, xk, enc); } catch { fail(406); }
  const { key, nonce } = H.schedule(kemName, kdf, aeadName, ss, info);
  let pt;
  try { pt = H.open(aeadName, key, nonce, aad, ct); } catch { await ctx.log(LOG.HPKE_OPEN, 1, ctx.token.sub, b.kid); fail(406); }
  await ctx.log(LOG.HPKE_OPEN, 0, ctx.token.sub, b.kid);
  return { json: { mode: 'base', suite: H.suiteHex(kemName, kdf, aeadName), kem: kemName, kdf, aead: aeadName, plaintext: b64(pt) } };
}

/** The HPKE KEM on the recipient side: the shared secret for `enc`. Throws when `enc` is not valid. */
export function hpkeDecap(kemName, m, xk, enc) {
  const K_ = H.KEMS[kemName];
  if (K_.curve) return H.dhkemDecap(kemName, K.ecdh(m, enc), enc, H.serializePub(K_, Buffer.from(m.pub, 'base64')));
  if (K_.okp) return H.dhkemDecap(kemName, K.ecdh(m, enc), enc, Buffer.from(m.pub, 'base64'));
  if (K_.kem) return crypto.decapsulate(K.privateKeyObject(m), enc);
  const ssM = crypto.decapsulate(K.privateKeyObject(m), enc.subarray(0, 1088));
  const ctX = enc.subarray(1088);
  return H.xwingCombine(ssM, K.ecdh(xk, ctX), ctX, Buffer.from(xk.pub, 'base64'));
}
