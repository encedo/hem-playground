// Encodings and the JWT the module speaks: classic base64 (strict, DEV-432),
// base64url only inside JWT segments, HS256 with an optional "ecdh":"x25519" header.

import crypto from 'node:crypto';

export const b64 = (bytes) => Buffer.from(bytes).toString('base64');
export const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
export const hex = (bytes) => Buffer.from(bytes).toString('hex');

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
/** Strict classic base64: standard alphabet, padded, canonical. null when it is not. */
export function unb64(s) {
  if (typeof s !== 'string' || !B64_RE.test(s)) return null;
  const buf = Buffer.from(s, 'base64');
  if (buf.toString('base64') !== s) return null;          // non-zero unused bits
  return buf;
}
/** base64url without padding, as the attestation nonce segment wants it. */
export function unb64urlNoPad(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s) || s.length % 4 === 1) return null;
  const buf = Buffer.from(s, 'base64url');
  return buf.toString('base64url') === s ? buf : null;
}

export const isHex32 = (s) => typeof s === 'string' && /^[0-9a-fA-F]{32}$/.test(s);
export const isPrintable = (s, min, max) => typeof s === 'string' && s.length >= min && s.length <= max && /^[\x20-\x7e]*$/.test(s);

// ---- X25519 with raw keys ----------------------------------------------------
const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');
export const x25519Priv = (raw) => crypto.createPrivateKey({ key: Buffer.concat([X25519_PKCS8, Buffer.from(raw)]), format: 'der', type: 'pkcs8' });
export const x25519Pub = (raw) => crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI, Buffer.from(raw)]), format: 'der', type: 'spki' });
export function x25519NewRaw() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  return { priv: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16), pub: publicKey.export({ format: 'der', type: 'spki' }).subarray(12) };
}
export const x25519PubOf = (rawPriv) => crypto.createPublicKey(x25519Priv(rawPriv)).export({ format: 'der', type: 'spki' }).subarray(12);
/** X25519(priv, pub) on raw 32-byte keys; null when the peer is not a valid key (low order etc). */
export function x25519(rawPriv, rawPub) {
  try { return crypto.diffieHellman({ privateKey: x25519Priv(rawPriv), publicKey: x25519Pub(rawPub) }); } catch { return null; }
}

export const hmac = (alg, key, ...parts) => { const h = crypto.createHmac(alg, key); for (const p of parts) h.update(p); return h.digest(); };
export const sha = (alg, ...parts) => { const h = crypto.createHash(alg); for (const p of parts) h.update(p); return h.digest(); };
export const rand = (n) => crypto.randomBytes(n);
export const ctEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);

// ---- JWT (HS256) -------------------------------------------------------------
export function jwtSign(payload, key, extraHeader = {}) {
  const head = b64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', ...extraHeader })));
  const body = b64url(Buffer.from(JSON.stringify(payload)));
  return `${head}.${body}.${b64url(hmac('sha256', key, `${head}.${body}`))}`;
}

/** Split and parse a compact JWS without checking it. null when malformed. */
export function jwtParse(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]*$/.test(p))) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!header || typeof header !== 'object' || !payload || typeof payload !== 'object') return null;
    return { header, payload, signed: `${parts[0]}.${parts[1]}`, sig: Buffer.from(parts[2], 'base64url') };
  } catch { return null; }
}

/** Verify HS256 with `key`, and exp/nbf against now. Returns the payload or null. */
export function jwtVerify(parsed, key, now = Math.floor(Date.now() / 1000)) {
  if (!parsed || parsed.header.alg !== 'HS256') return null;
  if (!ctEq(hmac('sha256', key, parsed.signed), parsed.sig)) return null;
  const p = parsed.payload;
  if (p.exp !== undefined && (typeof p.exp !== 'number' || p.exp < now)) return null;
  if (p.nbf !== undefined && (typeof p.nbf !== 'number' || p.nbf > now)) return null;
  return p;
}

/** HKDF (RFC 5869) without node's 1024-byte limit on `info` (an ML-KEM public key does not fit). */
export function hkdf(hash, ikm, salt, info, len) {
  const nh = crypto.createHash(hash).digest().length;
  const prk = hmac(hash, salt.length ? salt : Buffer.alloc(nh), ikm);
  const out = []; let t = Buffer.alloc(0);
  for (let i = 1; out.reduce((n, b) => n + b.length, 0) < len; i++) { t = hmac(hash, prk, t, info, Buffer.from([i])); out.push(t); }
  return Buffer.concat(out).subarray(0, len);
}
