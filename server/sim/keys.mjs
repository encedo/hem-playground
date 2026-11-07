// Key records and what can be done with them. A record:
//   { kid, type, att, pkey, ecdh, exdsa, label, descr, created, updated, priv, pub }
// priv: SECP* raw scalar; X/Ed curves pkcs8 DER; ML-KEM / ML-DSA the 64 / 32 B
// seed; symmetric the secret. pub: the API form (base64), see the key-type table.

import crypto from 'node:crypto';
import { b64, sha, rand } from './codec.mjs';
import { CURVES, toBuf, ed25519PrivToX25519, ed25519PubToX25519 } from './ec.mjs';

export const NIST = ['SECP256R1', 'SECP384R1', 'SECP521R1', 'SECP256K1'];
export const MONT = { CURVE25519: 'x25519', CURVE448: 'x448' };
export const EDW = { ED25519: 'ed25519', ED448: 'ed448' };
export const MLKEM = { MLKEM512: 'ml-kem-512', MLKEM768: 'ml-kem-768', MLKEM1024: 'ml-kem-1024' };
export const MLDSA = { MLDSA44: 'ml-dsa-44', MLDSA65: 'ml-dsa-65', MLDSA87: 'ml-dsa-87' };
export const HMACK = { 'SHA2-256': ['sha256', 32], 'SHA2-384': ['sha384', 48], 'SHA2-512': ['sha512', 64], 'SHA3-256': ['sha3-256', 32], 'SHA3-384': ['sha3-384', 48], 'SHA3-512': ['sha3-512', 64] };
export const AESK = { AES128: 16, AES192: 24, AES256: 32 };
export const ALL_TYPES = [...NIST, ...Object.keys(MONT), ...Object.keys(EDW), ...Object.keys(MLKEM), ...Object.keys(MLDSA), ...Object.keys(HMACK), 'SHA1', ...Object.keys(AESK)];
export const PUB_LEN = { SECP256R1: 33, SECP384R1: 49, SECP521R1: 67, SECP256K1: 33, CURVE25519: 32, CURVE448: 56, ED25519: 32, ED448: 57, MLKEM512: 800, MLKEM768: 1184, MLKEM1024: 1568, MLDSA44: 1312, MLDSA65: 1952, MLDSA87: 2592 };
export const KEM_CT = { MLKEM512: 768, MLKEM768: 1088, MLKEM1024: 1568 };

export const CURVE_HASH = (t) => ({ SECP256R1: 'sha256', SECP256K1: 'sha256', SECP384R1: 'sha384', SECP521R1: 'sha512' })[t];
export const isAsym = (t) => t in PUB_LEN;
export const isSym = (t) => t in HMACK || t in AESK || t === 'SHA1';
export const isPqc = (t) => t in MLKEM || t in MLDSA;

/** The type string the module reports: flags in a fixed order, then the subtype. */
export function typeString(k) {
  const f = [];
  if (k.att) f.push('ATT');
  if (k.pkey) f.push('PKEY');
  if (k.ecdh) f.push('ECDH');
  if (k.exdsa) f.push('ExDSA');
  if (k.cert) f.push('CERT');
  if (isPqc(k.type)) f.push('PQC');
  if (k.hpke) f.push('HPKE');
  f.push(k.der ? 'GENERIC_DER' : k.type);
  return f.join(',');
}

export function parseMode(mode) {
  if (mode === 'ECDH') return { ecdh: true, exdsa: false, hpke: false };
  if (mode === 'ExDSA') return { ecdh: false, exdsa: true, hpke: false };
  if (mode === 'ECDH,ExDSA') return { ecdh: true, exdsa: true, hpke: false };
  if (mode === 'HPKE') return { ecdh: false, exdsa: false, hpke: true };
  return null;
}
/** Types that may be made HPKE-only (create / derive with mode HPKE, DEV-503). */
export const HPKE_TYPES = ['SECP256R1', 'SECP384R1', 'SECP521R1', 'CURVE25519', 'CURVE448', 'MLKEM512', 'MLKEM768', 'MLKEM1024'];

/** Flags a key of `type` gets, given the requested mode. */
export function flagsFor(type, mode) {
  const m = mode ?? { ecdh: false, exdsa: false, hpke: false };
  if (m.hpke) return { ecdh: false, exdsa: false, hpke: true };
  if (NIST.includes(type)) return { ecdh: m.ecdh, exdsa: m.exdsa, hpke: false };
  if (type in MONT) return { ecdh: true, exdsa: false, hpke: false };
  if (type === 'ED25519') return { ecdh: m.ecdh, exdsa: true, hpke: false };
  if (type === 'ED448') return { ecdh: false, exdsa: true, hpke: false };
  return { ecdh: false, exdsa: false, hpke: false };
}

const SUBTYPE = { SECP256R1: 10, SECP384R1: 11, SECP521R1: 12, SECP256K1: 13, CURVE25519: 20, CURVE448: 21, ED25519: 22, ED448: 23,
  MLKEM512: 24, MLKEM768: 25, MLKEM1024: 26, MLDSA44: 27, MLDSA65: 28, MLDSA87: 29,
  'SHA2-256': 10, 'SHA2-384': 11, 'SHA2-512': 12, 'SHA3-256': 13, 'SHA3-384': 14, 'SHA3-512': 15, SHA1: 16, AES128: 30, AES192: 31, AES256: 32 };
/** The firmware's 16-bit type word (repo.h STOREDKEY_*), as ext/request reports it. */
export function typeCode(k) {
  let t = SUBTYPE[k.type] ?? 1;
  if (isAsym(k.type) || k.der) t |= 1 << 15;
  if (k.att) t |= 1 << 14;
  if (k.pkey) t |= 1 << 13;
  if (isAsym(k.type)) t |= 1 << 12;
  if (k.ecdh) t |= 1 << 11;
  if (k.exdsa) t |= 1 << 10;
  if (k.cert) t |= 1 << 9;
  if (isPqc(k.type)) t |= 1 << 8;
  if (k.hpke) t |= 1 << 7;
  return t;
}

const kidOf = (bytes) => sha('sha1', bytes).subarray(0, 16).toString('hex');

/** New key material of `type`: { priv, pub } (pub null for symmetric). */
export function generate(type) {
  if (NIST.includes(type)) {
    const e = crypto.createECDH(CURVES[type].node); e.generateKeys();
    return { priv: toBuf(BigInt('0x' + e.getPrivateKey('hex')), CURVES[type].size), pub: e.getPublicKey(null, 'compressed') };
  }
  if (type in MONT || type in EDW) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync(MONT[type] ?? EDW[type]);
    return { priv: privateKey.export({ format: 'der', type: 'pkcs8' }), pub: publicKey.export({ format: 'raw-public' }) };
  }
  if (type in MLKEM || type in MLDSA) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync(MLKEM[type] ?? MLDSA[type]);
    return { priv: privateKey.export({ format: 'raw-seed' }), pub: publicKey.export({ format: 'raw-public' }) };
  }
  if (type in HMACK) return { priv: rand(HMACK[type][1]), pub: null };
  if (type === 'SHA1') return { priv: rand(20), pub: null };
  if (type in AESK) return { priv: rand(AESK[type]), pub: null };
  throw new Error(`unknown type ${type}`);
}

/** Material from derived bytes (HKDF output). SECP*: L+8 bytes reduced to a scalar. */
export function fromSecret(type, okm) {
  if (NIST.includes(type)) {
    const c = CURVES[type];
    const d = (BigInt('0x' + okm.toString('hex')) % (c.n - 1n)) + 1n;
    const priv = toBuf(d, c.size);
    const e = crypto.createECDH(c.node); e.setPrivateKey(priv);
    return { priv, pub: e.getPublicKey(null, 'compressed') };
  }
  if (type in MONT || type in EDW) {
    const k = crypto.createPrivateKey({ key: okm, format: 'raw-private', asymmetricKeyType: MONT[type] ?? EDW[type] });
    return { priv: k.export({ format: 'der', type: 'pkcs8' }), pub: crypto.createPublicKey(k).export({ format: 'raw-public' }) };
  }
  return { priv: okm, pub: null };
}

/** Bytes HKDF has to produce for a derived key of `type`. */
export function deriveLen(type) {
  if (NIST.includes(type)) return CURVES[type].size + 8;
  return { CURVE25519: 32, CURVE448: 56, ED25519: 32, ED448: 57, SHA1: 20 }[type] ?? HMACK[type]?.[1] ?? AESK[type];
}

/** A stored record from material. */
export function record(type, material, { att, label, descr = null, mode = null, now }) {
  const fl = flagsFor(type, mode);
  // asymmetric: SHA-1 of the raw public key; symmetric: SHA-1 of the secret itself (DEV-501)
  const kidSrc = material.pub ?? material.priv;
  return {
    kid: kidOf(kidSrc), type, att: !!att, pkey: isAsym(type) && material.priv != null, ...fl,
    label, descr, created: now, updated: now,
    priv: material.priv != null ? b64(material.priv) : null,
    pub: material.pub ? b64(material.pub) : null,
  };
}

/** Check and normalise an imported public key; null when it is not one. */
export function importPub(type, bytes) {
  if (bytes.length !== PUB_LEN[type]) return null;
  try {
    if (NIST.includes(type)) {
      if (bytes[0] !== 2 && bytes[0] !== 3) return null;
      crypto.ECDH.convertKey(bytes, CURVES[type].node, null, null, 'uncompressed');
      return bytes;
    }
    const alg = MONT[type] ?? EDW[type] ?? MLKEM[type] ?? MLDSA[type];
    crypto.createPublicKey({ key: bytes, format: 'raw-public', asymmetricKeyType: alg });
    return bytes;
  } catch { return null; }
}

// ---- using a record ----------------------------------------------------------------
const PRIV = (k) => Buffer.from(k.priv, 'base64');
const PUB = (k) => Buffer.from(k.pub, 'base64');

export function privateKeyObject(k) {
  if (NIST.includes(k.type)) {
    const c = CURVES[k.type];
    const e = crypto.createECDH(c.node); e.setPrivateKey(PRIV(k));
    const u = e.getPublicKey();
    const crv = { prime256v1: 'P-256', secp384r1: 'P-384', secp521r1: 'P-521', secp256k1: 'secp256k1' }[c.node];
    return crypto.createPrivateKey({ key: { kty: 'EC', crv, x: u.subarray(1, 1 + c.size).toString('base64url'), y: u.subarray(1 + c.size).toString('base64url'), d: PRIV(k).toString('base64url') }, format: 'jwk' });
  }
  if (k.type in MONT || k.type in EDW) return crypto.createPrivateKey({ key: PRIV(k), format: 'der', type: 'pkcs8' });
  if (k.type in MLKEM || k.type in MLDSA) return crypto.createPrivateKey({ key: PRIV(k), format: 'raw-seed', asymmetricKeyType: MLKEM[k.type] ?? MLDSA[k.type] });
  throw new Error('not asymmetric');
}

export function publicKeyObject(k) {
  if (NIST.includes(k.type)) {
    const c = CURVES[k.type];
    const u = crypto.ECDH.convertKey(PUB(k), c.node, null, null, 'uncompressed');
    const crv = { prime256v1: 'P-256', secp384r1: 'P-384', secp521r1: 'P-521', secp256k1: 'secp256k1' }[c.node];
    return crypto.createPublicKey({ key: { kty: 'EC', crv, x: u.subarray(1, 1 + c.size).toString('base64url'), y: u.subarray(1 + c.size).toString('base64url') }, format: 'jwk' });
  }
  return crypto.createPublicKey({ key: PUB(k), format: 'raw-public', asymmetricKeyType: MONT[k.type] ?? EDW[k.type] ?? MLKEM[k.type] ?? MLDSA[k.type] });
}

/** The curve family an ECDH key belongs to, for pairing kid with ext_kid. */
export const ecdhFamily = (k) => (k.type === 'ED25519' ? 'CURVE25519' : k.type);

/** Raw peer public bytes for the ECDH of `k`: what `pubkey` must look like. */
export function peerLen(k) { return { SECP256R1: 33, SECP384R1: 49, SECP521R1: 67, SECP256K1: 33, CURVE25519: 32, ED25519: 32, CURVE448: 56 }[k.type]; }

/** The public part of a stored key as an ECDH peer (Ed25519 converted to X25519). */
export function peerBytesOf(k) { return k.type === 'ED25519' ? ed25519PubToX25519(PUB(k)) : PUB(k); }

/** ECDH of private record `k` with raw peer bytes. Throws when the peer is not a valid key. */
export function ecdh(k, peer) {
  if (NIST.includes(k.type)) {
    const e = crypto.createECDH(CURVES[k.type].node); e.setPrivateKey(PRIV(k));
    return e.computeSecret(peer);
  }
  let priv, alg;
  if (k.type === 'ED25519') {
    const seed = crypto.createPrivateKey({ key: PRIV(k), format: 'der', type: 'pkcs8' }).export({ format: 'raw-private' });
    priv = crypto.createPrivateKey({ key: ed25519PrivToX25519(seed), format: 'raw-private', asymmetricKeyType: 'x25519' });
    alg = 'x25519';
  } else {
    priv = crypto.createPrivateKey({ key: PRIV(k), format: 'der', type: 'pkcs8' });
    alg = MONT[k.type];
  }
  return crypto.diffieHellman({ privateKey: priv, publicKey: crypto.createPublicKey({ key: peer, format: 'raw-public', asymmetricKeyType: alg }) });
}

/** The X25519 public key an ED25519+ECDH key answers to (attestation pubkey.derived). */
export function derivedX25519(k) { return ed25519PubToX25519(PUB(k)); }

export { PRIV, PUB };
