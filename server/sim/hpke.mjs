// HPKE (RFC 9180), Base mode, single shot - DHKEM P-256/384/521, X25519, X448,
// ML-KEM (draft-connolly-cfrg-hpke-mlkem) and X-Wing, as the firmware has it (DEV-503).

import crypto from 'node:crypto';

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };

export const KEMS = {
  'DHKEM-P256': { id: 0x0010, type: 'SECP256R1', curve: 'prime256v1', hash: 'sha256', nsecret: 32, enc: 65, kdf: 'HKDF-SHA256', aead: 'AES128-GCM' },
  'DHKEM-P384': { id: 0x0011, type: 'SECP384R1', curve: 'secp384r1', hash: 'sha384', nsecret: 48, enc: 97, kdf: 'HKDF-SHA384', aead: 'AES256-GCM' },
  'DHKEM-P521': { id: 0x0012, type: 'SECP521R1', curve: 'secp521r1', hash: 'sha512', nsecret: 64, enc: 133, kdf: 'HKDF-SHA512', aead: 'AES256-GCM' },
  'DHKEM-X25519': { id: 0x0020, type: 'CURVE25519', okp: 'x25519', hash: 'sha256', nsecret: 32, enc: 32, kdf: 'HKDF-SHA256', aead: 'AES128-GCM' },
  'DHKEM-X448': { id: 0x0021, type: 'CURVE448', okp: 'x448', hash: 'sha512', nsecret: 64, enc: 56, kdf: 'HKDF-SHA512', aead: 'AES256-GCM' },
  MLKEM512: { id: 0x0040, type: 'MLKEM512', kem: 'ml-kem-512', enc: 768, kdf: 'HKDF-SHA256', aead: 'AES128-GCM' },
  MLKEM768: { id: 0x0041, type: 'MLKEM768', kem: 'ml-kem-768', enc: 1088, kdf: 'HKDF-SHA256', aead: 'AES256-GCM' },
  MLKEM1024: { id: 0x0042, type: 'MLKEM1024', kem: 'ml-kem-1024', enc: 1568, kdf: 'HKDF-SHA512', aead: 'AES256-GCM' },
  'X-Wing': { id: 0x647a, type: 'X-Wing', enc: 1120, kdf: 'HKDF-SHA256', aead: 'AES256-GCM' },
};
export const KEM_BY_TYPE = Object.fromEntries(Object.entries(KEMS).map(([n, k]) => [k.type, n]));
export const KDFS = { 'HKDF-SHA256': { id: 1, hash: 'sha256', nh: 32 }, 'HKDF-SHA384': { id: 2, hash: 'sha384', nh: 48 }, 'HKDF-SHA512': { id: 3, hash: 'sha512', nh: 64 } };
export const AEADS = { 'AES128-GCM': { id: 1, nk: 16, cipher: 'aes-128-gcm' }, 'AES256-GCM': { id: 2, nk: 32, cipher: 'aes-256-gcm' }, 'CHACHA20-POLY1305': { id: 3, nk: 32, cipher: 'chacha20-poly1305' } };

const extract = (hash, salt, ikm) => crypto.createHmac(hash, salt.length ? salt : Buffer.alloc(crypto.createHash(hash).digest().length)).update(ikm).digest();
function expand(hash, prk, info, L) {
  const out = []; let t = Buffer.alloc(0);
  for (let i = 1; Buffer.concat(out).length < L; i++) { t = crypto.createHmac(hash, prk).update(Buffer.concat([t, info, Buffer.from([i])])).digest(); out.push(t); }
  return Buffer.concat(out).subarray(0, L);
}
const labeledExtract = (hash, suite, salt, label, ikm) => extract(hash, salt, Buffer.concat([Buffer.from('HPKE-v1'), suite, Buffer.from(label), ikm]));
const labeledExpand = (hash, suite, prk, label, info, L) => expand(hash, prk, Buffer.concat([u16(L), Buffer.from('HPKE-v1'), suite, Buffer.from(label), info]), L);

/** DHKEM shared secret: ExtractAndExpand(dh, enc ‖ pkR). */
function dhkemSecret(k, dh, enc, pkR) {
  const suite = Buffer.concat([Buffer.from('KEM'), u16(k.id)]);
  const prk = labeledExtract(k.hash, suite, Buffer.alloc(0), 'eae_prk', dh);
  return labeledExpand(k.hash, suite, prk, 'shared_secret', Buffer.concat([enc, pkR]), k.nsecret);
}

/** Serialized public key as HPKE wants it: NIST uncompressed, OKP raw. */
export function serializePub(k, raw) {
  return k.curve ? crypto.ECDH.convertKey(raw, k.curve, null, null, 'uncompressed') : raw;
}

/** Encapsulate to pkR (serialized). x: for X-Wing, an object { pkM, pkX }. Returns { ss, enc }. */
export function encap(name, pkR, x = null) {
  const k = KEMS[name];
  if (k.curve) {
    const e = crypto.createECDH(k.curve); e.generateKeys();
    const dh = e.computeSecret(pkR);
    const enc = e.getPublicKey();
    return { ss: dhkemSecret(k, dh, enc, pkR), enc };
  }
  if (k.okp) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync(k.okp);
    const dh = crypto.diffieHellman({ privateKey, publicKey: crypto.createPublicKey({ key: pkR, format: 'raw-public', asymmetricKeyType: k.okp }) });
    const enc = publicKey.export({ format: 'raw-public' });
    return { ss: dhkemSecret(k, dh, enc, pkR), enc };
  }
  if (k.kem) {
    const { sharedKey, ciphertext } = crypto.encapsulate(crypto.createPublicKey({ key: pkR, format: 'raw-public', asymmetricKeyType: k.kem }));
    return { ss: sharedKey, enc: ciphertext };
  }
  // X-Wing
  const { sharedKey: ssM, ciphertext: ctM } = crypto.encapsulate(crypto.createPublicKey({ key: x.pkM, format: 'raw-public', asymmetricKeyType: 'ml-kem-768' }));
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  const ctX = publicKey.export({ format: 'raw-public' });
  const ssX = crypto.diffieHellman({ privateKey, publicKey: crypto.createPublicKey({ key: x.pkX, format: 'raw-public', asymmetricKeyType: 'x25519' }) });
  return { ss: xwingCombine(ssM, ssX, ctX, x.pkX), enc: Buffer.concat([ctM, ctX]) };
}

export const xwingCombine = (ssM, ssX, ctX, pkX) => crypto.createHash('sha3-256').update(Buffer.concat([ssM, ssX, ctX, pkX, Buffer.from('5c2e2f2f5e5c', 'hex')])).digest();

/** DHKEM decap given our DH function and our serialized public key. */
export function dhkemDecap(name, dh, enc, pkRm) { return dhkemSecret(KEMS[name], dh, enc, pkRm); }

/** Base-mode key schedule: { key, nonce }. */
export function schedule(name, kdfName, aeadName, ss, info) {
  const kdf = KDFS[kdfName], aead = AEADS[aeadName];
  const suite = Buffer.concat([Buffer.from('HPKE'), u16(KEMS[name].id), u16(kdf.id), u16(aead.id)]);
  const pskIdHash = labeledExtract(kdf.hash, suite, Buffer.alloc(0), 'psk_id_hash', Buffer.alloc(0));
  const infoHash = labeledExtract(kdf.hash, suite, Buffer.alloc(0), 'info_hash', info);
  const ctxt = Buffer.concat([Buffer.from([0]), pskIdHash, infoHash]);
  const secret = labeledExtract(kdf.hash, suite, ss, 'secret', Buffer.alloc(0));
  return { key: labeledExpand(kdf.hash, suite, secret, 'key', ctxt, aead.nk), nonce: labeledExpand(kdf.hash, suite, secret, 'base_nonce', ctxt, 12) };
}

export function seal(aeadName, key, nonce, aad, pt) {
  const c = crypto.createCipheriv(AEADS[aeadName].cipher, key, nonce, { authTagLength: 16 });
  c.setAAD(aad, { plaintextLength: pt.length });
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
}
export function open(aeadName, key, nonce, aad, ct) {
  const d = crypto.createDecipheriv(AEADS[aeadName].cipher, key, nonce, { authTagLength: 16 });
  d.setAuthTag(ct.subarray(ct.length - 16));
  d.setAAD(aad, { plaintextLength: ct.length - 16 });
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
}

export const suiteHex = (name, kdf, aead) => [KEMS[name].id, KDFS[kdf].id, AEADS[aead].id].map((n) => n.toString(16).padStart(4, '0')).join('-');

/** Export-only context (AEAD 0xFFFF): Export(exporterContext, L) after SetupBase with `ss`. */
export function exportSecret(name, kdfName, ss, info, exporterContext, L) {
  const kdf = KDFS[kdfName];
  const suite = Buffer.concat([Buffer.from('HPKE'), u16(KEMS[name].id), u16(kdf.id), u16(0xffff)]);
  const pskIdHash = labeledExtract(kdf.hash, suite, Buffer.alloc(0), 'psk_id_hash', Buffer.alloc(0));
  const infoHash = labeledExtract(kdf.hash, suite, Buffer.alloc(0), 'info_hash', info);
  const ctxt = Buffer.concat([Buffer.from([0]), pskIdHash, infoHash]);
  const secret = labeledExtract(kdf.hash, suite, ss, 'secret', Buffer.alloc(0));
  const exporter = labeledExpand(kdf.hash, suite, secret, 'exp', ctxt, kdf.nh);
  return labeledExpand(kdf.hash, suite, exporter, 'sec', exporterContext, L);
}
