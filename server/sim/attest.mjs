// The secure element, simulated: slot 0 is the device key (its certificate comes
// from the playground's own test CA, so nothing here passes as genuine Encedo
// hardware), slot 1 the attestation key.

import crypto from 'node:crypto';
import { b64, b64url, sha } from './codec.mjs';

export const slotKey = (pkcs8b64) => crypto.createPrivateKey({ key: Buffer.from(pkcs8b64, 'base64'), format: 'der', type: 'pkcs8' });
/** 04‖X‖Y of a P-256 key. */
export function rawPoint(priv) {
  const j = crypto.createPublicKey(priv).export({ format: 'jwk' });
  return Buffer.concat([Buffer.from([4]), Buffer.from(j.x, 'base64url'), Buffer.from(j.y, 'base64url')]);
}
export const skid = (priv) => sha('sha1', rawPoint(priv));

/** Device attestation token: [nonce.]SKID.TS.SIG, SIG = ES256 raw r‖s by slot 0. */
export function genuineToken(dev, nonce = null, now = Math.floor(Date.now() / 1000)) {
  const k = slotKey(dev.slot0);
  const ts = String(now + 60);
  const head = `${b64(skid(k))}.${b64(Buffer.from(ts))}`;
  if (nonce == null) return `${head}.${b64(crypto.sign('sha256', Buffer.from(ts), { key: k, dsaEncoding: 'ieee-p1363' }))}`;
  const text = `${nonce}.${head}`;
  return `${text}.${b64(crypto.sign('sha256', Buffer.from(text), { key: k, dsaEncoding: 'ieee-p1363' }))}`;
}

/** ES256 attestation JWT signed by slot 0. */
export function attestationJwt(dev, body) {
  const k = slotKey(dev.slot0);
  const j = crypto.createPublicKey(k).export({ format: 'jwk' });
  const header = { alg: 'ES256', typ: 'encedo-attest+jwt', kid: skid(k).toString('hex'), jwk: { kty: 'EC', crv: 'P-256', x: j.x, y: j.y } };
  const signed = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(Buffer.from(JSON.stringify(body)))}`;
  return `${signed}.${b64url(crypto.sign('sha256', Buffer.from(signed), { key: k, dsaEncoding: 'ieee-p1363' }))}`;
}
