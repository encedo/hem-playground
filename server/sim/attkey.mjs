// The playground's attestation key: one P-256 key for every module, PPA and EPA,
// in the role of the secure element's device key. Its certificate is issued by
// the Encedo EPA Custody CA for *.<domain>, so attest.encedo.com knows the
// playground's profile - and nothing tells one module from another by it.
//
//   PG_ATT_KEY   the private key (PEM, or PEM in base64 on one line) - only in the
//                server's .env, never in Redis
//   PG_ATT_CERT  its certificate (public)
//
// Made by server/tools/make-att-csr.mjs. Without them each module signs with a
// key of its own (slot 0) and answers without a certificate.

import crypto from 'node:crypto';

function pem(v) {
  if (!v) return null;
  v = String(v).trim().replace(/^"|"$/g, '');
  if (v.includes('-----BEGIN')) return v.replace(/\\n/g, '\n');
  const t = Buffer.from(v, 'base64').toString('utf8');
  return t.includes('-----BEGIN') ? t : null;
}

let key = null, crt = null;
try {
  const k = pem(process.env.PG_ATT_KEY), c = pem(process.env.PG_ATT_CERT);
  if (k) key = crypto.createPrivateKey(k);
  if (c) {
    const x = new crypto.X509Certificate(c);
    if (key && x.checkPrivateKey(key)) crt = x.raw.toString('base64');
    else console.error('PG_ATT_CERT is not the certificate of PG_ATT_KEY: modules answer without a certificate');
  }
} catch (e) { console.error('PG_ATT_KEY / PG_ATT_CERT do not load:', e.message); key = null; crt = null; }

/** The shared attestation key, or null (each module then uses its own). */
export const sharedAttKey = () => key;
/** Its certificate, base64 DER, or null. */
export const sharedAttCert = () => crt;
