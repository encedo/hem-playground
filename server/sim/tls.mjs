// The system TLS records a personalised module carries in its key repository:
// "TLS PrivateKey" (ATT,PKEY,GENERIC_DER, descr DNS:<hostname>) and
// "TLS Certificate" (CERT,GENERIC_DER). On a playground module TLS is ended by
// the proxy, so the certificate here is a self-signed one for the hostname; the
// records are what the Manager and hem-api-tester expect to find (T-15.13).

import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { b64, sha } from './codec.mjs';

const run = (args) => new Promise((resolve, reject) => execFile('openssl', args, { timeout: 15000 }, (e, so, se) => (e ? reject(new Error(String(se))) : resolve())));

/** KID of a generic DER record: SHA-1 of the 2-byte DER length (little-endian) and the DER (DEV-501). */
const derKid = (der) => { const l = Buffer.alloc(2); l.writeUInt16LE(der.length); return sha('sha1', l, der).subarray(0, 16).toString('hex'); };

/** { key, cert, csr } records / CSR for `hostname`, built with OpenSSL (PKCS#10 v1, version 0). */
export async function tlsRecords(hostname, email, now) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const keyDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  const jwk = publicKey.export({ format: 'jwk' });
  const y = Buffer.from(jwk.y, 'base64url');
  const point = Buffer.concat([Buffer.from([y[31] & 1 ? 3 : 2]), Buffer.from(jwk.x, 'base64url')]);
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'tls-'));
  try {
    const k = path.join(dir, 'k.pem');
    await fs.writeFile(k, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
    const subj = `/C=UK/O=Encedo Limited/OU=EncedoKey/CN=${hostname}/emailAddress=${email}`;
    const san = `subjectAltName=DNS:${hostname}`;
    await run(['req', '-new', '-x509', '-key', k, '-subj', subj, '-addext', san, '-days', '825', '-sha256', '-outform', 'DER', '-out', path.join(dir, 'c.der')]);
    await run(['req', '-new', '-key', k, '-subj', subj, '-addext', san, '-sha256', '-outform', 'DER', '-out', path.join(dir, 'r.der')]);
    const certDer = await fs.readFile(path.join(dir, 'c.der'));
    const csr = await fs.readFile(path.join(dir, 'r.der'));
    const descr = b64(Buffer.from(`DNS:${hostname}`));
    const base = { type: 'GENERIC_DER', der: true, ecdh: false, exdsa: false, hpke: false, descr, created: now, updated: now };
    return {
      key: { ...base, kid: derKid(keyDer), label: 'TLS PrivateKey', att: true, pkey: true, cert: false, priv: b64(keyDer), pub: b64(point) },
      cert: { ...base, kid: derKid(certDer), label: 'TLS Certificate', att: false, pkey: false, cert: true, priv: null, pub: null, certDer: b64(certDer) },
      csr: b64(csr),
    };
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
}
