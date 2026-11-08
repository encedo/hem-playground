// The playground's attestation key and the CSR for its certificate (see sim/attkey.mjs).
// Prints two things: the line PG_ATT_KEY=... for the .env, then the CSR (PEM) to be
// signed by the Encedo EPA Custody CA. Run it where the .env lives and keep the key
// line there; only the CSR leaves.
//   node server/tools/make-att-csr.mjs <domain>
// The CSR is a secure element's, as the CA's tooling expects it: PKCS#10 v1
// (version 0), P-256, subject C=UK, O=Encedo Ltd, CN=#<serial>, and in the SAN the
// otherName 1.3.6.1.4.1.56231.1 (SHA-1 of 04||X||Y of the key) and dNSName *.<domain>.
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const domain = (process.argv[2] ?? process.env.DOMAIN ?? '').toLowerCase();
if (!/^[a-z0-9][a-z0-9.-]*$/.test(domain)) { console.error('usage: node server/tools/make-att-csr.mjs <domain>'); process.exit(2); }
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const j = publicKey.export({ format: 'jwk' });
const skid = crypto.createHash('sha1').update(Buffer.concat([Buffer.from([4]), Buffer.from(j.x, 'base64url'), Buffer.from(j.y, 'base64url')])).digest('hex');
const serial = `0123${crypto.randomBytes(7).toString('hex')}`;          // the shape of an ATECC serial
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-'));
try {
  const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.cnf');
  const keyPem = privateKey.export({ format: 'pem', type: 'pkcs8' });
  fs.writeFileSync(k, keyPem, { mode: 0o600 });
  // '#' starts a comment in an OpenSSL config, hence '\#'
  fs.writeFileSync(c, ['[req]', 'distinguished_name = dn', 'req_extensions = ext', 'prompt = no', '[dn]', 'C = UK', 'O = Encedo Ltd', `CN = \\#${serial}`,
    '[ext]', 'subjectAltName = @alt', '[alt]', `otherName.1 = 1.3.6.1.4.1.56231.1;FORMAT:HEX,OCT:${skid}`, `DNS.1 = *.${domain}`, ''].join('\n'));
  const csr = execFileSync('openssl', ['req', '-new', '-key', k, '-config', c, '-sha256'], { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  process.stdout.write(`PG_ATT_KEY=${Buffer.from(keyPem).toString('base64')}\n`);
  process.stdout.write(`# SKID ${skid}, CN #${serial}, DNS *.${domain}\n${csr}`);
} finally { fs.rmSync(dir, { recursive: true, force: true }); }
