// ML-DSA beyond what node:crypto exposes: HashML-DSA (FIPS 204 5.4) and
// external mu (Alg. 7 line 6), through the OpenSSL 3.5 command line:
//   message-encoding:0  signs M' as it is (ML-DSA.Sign_internal), so M' can be the HashML-DSA one
//   mu:1                the input is mu itself

import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const OID = { 'HashML-DSA-SHA256': '0609608648016503040201', 'HashML-DSA-SHA384': '0609608648016503040202', 'HashML-DSA-SHA512': '0609608648016503040203' };

/** M' of HashML-DSA: 0x01 ‖ len(ctx) ‖ ctx ‖ OID(hash) ‖ digest. */
export function hashMessage(mode, ctx, digest) {
  const c = ctx ?? Buffer.alloc(0);
  return Buffer.concat([Buffer.from([1, c.length]), c, Buffer.from(OID[mode], 'hex'), digest]);
}

function run(args) {
  return new Promise((resolve) => execFile('openssl', args, { timeout: 30000 }, (err, stdout, stderr) => resolve({ ok: !err, out: String(stdout) + String(stderr) })));
}

async function withFiles(files, fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'mldsa-'));
  try {
    const p = {};
    for (const [name, data] of Object.entries(files)) { p[name] = path.join(dir, name); await fs.writeFile(p[name], data, { mode: 0o600 }); }
    return await fn(p, dir);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
}

/** Sign `input` (M' for HashML-DSA, or mu) with a private KeyObject. */
export async function signRaw(privKey, input, mu) {
  return withFiles({ 'k.pem': privKey.export({ format: 'pem', type: 'pkcs8' }), 'm.bin': input }, async (p, dir) => {
    const out = path.join(dir, 's.bin');
    const r = await run(['pkeyutl', '-sign', '-inkey', p['k.pem'], '-in', p['m.bin'], '-rawin', '-pkeyopt', mu ? 'mu:1' : 'message-encoding:0', '-out', out]);
    if (!r.ok) throw new Error(r.out);
    return fs.readFile(out);
  });
}

export async function verifyRaw(pubKey, input, sig, mu) {
  return withFiles({ 'p.pem': pubKey.export({ format: 'pem', type: 'spki' }), 'm.bin': input, 's.bin': sig }, async (p) => {
    const r = await run(['pkeyutl', '-verify', '-pubin', '-inkey', p['p.pem'], '-in', p['m.bin'], '-rawin', '-pkeyopt', mu ? 'mu:1' : 'message-encoding:0', '-sigfile', p['s.bin']]);
    return r.ok && /Verified Successfully/.test(r.out);
  });
}

export const randomName = () => crypto.randomBytes(6).toString('hex');

// ---- Ed25519ph / Ed448ph (RFC 8032 pre-hashed): OpenSSL hashes the message itself ----------
const edOpts = (alg, ctx) => ['-pkeyopt', `instance:${alg}`, ...(ctx ? ['-pkeyopt', `hexcontext-string:${ctx.toString('hex')}`] : [])];

export async function edphSign(privKey, alg, msg, ctx) {
  return withFiles({ 'k.pem': privKey.export({ format: 'pem', type: 'pkcs8' }), 'm.bin': msg }, async (p, dir) => {
    const out = path.join(dir, 's.bin');
    const r = await run(['pkeyutl', '-sign', '-inkey', p['k.pem'], '-in', p['m.bin'], '-rawin', ...edOpts(alg, ctx), '-out', out]);
    if (!r.ok) throw new Error(r.out);
    return fs.readFile(out);
  });
}
export async function edphVerify(pubKey, alg, msg, sig, ctx) {
  return withFiles({ 'p.pem': pubKey.export({ format: 'pem', type: 'spki' }), 'm.bin': msg, 's.bin': sig }, async (p) => {
    const r = await run(['pkeyutl', '-verify', '-pubin', '-inkey', p['p.pem'], '-in', p['m.bin'], '-rawin', ...edOpts(alg, ctx), '-sigfile', p['s.bin']]);
    return r.ok && /Verified Successfully/.test(r.out);
  });
}
