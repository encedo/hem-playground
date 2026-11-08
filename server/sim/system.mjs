// /api/system/*, /api/storage/*, /api/logger/*

import crypto from 'node:crypto';
import { hkdf, b64, unb64, unb64urlNoPad, jwtParse, jwtVerify, jwtSign, x25519, hmac, isPrintable, isHex32, sha, rand } from './codec.mjs';
import { fail, hasScope, scopes } from './http.mjs';
import { FW_VERSION, BL_VERSION, PUBLISHER, APP_PUBKEY, TRUSTED_BACKENDS, issueNonce, nonceValid, uptime, LOG, newBoot } from './device.mjs';
import { genuineToken, attestationJwt, slotKey, skid } from './attest.mjs';
import { sharedAttCert } from './attkey.mjs';
import * as K from './keys.mjs';
import * as H from './hpke.mjs';
import { hpkeDecap } from './crypto.mjs';

const isoTs = (s) => new Date(s * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');

export async function status(ctx) {
  const d = ctx.dev, b = ctx.boot;
  const j = {};
  if (!ctx.inited) j.inited = false;
  if (!ctx.tls) j.https = d.httpsUp !== false;   // after a factory wipe: false until the TLS bootstrap
  // the Host the client sent (the proxy picks the module by TLS name and passes the original in X-Orig-Host)
  const host = ('x-orig-host' in ctx.headers ? ctx.headers['x-orig-host'] : ctx.headers.host ?? '').toLowerCase();
  const hn = (d.cfg?.hostname ?? d.hostname ?? '').toLowerCase();
  if (!hn || !host.startsWith(hn)) j.hostname = d.cfg?.hostname ?? d.hostname;
  if (!d.cfg?.trusted_ts) j.tts = false;
  j.ctx = d.cfg?.ctx ?? 0;
  j.uptime = uptime(b);
  if (b.rtcSet) { j.ts = isoTs(ctx.now); j.time = ctx.now; }
  if (ctx.ppa) {
    j.storage = d.storage.map((x) => `${x.sectors - 1}:${x.mode}`);
    if (d.inited && b.busyUntil) {
      if (Date.now() < b.busyUntil) { b.formatPolls++; j.format = `status${Math.min(b.formatPolls, 9)}`; ctx.touch('boot'); } else j.format = 'done';
    }
  }
  j.temp = 31 + (b.n % 7);
  j.fls_state = d.fls;
  j.cc_mode = d.cfg?.cc_mode ?? 0;
  if (b.fwUpgraded) j.fw_upgrade = true;
  return { json: j };
}

export function versionJson(ctx) {
  const d = ctx.dev;
  const j = { hwv: d.variant === 'PPA' ? 'PPA rev 2.2' : `EPA rev 1.0 @${d.devid}`, fwv: d.fwv ?? FW_VERSION, fwk: b64(PUBLISHER), fws: d.fws, blv: BL_VERSION, blk: b64(PUBLISHER), bls: d.bls };
  if (ctx.ppa) j.uis = d.uis;
  return j;
}
export async function version(ctx) {
  const j = versionJson(ctx);
  if (ctx.ppa && (!ctx.inited || ctx.token)) { j.sd_csd = sha('md5', ctx.dev.devid, 'csd').toString('hex'); j.sd_cid = sha('md5', ctx.dev.devid, 'cid').toString('hex'); }
  return { json: j };
}

export async function selftest(ctx) {
  if (ctx.inited) { ctx.needToken(); await ctx.needScope(['system:config']); }
  if ((ctx.boot.selftestUntil ?? 0) > Date.now()) fail(409);       // one run at a time
  ctx.boot.selftestUntil = Date.now() + 1500; ctx.touch('boot');
  const keys = await ctx.keys();
  const last = ctx.dev.selftestTs ?? 0;
  ctx.dev.selftestTs = ctx.now; ctx.touch('dev');
  await ctx.log(LOG.SELFTEST_PASSED, ctx.dev.fls ? 1 : 0);
  const j = { last_selftest_ts: last, last_fls_state: ctx.dev.fls, last_entropytest_ts: ctx.now - uptime(ctx.boot), last_kat_ts: ctx.now - uptime(ctx.boot),
    fls_state: ctx.dev.fls, selftest_ts: ctx.now, cc_mode: ctx.dev.cfg?.cc_mode ?? 0, fls_raw: 0,
    selftests: { kat: true, trng: true, temp: true, integrity: true },
    repo_stats: { total: keys.length, deleted: ctx.dev.deletedKeys ?? 0, invalid: 0, fragmented: 0, freeslots: Math.max(0, (ctx.settings.keysPerModule ?? 512) - keys.length) } };
  if (ctx.ppa) j.se_state = 0;
  return { json: j, delay: 1500 };
}

// ---- check-in with the Encedo backend -------------------------------------------------------
const checkKey = (ctx) => x25519(Buffer.from(ctx.boot.session.priv, 'base64'), APP_PUBKEY);

export async function getCheckin(ctx) {
  const c = { jti: issueNonce(ctx.boot, 600), iss: ctx.boot.session.pub, qid: ctx.boot.qid, aud: b64(APP_PUBKEY), fws: ctx.dev.fws, bls: ctx.dev.bls };
  if (ctx.ppa) c.uis = ctx.dev.uis;
  ctx.touch('boot');
  return { json: { check: jwtSign(c, checkKey(ctx), { ecdh: 'x25519' }) } };
}

export async function postCheckin(ctx) {
  if (!ctx.body || typeof ctx.body.checked !== 'string') fail(400);
  const key = checkKey(ctx);
  const p = jwtParse(ctx.body.checked);
  const pl = p && jwtVerify(p, key, ctx.now);
  if (!pl) fail(401);
  if (!nonceValid(ctx.boot, pl.jti)) fail(401);
  if (!TRUSTED_BACKENDS.includes(pl.iss)) fail(401);
  const st = unb64(pl.status);
  if (!st || st.length !== 32) fail(400);
  const qid = Buffer.from(ctx.boot.qid, 'base64');
  let status = '???';
  for (const a of ['', 'L', 'W', 'R', 'B', 'U']) if (hmac('sha256', key, qid, a).equals(st)) status = a || 'OK';
  const j = { status };
  if (pl.newcrt !== undefined) j.newcrt = 'ERROR';
  if (pl.newfws !== undefined) j.newfws = pl.newfws;
  if (pl.newuis !== undefined && ctx.ppa) j.newuis = pl.newuis;
  if (typeof pl.iat === 'number' && pl.iat) { ctx.boot.rtcSet = true; ctx.touch('boot'); }
  // Remote actions are reported, never run: a playground module is not to be locked or wiped by the backend.
  return { json: j };
}

// ---- configuration -------------------------------------------------------------------------
export async function getConfig(ctx) {
  ctx.needToken();
  await ctx.needScope(['system:config', 'logger:get', 'auth:ext:pair']);
  const d = ctx.dev, c = d.cfg ?? {};
  const j = { iat: d.inited, uts: d.uts, instanceid: d.instanceid, eid: d.eid.pub, eid_sign: d.eidSign.pub,
    user: c.user ?? '', email: c.email ?? '', hostname: c.hostname ?? d.hostname, dnsd: !!c.dnsd, trusted_ts: !!c.trusted_ts,
    trusted_backend: !!c.trusted_backend, allow_keysearch: c.allow_keysearch ?? true, policy: c.policy ?? [], origin: c.origin ?? '*',
    ctx: c.ctx ?? 0, ip: c.ip ?? '192.168.7.1/24', http_option_hsts: c.http_option_hsts ?? true, http_option_dosprot_mode: c.http_option_dosprot_mode ?? 0 };
  if (ctx.ppa) Object.assign(j, { genuine_id: d.genuineId, storage_mode: c.storage_mode ?? 0, storage_disk0size: d.storage[0].sectors, storage_capacity: d.storage[0].sectors + d.storage[1].sectors });
  j.spk = ctx.boot.session.pub;
  j.nonce = issueNonce(ctx.boot, 300);
  ctx.touch('boot');
  return { json: j };
}

export async function postConfig(ctx) {
  if (ctx.boot.installing) fail(409);
  const b = ctx.body;
  if (!ctx.inited) {
    if (!b) fail(400);
    if (!b.tls) fail(406);
    ctx.dev.httpsUp = true; ctx.touch('dev');            // the bootstrap starts HTTPS
    return {};
  }
  ctx.needToken();
  await ctx.needScope(['system:config']);
  if (!b) fail(400);
  if ('policy' in b) fail(400);
  if (typeof b.wipeout === 'boolean' || typeof b.wipeout === 'string') {
    if (b.wipeout === false || (typeof b.wipeout === 'string' && b.wipeout !== 'factory')) fail(400);
    ctx.wipe = b.wipeout === 'factory' ? 'factory' : 'classic';   // done by the caller: config and keys go, a new boot starts
    return { close: true };
  }
  if (b.tls !== undefined) fail(400);                  // a playground module keeps the certificate of its domain
  const c = { ...ctx.dev.cfg };
  let bad = false;
  const setStr = (f, max) => { if (b[f] !== undefined) { if (isPrintable(b[f], 1, max)) c[f] = b[f]; else bad = true; } };
  const setBool = (f) => { if (b[f] !== undefined) { if (typeof b[f] === 'boolean') c[f] = b[f]; else bad = true; } };
  setStr('user', 63); setStr('email', 63); setStr('origin', 127);
  setBool('trusted_ts'); setBool('trusted_backend'); setBool('allow_keysearch'); setBool('http_option_hsts');
  if (b.ctx !== undefined) { if (Number.isInteger(b.ctx)) c.ctx = b.ctx; else bad = true; }
  if (b.http_option_dosprot_mode !== undefined) { if (Number.isInteger(b.http_option_dosprot_mode) && b.http_option_dosprot_mode >= 0 && b.http_option_dosprot_mode <= 4) c.http_option_dosprot_mode = b.http_option_dosprot_mode; else bad = true; }
  if (ctx.ppa) {
    setBool('dnsd');
    // DEV-499 B2: Disk0 nibble 0x00 / 0x01 / 0x03, Disk1 nibble 0x50 (AES-CTR) / 0xA0 (AES-XTS)
    const okMode = (v) => Number.isInteger(v) && [0x00, 0x01, 0x03].includes(v & 0x0f) && [0x50, 0xa0].includes(v & 0xf0) && v <= 0xff;
    if (b.storage_mode !== undefined) { if (okMode(b.storage_mode)) c.storage_mode = b.storage_mode; else bad = true; }
    if (b.storage_disk0size !== undefined) {
      const total = ctx.dev.storage[0].sectors + ctx.dev.storage[1].sectors;
      if (Number.isInteger(b.storage_disk0size) && b.storage_disk0size >= 1 && b.storage_disk0size < total) {
        c.storage_disk0size = b.storage_disk0size;
        ctx.dev.storage[0].sectors = b.storage_disk0size; ctx.dev.storage[1].sectors = total - b.storage_disk0size;
      } else bad = true;
    }
  }
  if (b.userkey !== undefined && b.userkey_hmac !== undefined && b.userkey_nonce !== undefined) {
    const uk = unb64(b.userkey), mac = unb64(b.userkey_hmac), nonce = unb64(b.userkey_nonce);
    if (uk?.length === 32 && mac?.length === 32 && nonce?.length === 32 && nonceValid(ctx.boot, b.userkey_nonce)) {
      const k = x25519(Buffer.from(ctx.boot.session.priv, 'base64'), uk);
      if (k && hmac('sha256', k, nonce).equals(mac)) { c.userkey = b.userkey; ctx.dev.userLocked = false; }
    }
  }
  const changed = JSON.stringify(c) !== JSON.stringify(ctx.dev.cfg);
  if (!changed && bad) fail(400);
  const j = { updated: changed };
  if (changed) { ctx.dev.cfg = c; ctx.dev.uts = ctx.now; ctx.touch('dev'); await ctx.log(LOG.CONFIG_UPDATED, 0, ctx.token.sub); }
  return { json: j };
}

// ---- attestation ---------------------------------------------------------------------------
export async function getAttestation(ctx, rest) {
  let nonce = null;
  if (rest !== '') {
    if (!rest.startsWith('/')) fail(404);
    const n = unb64urlNoPad(rest.slice(1));
    if (!n || n.length < 32 || n.length > 64) fail(400);
    nonce = rest.slice(1);
  }
  if (ctx.inited && !ctx.token) fail(401);
  if (ctx.boot.installing || ctx.fls) fail(409);
  // the certificate of the shared device key, on PPA and - as an exception to the firmware, where an EPA
  // returns the CSR of its attestation key - on EPA too
  const crt = sharedAttCert();
  const j = {};
  if (crt) j.crt = crt;
  j.genuine = genuineToken(ctx.dev, nonce);
  return { json: j };
}

function seq(...fields) {
  return Buffer.concat(fields.map((f) => { const b = Buffer.from(f); const l = Buffer.alloc(2); l.writeUInt16BE(b.length); return Buffer.concat([l, b]); }));
}

export async function postAttestation(ctx) {
  const b = ctx.body;
  if (!b) fail(400);
  const nonce = unb64(b.nonce);
  if (!nonce || nonce.length < 32 || nonce.length > 64 || !isPrintable(b.aud, 1, 64)) fail(400);
  if (b.kid !== undefined && !isHex32(b.kid)) fail(400);
  if (b.pop_args !== undefined && (typeof b.pop_args !== 'object' || b.pop_args === null || Array.isArray(b.pop_args) || b.kid === undefined)) fail(400);
  if (b.kid !== undefined) {
    if (!ctx.token || ctx.token.sub == null || ctx.token.sub === 'M' || !hasScope(ctx.token, `keymgmt:use:${b.kid}`)) { await ctx.log(LOG.FAILED_SCOPE_CHECK, 1, ctx.token?.sub ?? '', `keymgmt:use:${b.kid}`); fail(403); }
    ctx.needTls();
  } else if (ctx.inited && !ctx.token) fail(401);
  if (ctx.boot.installing || ctx.fls) fail(409);
  const v = versionJson(ctx);
  const body = { iss: 'https://attest.encedo.com', aud: b.aud, iat: ctx.now, exp: ctx.now + 300, nonce: b.nonce, jti: crypto.randomUUID(),
    device: { hwv: v.hwv, fwv: v.fwv, blv: v.blv, assurance: ctx.ppa ? 'hard' : 'soft', cc_mode: ctx.dev.cfg?.cc_mode ?? 0, policy: ctx.dev.cfg?.policy ?? [] } };
  let k = b.kid ? await ctx.key(b.kid) : null;
  if (k?.der) k = null;                                   // a generic DER record: a token without a key block
  if (b.pop_args && (!k || !K.isAsym(k.type) || !k.pkey)) fail(400);
  if (k) {
    const modes = k.hpke ? (k.type in K.MLKEM ? ['HPKE', 'MLKEM'] : ['HPKE']) : K.NIST.includes(k.type) || k.type in K.MONT || k.type in K.EDW
      ? [k.exdsa && 'ExDSA', k.ecdh && 'ECDH'].filter(Boolean) : k.type in K.MLDSA ? ['MLDSA'] : k.type in K.MLKEM ? ['MLKEM'] : k.type in K.HMACK ? ['HMAC'] : k.type === 'SHA1' ? ['OTP'] : ['AES'];
    const key = { kid: k.kid, type: k.type, modes };
    if (K.isAsym(k.type)) {
      key.pubkey = { primary: k.pub };
      if (k.type === 'ED25519' && k.ecdh) key.pubkey.derived = b64(K.derivedX25519(k));
      key.properties = { privatekey: k.pkey, derived: !k.att };
    } else key.properties = { derived: !k.att };
    key.created = k.created; key.updated = k.updated;
    if (b.include_metadata) { key.label = k.label; if (k.descr) key.descr = k.descr; }
    body.key = key;
    if (b.pop_args) body.pop = pop(k, b, nonce);
  }
  await ctx.log(LOG.SYSTEM_ATTESTATION, 0, ctx.token?.sub ?? '', b.kid ?? '');
  return { json: { attestation: attestationJwt(ctx.dev, body) } };
}

function pop(k, b, nonce) {
  const pa = b.pop_args, pub = Buffer.from(k.pub, 'base64');
  if ([pa.verifier_eph_pub, pa.ciphertext, pa.enc].filter((x) => x !== undefined).length > 1) fail(400);
  if (k.hpke) {
    // DEV-503: HPKE PoP - the verifier set up an export-only context to the key and sent its enc
    const enc = pa.enc !== undefined ? unb64(pa.enc) : null;
    const kemName = H.KEM_BY_TYPE[k.type], K_ = H.KEMS[kemName];
    if (!enc || enc.length !== K_.enc) fail(400);
    const info = seq('encedo-attest-pop:v1:hpke', b.aud, H.serializePub(K_, pub), nonce);
    let ss; try { ss = hpkeDecap(kemName, k, null, enc); } catch { fail(400); }
    return { export: b64(H.exportSecret(kemName, K_.kdf, ss, info, Buffer.from('pop'), 32)) };
  }
  if (pa.enc !== undefined) fail(400);
  const mac = (ss, info, rest) => {
    const key = hkdf('sha256', ss, nonce, info, 32);
    return { mac: b64(hmac('sha256', key, Buffer.concat([info, rest]))) };
  };
  if (pa.verifier_eph_pub !== undefined) {
    const eph = unb64(pa.verifier_eph_pub);
    if (!eph || !k.ecdh || k.type === 'ED25519' || eph.length !== K.peerLen(k)) fail(400);
    let ss; try { ss = K.ecdh(k, eph); } catch { fail(400); }
    const info = seq('encedo-attest-pop:v1:ecdh', b.aud, pub);
    return mac(ss, info, seq(nonce, eph));
  }
  if (pa.ciphertext !== undefined) {
    const ct = unb64(pa.ciphertext);
    if (!ct || !(k.type in K.MLKEM) || ct.length !== K.KEM_CT[k.type]) fail(400);
    const ss = crypto.decapsulate(K.privateKeyObject(k), ct);
    const info = seq('encedo-attest-pop:v1:kem', b.aud, pub);
    return mac(ss, info, seq(nonce, sha('sha256', ct)));
  }
  const msg = seq('encedo-attest-pop:v1:sig', b.aud, pub, nonce);
  if (K.NIST.includes(k.type) && k.exdsa) return { signature: b64(crypto.sign(K.CURVE_HASH(k.type), msg, { key: K.privateKeyObject(k), dsaEncoding: 'ieee-p1363' })) };
  if (k.type in K.EDW || k.type in K.MLDSA) return { signature: b64(crypto.sign(null, msg, K.privateKeyObject(k))) };
  fail(400);
}

export async function provisioning(ctx) {
  if (!ctx.ppa) fail(404);
  if (ctx.inited || ctx.boot.installing || ctx.fls) fail(409);
  fail(406);                                            // the certificate is stored when the module is made
}

// ---- upgrade / reboot / shutdown / defrag ---------------------------------------------------
async function upgradeAccess(ctx) {
  if (ctx.inited) { ctx.needToken(); await ctx.needScope(['system:upgrade', 'system:config']); }
}

export async function upload(ctx, kind) {
  if (!ctx.ppa) fail(400);
  if (ctx.inited) { ctx.needToken(); await ctx.needScope(['system:upgrade']); }
  const name = ctx.uploadName;
  if (kind === 'fw') {
    if (!/\.(bin|hex)$/i.test(name)) fail(400, { close: true });
    if (ctx.uploadSize >= 3 * 1024 * 1024) fail(413, { close: true });
  } else if (name.toLowerCase() !== 'webroot.tar') fail(400, { close: true });
  await ctx.readUpload();
  ctx.dev.upgrade[kind] = { name, size: ctx.raw.length, ok: ctx.raw.length > 0 && ctx.raw[0] !== 0xff, polls: 0, state: 'uploaded' };
  ctx.touch('dev');
  return {};
}

export async function upgrade(ctx, sub) {
  await upgradeAccess(ctx);
  const u = ctx.dev.upgrade;
  const check = (kind) => {
    const f = u[kind];
    if (!f) { if (kind === 'fw') fail(404); return { status: 201 }; }
    if (f.state === 'uploaded') { f.state = 'checking'; f.polls = 0; ctx.touch('dev'); return { status: 201 }; }
    if (f.state === 'checking') {
      if (++f.polls < 2) { ctx.touch('dev'); return { status: 202 }; }
      f.state = f.ok ? 'passed' : 'failed'; ctx.touch('dev');
    }
    if (f.state === 'failed') fail(406);
    return { status: 200 };
  };
  switch (sub) {
    case '/check_fw': if (!ctx.ppa) fail(404); return check('fw');
    case '/check_ui': if (!ctx.ppa) fail(404); return check('ui');
    case '/install_fw':
      if (!ctx.ppa) fail(404);
      if (u.fw?.state !== 'passed') fail(409);
      u.fw = null; ctx.reboot = { fwUpgraded: true };
      await ctx.log(LOG.UPGRADE, 0, ctx.token?.sub ?? '');
      ctx.touch('dev');
      return { close: true };
    case '/install_ui':
      if (!ctx.ppa) fail(404);
      if (u.ui?.state !== 'passed') { await ctx.log(LOG.UPGRADE, 1, ctx.token?.sub ?? ''); fail(406); }
      u.ui = null; ctx.dev.uis = b64(rand(32)); ctx.touch('dev');
      await ctx.log(LOG.UPGRADE, 0, ctx.token?.sub ?? '');
      return {};
    case '/usbmode':
      ctx.reboot = {}; await ctx.log(LOG.UPGRADE, 0, ctx.token?.sub ?? '');
      return { close: true };
    default: fail(404);
  }
}

export async function reboot(ctx) {
  if (ctx.boot.installing) fail(409);
  if (ctx.inited) { ctx.needToken(); await ctx.needScope(['system:config', 'system:upgrade', 'system:shutdown'], { logScope: 'system:shutdown' }); }
  await ctx.log(LOG.REBOOT, 0, ctx.token?.sub ?? '');
  ctx.reboot = {};
  return { close: true };
}

export async function shutdown(ctx) {
  if (ctx.boot.installing) fail(409);
  ctx.needToken();
  await ctx.needScope(['system:config', 'system:shutdown']);
  await ctx.log(LOG.SHUTDOWN, 0, ctx.token.sub);
  ctx.boot.shutdown = true; ctx.touch('boot');
  return { close: true };
}

async function defragReport(ctx) {
  if (ctx.boot.installing || !ctx.inited) fail(409);
  ctx.needToken();
  await ctx.needScope(['system:config']);
  const keys = await ctx.keys();
  const del = ctx.dev.deletedKeys ?? 0;
  const delSize = ctx.dev.deletedBytes ?? 0;
  return { used: keys.reduce((s, k) => s + 160 + (k.pub ? k.pub.length : 0), 0) + delSize, keys: keys.length, deleted: del, deleted_size: delSize,
    invalid: 0, duplicates: 0, reclaimable: delSize >= 8192, reclaimable_size: delSize >= 8192 ? delSize : 0, reserved: 'idle' };
}
export async function defragCheck(ctx) { return { json: await defragReport(ctx) }; }
export async function defragStart(ctx) {
  const r = await defragReport(ctx);
  if (!r.reclaimable) return { json: r };
  ctx.dev.deletedKeys = 0; ctx.dev.deletedBytes = 0; ctx.touch('dev');
  ctx.reboot = {};
  return { status: 202, json: r, close: true };
}

// ---- storage (PPA) -------------------------------------------------------------------------
async function storageAccess(ctx) {
  if (!ctx.ppa) fail(404);
  if (ctx.fls || !ctx.inited || ctx.busy) fail(409);
  ctx.needToken();
  const s = scopes(ctx.token).find((x) => x.startsWith('storage:disk'));
  if (!s || ctx.token.sub === 'M') { await ctx.log(LOG.FAILED_SCOPE_CHECK, 1, ctx.token.sub, 'storage:disk'); fail(403); }
  const m = /^storage:disk(\d)(:rw|:ro)?$/.exec(s);
  if (!m || Number(m[1]) > 1) fail(403);
  return { disk: Number(m[1]), rw: m[2] === ':rw' };
}
export async function unlock(ctx, suffix) {
  if (!['', '/rw', '/ro'].includes(suffix)) { if (!ctx.ppa) fail(404); fail(404); }
  const { disk, rw } = await storageAccess(ctx);
  if (suffix === '/rw' && !rw) fail(403);
  const mode = suffix === '/ro' ? 'ro' : suffix === '/rw' ? 'rw' : rw ? 'rw' : 'ro';
  ctx.dev.storage[disk].mode = mode; ctx.touch('dev');
  await ctx.log(LOG.STORAGE_UNLOCK, 0, ctx.token.sub, `${disk}${mode}`);
  return {};
}
export async function lock(ctx) {
  const { disk } = await storageAccess(ctx);
  ctx.dev.storage[disk].mode = '-'; ctx.touch('dev');
  await ctx.log(LOG.STORAGE_LOCK, 0, ctx.token.sub, String(disk));
  return {};
}

// ---- audit log -----------------------------------------------------------------------------
async function loggerAccess(ctx) {
  if (!ctx.inited || ctx.busy) fail(409);
  ctx.needToken();
  await ctx.needScope(['logger:get']);
}
export async function loggerKey(ctx, seg = null) {
  await loggerAccess(ctx);
  let nonce;
  if (seg !== null) {
    nonce = unb64urlNoPad(seg);
    if (!nonce || nonce.length < 32 || nonce.length > 64) fail(400);
  } else { nonce = Buffer.from(issueNonce(ctx.boot), 'base64'); ctx.touch('boot'); }
  const k = crypto.createPrivateKey({ key: Buffer.from(ctx.dev.logKey.priv, 'base64'), format: 'der', type: 'pkcs8' });
  return { json: { key: ctx.dev.logKey.pub, nonce: b64(nonce), nonce_signed: b64(crypto.sign(null, nonce, k)) } };
}
export async function loggerRest(ctx, rest) {
  if (rest.startsWith('key/')) return loggerKey(ctx, rest.slice(4));
  await loggerAccess(ctx);
  if (!ctx.ppa) fail(404);
  const ids = (await ctx.store.fields(ctx.prefix, 'audit:*')).map(([f]) => f.slice(6)).filter((id) => id !== ctx.boot.logId).sort();
  if (rest === 'list' || rest.startsWith('list/')) {
    const m = /^list(?:\/(\d{1,9})(?:\/(\d{1,9}))?)?$/.exec(rest);
    if (!m) fail(400);
    const offset = Number(m[1] ?? 0), limit = Math.min(Number(m[2] ?? 128), 128);
    if (m[2] !== undefined && limit === 0) fail(400);
    const page = ids.slice(offset, offset + limit);
    const j = { offset, total: ids.length, listed: page.length };
    if (ids.length) { j.oldest = ids[0]; j.newest = ids.at(-1); }
    j.current = ctx.boot.logId;
    j.id = page;
    await ctx.log(LOG.LOGGER_LIST_LOG, 0, ctx.token.sub);
    return { json: j };
  }
  if (!/^[0-9a-fA-F]{8}$/.test(rest)) { if (rest === '') fail(404); fail(400); }
  const id = rest.toLowerCase();
  if (id === ctx.boot.logId) fail(409);
  const f = await ctx.store.get(ctx.prefix, `audit:${id}`);
  if (!f) fail(404);
  await ctx.log(LOG.LOGGER_READ_LOG, 0, ctx.token.sub, id);
  return { text: f.lines.join('\n') + '\n' };
}

export { newBoot };
