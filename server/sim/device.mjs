// One virtual module's state: what it keeps across power cycles (dev), what a
// power cycle resets (boot), and the audit log it writes.

import crypto from 'node:crypto';
import { b64, b64url, hex, rand, x25519NewRaw, hmac } from './codec.mjs';

export const FW_VERSION = 'Encedo nGINE FW v1.3.2-sim';
export const BL_VERSION = 'Encedo Secure Bootloader v2.0.2';
// The release footer of the firmware the playground pretends to run: the
// application X25519 key the check-in is keyed with, and the publisher key.
export const APP_PUBKEY = Buffer.from('fcb6f1a3932053a64eb55b31c46e63090e7ee1ec31a1ad6b57c7aa3081459d30', 'hex');
export const PUBLISHER = Buffer.from('b15be87ccb5de4f9c6c18d62dc63864fdc558b4f5062221f75127d52c10f7aea', 'hex');
export const TRUSTED_BACKENDS = ['/Lbxo5MgU6ZOtVsxxG5jCQ5+4ewxoa1rV8eqMIFFnTA=', 'HZgDdk8pYjtLQCunwz/KTnwpFA3ELGlkIjKbxMyrEwI='];
export const SD_SECTORS = 31116288;                 // a 16 GB card, as a PPA has
const NONCE_KEEP = 256;

const edPair = () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return { priv: b64(privateKey.export({ format: 'der', type: 'pkcs8' })), pub: b64(publicKey.export({ format: 'der', type: 'spki' }).subarray(12)) };
};
const p256Pair = () => {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return b64(privateKey.export({ format: 'der', type: 'pkcs8' }));
};

/** A module straight out of the box. */
export function newDevice(variant = 'PPA') {
  const eid = x25519NewRaw();
  return {
    variant,
    devid: hex(rand(8)),
    instanceid: crypto.randomUUID(),
    eid: { priv: b64(eid.priv), pub: b64(eid.pub) },
    eidSign: edPair(),
    logKey: edPair(),
    slot0: p256Pair(),             // the secure element's device key (playground CA signs its certificate)
    slot1: p256Pair(),             // the attestation key
    genuineId: hex(rand(9)),
    qidSeed: b64(rand(32)),
    uis: b64(rand(32)),
    fws: b64(rand(64)),
    bls: b64(rand(64)),
    inited: 0,                     // init time; 0 = in the box
    uts: 0,
    cfg: null,
    fls: 0,
    storage: variant === 'PPA' ? [{ sectors: 8388608, mode: '-' }, { sectors: SD_SECTORS - 8388608 - 2, mode: '-' }] : null,
    upgrade: { fw: null, ui: null },
    selftestTs: 0,
    bootCount: 0,
  };
}

/** A power cycle: new session key, no nonces, uptime from zero. */
export function newBoot(dev) {
  const s = x25519NewRaw();
  dev.bootCount = (dev.bootCount ?? 0) + 1;
  for (const d of dev.storage ?? []) d.mode = '-';
  const started = Date.now();
  return {
    n: dev.bootCount,
    started,
    session: { priv: b64(s.priv), pub: b64(s.pub) },
    tokenKey: b64(rand(32)),       // HS256 key of issued bearer tokens
    qid: b64(hmac('sha256', Buffer.from(dev.qidSeed, 'base64'), Buffer.from(String(started)))),
    nonces: [],
    authFails: 0, lastFail: 0,
    busyUntil: 0,                  // a disk format after init (PPA)
    formatPolls: 0,
    logId: Math.floor(started / 1000).toString(16).padStart(8, '0'),
    rtcSet: true,                  // the virtual clock is the server's: always set
    shutdown: false,
  };
}

export const uptime = (boot) => Math.floor((Date.now() - boot.started) / 1000);

/** A time-based 32-byte nonce, remembered for this boot. */
export function issueNonce(boot, ttl = 86400) {
  const n = Buffer.concat([Buffer.alloc(4), rand(28)]);
  n.writeUInt32BE(Math.floor(Date.now() / 1000));
  const s = b64(n);
  boot.nonces.push({ n: s, exp: Math.floor(Date.now() / 1000) + ttl });
  if (boot.nonces.length > NONCE_KEEP) boot.nonces.splice(0, boot.nonces.length - NONCE_KEEP);
  return s;
}
/** Is `s` a live nonce of this boot? consume: take it, so it is accepted once (DEV-499). */
export function nonceValid(boot, s, consume = false) {
  const now = Math.floor(Date.now() / 1000);
  const i = typeof s === 'string' ? boot.nonces.findIndex((x) => x.n === s && x.exp >= now) : -1;
  if (i >= 0 && consume) boot.nonces.splice(i, 1);
  return i >= 0;
}

// ---- audit log -----------------------------------------------------------------
// The file format the Manager and hem-sdk-js verify: a key line with a fresh
// nonce and its Ed25519 signature, then entries whose last field is the first
// 16 bytes of HMAC-SHA256(nonce, everything up to and including the last '|').

export const LOG = {
  STARTUP: 1, REBOOT: 2, SHUTDOWN: 3, UPGRADE: 4, SELFTEST_PASSED: 7, LOGGER_LIST_LOG: 9, LOGGER_READ_LOG: 11,
  FAILED_SCOPE_CHECK: 12, AUTH_SUCCESS_INTERNAL: 13, AUTH_SUCCESS_EXTERNAL: 14, AUTH_PAIRED_EXTERNAL: 15,
  CONFIG_UPDATED: 18, RTC_SET: 19, KEY_GENERATION: 20, KEY_DELETE: 21, KEY_IMPORT: 22, KEY_USAGE_PKEY: 23,
  KEY_ATTRIBUTES_CHANGED: 25, KEY_DERIVE: 26, DEVICE_INITED: 29, HMAC_HASH: 30, HMAC_VERIFY: 31, EXDSA_SIGN: 32,
  EXDSA_VERIFY: 33, WRAP: 34, UNWRAP: 35, ENCRYPT: 36, DECRYPT: 37, ECDH: 38, MLKEM_ENCAPS: 39, MLKEM_DECAPS: 40,
  MLDSA_SIGN: 41, MLDSA_VERIFY: 42, SYSTEM_ATTESTATION: 43, KDF: 46, OTP: 47, XWING_ENCAPS: 48, XWING_DECAPS: 49,
  STORAGE_UNLOCK: 52, STORAGE_LOCK: 53, HPKE_SEAL: 54, HPKE_OPEN: 55,
};

// Format v2 (DEV-500): a per-file Ed25519 key, certified by the device log key in
// the header line; every line signed with the per-file key.
//   <seq>|<ts>|<type>|<result>|<subject>|<data>|<sig>
const edPriv = (b) => crypto.createPrivateKey({ key: Buffer.from(b, 'base64'), format: 'der', type: 'pkcs8' });

export function newLogFile(dev, boot) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
  const cert = crypto.sign(null, pub, edPriv(dev.logKey.priv));
  const file = { id: boot.logId, v: 2, key: b64(privateKey.export({ format: 'der', type: 'pkcs8' })), seq: 0, lines: [`# ${FW_VERSION}`] };
  writeLine(file, `0|${Math.floor(Date.now() / 1000).toString(16)}|0|0|v2|${b64url(Buffer.concat([pub, cert]))}|`);
  return file;
}

function writeLine(file, text) {
  file.lines.push(text + b64url(crypto.sign(null, Buffer.from(text, 'utf8'), edPriv(file.key))));
}

/** Append one entry. subject: up to 32 printable characters (role, scope, id); data: bytes or text, written base64url. */
export function logAppend(file, type, result = 0, subject = '', data = '') {
  if (file.v !== 2) return;                         // a v1 file from an older playground build: leave it as it is
  file.seq++;
  const ts = Math.floor(Date.now() / 1000).toString(16);
  const d = data === '' ? '' : b64url((Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8')).subarray(0, 360));
  const subj = String(subject ?? '').replace(/[^\x20-\x7e]|\|/g, '').slice(0, 32);
  writeLine(file, `${file.seq.toString(16)}|${ts}|${type.toString(16)}|${result}|${subj}|${d}|`);
  if (file.lines.length > 20000) file.lines.splice(2, file.lines.length - 20000);
}
