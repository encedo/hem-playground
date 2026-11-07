// One request to one virtual module: load it, run the firmware's pre-handler
// checks, dispatch, save what changed, record the request for the admin view.

import { Ctx, HttpErr, send, originAllowed, checkBearer, MAX_JSON, MAX_UPLOAD } from './http.mjs';
import { newBoot, newDevice, LOG } from './device.mjs';
import * as A from './auth.mjs';
import * as S from './system.mjs';
import * as KM from './keymgmt.mjs';
import * as C from './crypto.mjs';

const EXACT = {
  'GET /api/auth/token': A.getToken, 'POST /api/auth/token': A.postToken,
  'GET /api/auth/init': A.getInit, 'POST /api/auth/init': A.postInit,
  'POST /api/auth/ext/init': A.extInit, 'POST /api/auth/ext/validate': A.extValidate, 'POST /api/auth/ext/mac': A.extMac,
  'POST /api/auth/ext/request': A.extRequest, 'POST /api/auth/ext/token': A.extToken,
  'GET /api/system/status': S.status, 'GET /api/system/version': S.version, 'GET /api/system/selftest': S.selftest,
  'GET /api/system/checkin': S.getCheckin, 'POST /api/system/checkin': S.postCheckin,
  'GET /api/system/config': S.getConfig, 'POST /api/system/config': S.postConfig,
  'POST /api/system/config/attestation': S.postAttestation, 'POST /api/system/config/provisioning': S.provisioning,
  'GET /api/system/reboot': S.reboot, 'GET /api/system/shutdown': S.shutdown,
  'GET /api/system/defrag/check': S.defragCheck, 'GET /api/system/defrag/start': S.defragStart,
  'GET /api/storage/lock': S.lock, 'GET /api/logger/key': S.loggerKey,
  'POST /api/keymgmt/search': KM.search, 'POST /api/keymgmt/create': KM.create, 'POST /api/keymgmt/update': KM.update,
  'POST /api/keymgmt/import': KM.importKey, 'POST /api/keymgmt/derive': KM.derive,
  'POST /api/crypto/hmac/hash': C.hmacHash, 'POST /api/crypto/hmac/verify': C.hmacVerify,
  'POST /api/crypto/exdsa/sign': C.exdsaSign, 'POST /api/crypto/exdsa/verify': C.exdsaVerify,
  'POST /api/crypto/cipher/encrypt': C.encrypt, 'POST /api/crypto/cipher/decrypt': C.decrypt,
  'POST /api/crypto/cipher/wrap': C.wrap, 'POST /api/crypto/cipher/unwrap': C.unwrap,
  'POST /api/crypto/ecdh': C.ecdh, 'POST /api/crypto/kdf': C.kdf, 'POST /api/crypto/hmac/otp': C.otp,
  'POST /api/crypto/pqc/mlkem/encaps': C.mlkemEncaps, 'POST /api/crypto/pqc/mlkem/decaps': C.mlkemDecaps,
  'POST /api/crypto/pqc/xwing/encaps': C.xwingEncaps, 'POST /api/crypto/pqc/xwing/decaps': C.xwingDecaps,
  'POST /api/crypto/pqc/mldsa/sign': C.mldsaSign, 'POST /api/crypto/pqc/mldsa/verify': C.mldsaVerify,
  'POST /api/crypto/hpke/seal': C.hpkeSeal, 'POST /api/crypto/hpke/open': C.hpkeOpen,
};
const PREFIX = [
  ['GET', '/api/system/config/attestation', S.getAttestation],
  ['GET', '/api/system/upgrade', (ctx, rest) => S.upgrade(ctx, rest)],
  ['GET', '/api/keymgmt/list', KM.list], ['GET', '/api/keymgmt/get', KM.get], ['DELETE', '/api/keymgmt/delete', KM.del],
  ['GET', '/api/crypto/random', C.random],
  ['GET', '/api/storage/unlock', S.unlock],
  ['GET', '/api/logger/', S.loggerRest],
];
const UPLOADS = { '/api/system/upgrade/upload_fw': 'fw', '/api/system/upgrade/upload_ui': 'ui' };

function route(method, path) {
  const h = EXACT[`${method} ${path}`];
  if (h) return (ctx) => h(ctx);
  for (const [m, p, fn] of PREFIX) if (m === method && path.startsWith(p)) return (ctx) => fn(ctx, path.slice(p.length));
  return null;
}

function readBody(req, limit) {
  return new Promise((resolve) => {
    const chunks = []; let n = 0, over = false;
    const timer = setTimeout(() => done(true), 5000);
    const done = (short) => { clearTimeout(timer); resolve({ buf: Buffer.concat(chunks), over, short }); };
    req.on('data', (c) => { n += c.length; if (n > limit) over = true; else chunks.push(c); });
    req.on('end', () => done(false));
    req.on('error', () => done(true));
  });
}

/** A fresh module record, as the registration stores it. */
export function createModule(variant, hostname) {
  const dev = newDevice(variant);
  dev.hostname = hostname;
  return { dev, boot: newBoot(dev) };
}

export async function handleHem({ store, prefix, req, res, tls, settings, onLog }) {
  const t0 = Date.now();
  const info = { tls, requestId: null, origin: null };
  const rid = req.headers['x-request-id'];
  if (typeof rid === 'string' && /^[A-Za-z0-9._-]{1,64}$/.test(rid)) info.requestId = rid;
  const url = req.url;
  const path = url;                                     // no decoding, no query stripping: as the firmware does
  let status = 500;
  const finish = (st, opts) => { status = st; send(res, info, st, opts); };
  let reply = null;

  try {
    if (url.length > 1024) return finish(414, { close: true });
    if (!['GET', 'POST', 'DELETE', 'OPTIONS'].includes(req.method)) return finish(405, { close: true });

    await store.withLock(prefix, async () => {
      const { dev, boot } = await store.getMany(prefix, ['dev', 'boot']);
      if (!dev) throw new HttpErr(404);
      let b = boot ?? newBoot(dev);
      info.hsts = dev.cfg?.http_option_hsts !== false;
      if (b.shutdown) { req.socket.destroy(); status = 0; return; }

      if (req.headers['transfer-encoding']) throw new HttpErr(501, { close: true });
      const origin = req.headers.origin;
      if (origin !== undefined) {
        if (!originAllowed(dev.cfg?.origin ?? '*', origin)) throw new HttpErr(412);
        info.origin = origin;
      }
      if (req.method === 'OPTIONS') {
        const h = { 'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS', 'Access-Control-Allow-Headers': `Content-Type, Authorization, X-Request-ID${dev.variant === 'PPA' ? ', Content-Disposition' : ''}`, 'Access-Control-Max-Age': '86400', Vary: 'Origin' };
        if (dev.variant === 'PPA' && req.headers['access-control-request-private-network'] === 'true') { h['Access-Control-Allow-Private-Network'] = 'true'; h['Private-Network-Access-Name'] = 'encedo-ppa'; }
        return finish(204, { headers: h });
      }

      let isJson = false, uploadName = null;
      if (req.method === 'POST') {
        // the proxy in front passes the client's own Content-Length (or none) in X-Orig-Content-Length
        const cl = 'x-orig-content-length' in req.headers ? (req.headers['x-orig-content-length'] || undefined) : req.headers['content-length'];
        if (cl === undefined) throw new HttpErr(411);
        if (!/^\d+$/.test(cl)) throw new HttpErr(400, { close: true });
        if (Number(cl) === 0) throw new HttpErr(400);
        isJson = /^application\/json/i.test(req.headers['content-type'] ?? '');
      }

      const ctx = new Ctx({ store, prefix, req, path, tls, body: null, raw: null, settings });
      ctx._dev = dev; ctx._boot = b;
      if (req.headers.authorization !== undefined) {
        ctx.token = checkBearer(b, req.headers.authorization, ctx.now);
        if (!ctx.token) throw new HttpErr(401);
      }

      let handler;
      if (req.method === 'POST' && !isJson) {
        const kind = UPLOADS[path];
        if (dev.variant !== 'PPA') throw new HttpErr(400);
        const cd = req.headers['content-disposition'] ?? '';
        const m = /filename\s*=\s*"?([^";]*)"?/i.exec(cd);
        if (!m || Number(req.headers['content-length']) > MAX_UPLOAD) throw new HttpErr(413, { close: true });
        if (!/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,23}$/.test(m[1])) throw new HttpErr(400, { close: true });
        if (!kind) throw new HttpErr(404);
        ctx.uploadName = m[1];
        ctx.uploadSize = Number(req.headers['content-length']);
        // access, name and size are checked before the body is read (a 3 MiB firmware gets its 413 at once)
        ctx.readUpload = async () => {
          const { buf, short } = await readBody(req, MAX_UPLOAD);
          if (short || buf.length < ctx.uploadSize) throw new HttpErr(406, { close: true });
          ctx.raw = buf;
        };
        handler = (c) => S.upload(c, kind);
      } else {
        if (req.method === 'POST') {
          if (Number(req.headers['content-length']) > MAX_JSON) throw new HttpErr(413, { close: true });
          const { buf } = await readBody(req, MAX_JSON);
          try { ctx.body = JSON.parse(buf.toString('utf8')); if (typeof ctx.body !== 'object' || ctx.body === null || Array.isArray(ctx.body)) ctx.body = null; } catch { ctx.body = null; }
        }
        if (!path.startsWith('/api/')) throw new HttpErr(404);
        handler = route(req.method, path);
        if (!handler) throw new HttpErr(404);
      }

      let out, err = null;
      try { out = await handler(ctx); } catch (e) { if (!(e instanceof HttpErr)) throw e; err = e; }

      // what changed is saved even when the handler failed (audit entries, throttling state)
      if (ctx.wipe) {
        const fresh = newDevice(dev.variant);
        Object.assign(fresh, { hostname: dev.hostname, devid: dev.devid, instanceid: dev.instanceid, eid: dev.eid, eidSign: dev.eidSign, logKey: dev.logKey, slot0: dev.slot0, slot1: dev.slot1, genuineId: dev.genuineId, bootCount: dev.bootCount, qidSeed: dev.qidSeed });
        if (ctx.wipe === 'factory') fresh.httpsUp = false;   // no TLS of the previous owner left
        const keyFields = (await store.fields(prefix, 'k:*')).map(([f]) => f);
        await store.del(prefix, ...keyFields);
        const nb = newBoot(fresh);
        await store.set(prefix, { dev: fresh, boot: nb });
      } else {
        if (ctx.reboot) { Object.assign(b = newBoot(dev), ctx.reboot); ctx.touch('dev', 'boot'); ctx._boot = b; }
        const save = {};
        if (ctx.dirty.has('dev')) save.dev = dev;
        if (ctx.dirty.has('boot') || !boot) save.boot = ctx._boot;
        if (ctx.audit) save[`audit:${ctx.audit.id}`] = ctx.audit;
        if (ctx.reboot) {
          // the new session starts its log with the power-up
          const { newLogFile, logAppend } = await import('./device.mjs');
          const f = newLogFile(dev, b); logAppend(f, LOG.STARTUP, 0); save[`audit:${f.id}`] = f;
        }
        await store.set(prefix, save);
      }
      if (err) throw err;
      reply = out ?? {};
    });
    // a handler that takes time on a real module (selftest) answers after the lock is released,
    // so a request arriving meanwhile sees the module busy
    if (reply) {
      if (reply.delay) await new Promise((r) => setTimeout(r, reply.delay));
      finish(reply.status ?? 200, { json: reply.json ?? null, text: reply.text ?? null, close: reply.close });
    }
  } catch (e) {
    if (e instanceof HttpErr) finish(e.status, { close: e.close, text: e.text });
    else { console.error(`[${prefix}] ${req.method} ${url}`, e); finish(500); }
  } finally {
    if (status && onLog) onLog({ t: Math.floor(t0 / 1000), m: req.method, p: url.slice(0, 120), s: status, ms: Date.now() - t0, o: req.headers.origin ?? '' });
  }
}
