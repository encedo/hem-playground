// HEM Playground: one HTTP server, routed by the Host header.
//   <domain>            the public site: register a module
//   admin.<domain>      the admin panel
//   manager.<domain>    the Encedo Manager (static, from the manager/ submodule)
//   <prefix>.<domain>   one virtual module
// TLS is ended by the proxy in front (Caddy locally, nginx on the server), which
// says so in X-Forwarded-Proto; the module answers 418 where it needs TLS.

import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store } from './lib/store.mjs';
import { Mailer } from './lib/mail.mjs';
import { Registry, MODE_LABEL, DEFAULT_SETTINGS } from './registry.mjs';
import { handleHem } from './sim/index.mjs';
import { versionJson } from './sim/system.mjs';
import * as ui from './web/ui.mjs';
import * as admin from './web/admin.mjs';
import * as auth from './web/auth.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DOMAIN = (process.env.DOMAIN || 'localhost').toLowerCase();
const PORT = Number(process.env.PORT || 8080);
const MANAGER_DIR = path.resolve(process.env.MANAGER_DIR || path.join(HERE, '..', 'manager'));
const store = new Store(process.env.REDIS_URL || 'redis://127.0.0.1:6379');
const mailer = new Mailer();
const registry = new Registry(store, DOMAIN, mailer);

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.map': 'application/json', '.png': 'image/png', '.woff2': 'font/woff2', '.ico': 'image/x-icon' };

// ---- helpers -----------------------------------------------------------------------------------
const html = (res, status, body, headers = {}) => { res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'DENY', ...headers }); res.end(body); };
const json = (res, status, obj) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj, null, 2)); };
const redirect = (res, to, headers = {}) => { res.writeHead(303, { Location: to, 'Cache-Control': 'no-store', ...headers }); res.end(); };
const clientIp = (req) => (req.headers['x-forwarded-for'] ?? '').split(',')[0].trim() || req.socket.remoteAddress;

async function form(req) {
  const chunks = []; let n = 0;
  for await (const c of req) { n += c.length; if (n > 16384) break; chunks.push(c); }
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
}

async function serveFile(res, root, rel) {
  const file = path.resolve(root, '.' + path.posix.normalize('/' + rel));
  if (!file.startsWith(root + path.sep) && file !== root) { res.writeHead(404); return res.end(); }
  try {
    const body = await fs.readFile(file);
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] ?? 'application/octet-stream', 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff' });
    res.end(body);
  } catch { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found'); }
}

async function assets(res, rel) {
  if (rel === 'manager.css') return serveFile(res, path.join(MANAGER_DIR, 'app'), 'style.css');
  if (rel === 'favicon.svg') return serveFile(res, MANAGER_DIR, 'favicon.svg');
  if (rel === 'pg.css') return serveFile(res, path.join(HERE, 'web'), 'pg.css');
  res.writeHead(404); res.end();
}

async function viewCfg() {
  const s = await registry.settings();
  return { domain: DOMAIN, ...s, modeLabel: MODE_LABEL[s.mode], oidcHost: auth.oidcHost(), mailOk: mailer.configured };
}

// ---- request log and rate limit, per module -------------------------------------------------------
const pendingLog = new Map();                    // prefix -> [entries]
const rate = new Map();                          // prefix -> { minute, n }
function overRate(prefix, rpm) {
  if (!rpm) return false;
  const minute = Math.floor(Date.now() / 60000);
  const r = rate.get(prefix);
  if (!r || r.minute !== minute) { rate.set(prefix, { minute, n: 1 }); return false; }
  return ++r.n > rpm;
}
async function flushLogs() {
  const s = await registry.settings();
  for (const [prefix, entries] of pendingLog) {
    pendingLog.delete(prefix);
    await store.withLock(prefix, async () => {
      const { meta, log } = await store.getMany(prefix, ['meta', 'log']);
      if (!meta) return;
      meta.lastReq = Math.max(meta.lastReq ?? 0, ...entries.map((e) => e.t));
      await store.set(prefix, { meta, log: [...entries.reverse(), ...(log ?? [])].slice(0, s.logKeep) });
    }).catch((e) => console.error('log flush', e.message));
  }
}
setInterval(flushLogs, 2000).unref();
setInterval(() => registry.sweep().catch((e) => console.error('sweep', e.message)), 3600_000).unref();

// ---- sites ---------------------------------------------------------------------------------------
async function publicSite(req, res, url) {
  const cfg = await viewCfg();
  if (url.pathname.startsWith('/assets/')) return assets(res, url.pathname.slice(8));
  if (url.pathname === '/' && req.method === 'GET') return html(res, 200, ui.registerPage(cfg));
  if (url.pathname === '/check' && req.method === 'GET') {
    const p = (url.searchParams.get('prefix') ?? '').trim().toLowerCase();
    const why = await registry.whyNot(p, cfg);
    return json(res, 200, { free: !why, message: why ?? `${p}.${DOMAIN} is free.` });
  }
  if (url.pathname === '/register' && req.method === 'POST') {
    const f = await form(req);
    const values = { prefix: f.get('prefix') ?? '', email: f.get('email') ?? '', variant: f.get('variant') ?? 'PPA' };
    const r = await registry.register(values);
    if (r.error) return html(res, 400, ui.registerPage(cfg, { values, error: r.error }));
    if (r.meta.state === 'active') return html(res, 200, ui.registeredPage(cfg, r.meta));
    return html(res, 200, ui.messagePage(cfg, 'One more step', 'The address is held for you until the link in the e-mail is opened.',
      `A message went to <span class="mono">${ui.esc(r.meta.email)}</span>. The link in it is good for 24 hours; after that the prefix is free again.`,
      cfg.mode === 'approve' ? '<p class="note">The administrator approves the module after that; it answers from then on.</p>' : ''));
  }
  if (url.pathname === '/confirm' && req.method === 'GET') {
    const r = await registry.confirm((url.searchParams.get('p') ?? '').toLowerCase(), url.searchParams.get('t') ?? '');
    if (r.error) return html(res, 400, ui.messagePage(cfg, 'Confirmation', 'This link does not work.', ui.esc(r.error)));
    if (r.meta.state === 'active') return html(res, 200, ui.registeredPage(cfg, r.meta));
    return html(res, 200, ui.messagePage(cfg, 'E-mail confirmed', 'The module now waits for the administrator.', 'It answers as soon as it is approved.'));
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found');
}

async function adminSite(req, res, url) {
  const cfg = await viewCfg();
  const p = url.pathname;
  if (p.startsWith('/assets/')) return assets(res, p.slice(8));
  if (p === '/login' && req.method === 'GET') return html(res, 200, admin.signinPage(cfg, { oidc: auth.oidcEnabled() }));
  if (p === '/login' && req.method === 'POST') {
    const f = await form(req);
    const r = auth.checkPassword(clientIp(req), f.get('user') ?? '', f.get('password') ?? '');
    if (r.ok) return redirect(res, '/', { 'Set-Cookie': auth.sessionCookie(f.get('user'), 'password') });
    return html(res, 401, admin.signinPage(cfg, { oidc: auth.oidcEnabled(), error: r.locked ? 'Too many wrong tries from this address. Try again in 15 minutes.' : 'That user and password do not match an administrator.' }));
  }
  if (p === '/auth/oidc') {
    if (!auth.oidcEnabled()) return redirect(res, '/login');
    const s = await auth.oidcStart();
    return redirect(res, s.location, { 'Set-Cookie': s.cookie });
  }
  if (p === '/auth/callback') {
    const r = await auth.oidcFinish(req, url.searchParams).catch((e) => ({ error: `The sign-in failed: ${e.message}` }));
    if (r.error) return html(res, 401, admin.signinPage(cfg, { oidc: true, error: r.error }), { 'Set-Cookie': auth.clearOidc() });
    return redirect(res, '/', { 'Set-Cookie': [auth.sessionCookie(r.email, 'oidc'), auth.clearOidc()] });
  }
  if (p === '/logout') return redirect(res, '/login', { 'Set-Cookie': auth.clearSession() });

  const sess = auth.session(req);
  if (!sess) return redirect(res, '/login');
  let f = null;
  if (req.method === 'POST') {
    f = await form(req);
    if (f.get('csrf') !== auth.csrfToken(sess)) { res.writeHead(403, { 'Content-Type': 'text/plain' }); return res.end('The form is stale. Reload the page and try again.'); }
  }
  const mods = await registry.all();
  if (p === '/' && req.method === 'GET') return html(res, 200, admin.modulesPage(cfg, sess, mods, url.searchParams));
  if (p === '/settings') {
    if (req.method === 'POST') {
      const s = {};
      const mode = f.get('mode');
      if (mode && ['auto', 'email', 'approve'].includes(mode) && (mode === 'auto' || mailer.configured)) s.mode = mode;
      for (const k of ['modulesPerEmail', 'keysPerModule', 'rpm', 'idleDays', 'logKeep']) {
        const v = Number(f.get(k));
        if (Number.isInteger(v) && v >= 0 && v <= 100000) s[k] = v;
      }
      if (s.logKeep !== undefined) s.logKeep = Math.max(10, Math.min(s.logKeep, 2000));
      s.reserved = (f.get('reserved') ?? DEFAULT_SETTINGS.reserved).replace(/[^a-z0-9*\s-]/g, '').trim();
      await store.saveSettings(s);
      return html(res, 200, admin.settingsPage(await viewCfg(), sess, await registry.settings(), { count: mods.length, saved: true, mailOk: mailer.configured }));
    }
    return html(res, 200, admin.settingsPage(cfg, sess, await registry.settings(), { count: mods.length, mailOk: mailer.configured }));
  }
  const m = /^\/m\/([a-z0-9-]+)(?:\/([a-z.]+))?$/.exec(p);
  if (m) {
    const prefix = m[1];
    if (req.method === 'POST' && m[2]) {
      const r = await registry.act(prefix, m[2]);
      return redirect(res, r.gone ? '/' : `/m/${prefix}`);
    }
    const { meta, dev, boot, log } = await store.getMany(prefix, ['meta', 'dev', 'boot', 'log']);
    if (!meta) return redirect(res, '/');
    const fake = { dev, ppa: dev.variant === 'PPA' };
    if (m[2] === 'status.json') return json(res, 200, { meta, version: versionJson(fake), personalised: !!dev.inited, config: dev.cfg ? { ...dev.cfg } : null, uptime: Math.floor((Date.now() - boot.started) / 1000), boot: boot.n, storage: dev.storage });
    if (m[2] === 'log.jsonl') { res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Content-Disposition': `attachment; filename="${prefix}-requests.jsonl"` }); return res.end((log ?? []).map((x) => JSON.stringify(x)).join('\n') + '\n'); }
    const keys = (await store.redis.call('HKEYS', prefix)).filter((x) => x.startsWith('k:')).length;
    return html(res, 200, admin.modulePage(cfg, sess, meta, { dev, boot, log, keys, statusJson: versionJson(fake), count: mods.length }));
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found');
}

async function managerSite(req, res, url) {
  const rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
  if (!/^(index\.html|favicon\.svg|app\/[\w./-]+|sdk\/[\w./-]+)$/.test(rel) || rel.includes('..')) { res.writeHead(404); return res.end(); }
  return serveFile(res, MANAGER_DIR, rel);
}

async function moduleSite(req, res, prefix, tls) {
  const meta = await store.get(prefix, 'meta');
  if (!meta || meta.state === 'unconfirmed' || meta.state === 'pending') { res.writeHead(404, { 'Content-Length': 0, Connection: 'close' }); return res.end(); }
  if (meta.state === 'blocked') { res.writeHead(503, { 'Content-Length': 0, 'Retry-After': '3600', Connection: 'close' }); return res.end(); }
  const s = await registry.settings();
  if (overRate(prefix, s.rpm)) { res.writeHead(429, { 'Content-Length': 0, 'Retry-After': '60' }); return res.end(); }
  return handleHem({ store, prefix, req, res, tls, settings: s, onLog: (e) => { const a = pendingLog.get(prefix) ?? []; a.push(e); pendingLog.set(prefix, a); } });
}

// ---- server --------------------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  try {
    const host = (req.headers.host ?? '').toLowerCase().replace(/:\d+$/, '');
    const tls = req.headers['x-forwarded-proto'] === 'https';
    if (req.url === '/healthz') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ok'); }
    if (req.url.startsWith('/healthz/tls?')) {
      // Caddy asks before it issues an on-demand certificate: only for our own names and registered prefixes
      const d = (new URL(req.url, 'http://x').searchParams.get('domain') ?? '').toLowerCase();
      const sub = d.endsWith(`.${DOMAIN}`) ? d.slice(0, -DOMAIN.length - 1) : null;
      const ok = d === DOMAIN || ['admin', 'manager', 'www'].includes(sub) || (sub && /^[a-z0-9-]+$/.test(sub) && await store.exists(sub));
      res.writeHead(ok ? 200 : 404); return res.end();
    }
    // the public site lives on www.<domain>: covered by the wildcard DNS record and certificate
    if (host === `www.${DOMAIN}`) return await publicSite(req, res, new URL(req.url, 'http://x'));
    if (host === DOMAIN) return redirect(res, `https://www.${DOMAIN}${req.url}`);
    if (host === `admin.${DOMAIN}`) return await adminSite(req, res, new URL(req.url, 'http://x'));
    if (host === `manager.${DOMAIN}`) return await managerSite(req, res, new URL(req.url, 'http://x'));
    if (host.endsWith(`.${DOMAIN}`)) {
      const prefix = host.slice(0, -DOMAIN.length - 1);
      if (/^[a-z0-9-]+$/.test(prefix)) return await moduleSite(req, res, prefix, tls);
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Unknown host');
  } catch (e) {
    console.error(e);
    if (!res.headersSent) { res.writeHead(500, { 'Content-Type': 'text/plain' }); res.end('Internal error'); } else res.destroy();
  }
});
server.keepAliveTimeout = 2000;
server.requestTimeout = 30000;

async function seed() {
  for (const p of (process.env.SEED_HEM ?? '').split(',').map((x) => x.trim()).filter(Boolean)) {
    if (await store.exists(p)) continue;
    const s = await registry.settings();
    await store.saveSettings({ ...s });
    const r = await registry.register({ prefix: p, email: process.env.SEED_EMAIL || 'test@playground.local', variant: 'PPA' });
    if (r.meta && r.meta.state !== 'active') await registry.act(p, 'approve');
    console.log(`seeded ${p}.${DOMAIN}${r.error ? ` (${r.error})` : ''}`);
  }
}

await seed().catch((e) => console.error('seed', e.message));
server.listen(PORT, () => console.log(`HEM Playground on :${PORT} for ${DOMAIN} (manager from ${MANAGER_DIR}, OIDC ${auth.oidcEnabled() ? 'on' : 'off'}, mail ${mailer.configured ? 'on' : 'log only'})`));
