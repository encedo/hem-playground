// The module's HTTP front: the checks the firmware makes before a handler runs,
// in the firmware's order, and the reply headers it always sends.

import { jwtParse, jwtVerify, jwtSign, b64, rand } from './codec.mjs';
import { newLogFile, logAppend, LOG } from './device.mjs';

export class HttpErr extends Error { constructor(status, opts = {}) { super(`HTTP ${status}`); this.status = status; this.close = opts.close; this.text = opts.text; } }
export const fail = (status, opts) => { throw new HttpErr(status, opts); };

export const MAX_JSON = 7300;
export const MAX_UPLOAD = 16 * 1024 * 1024;
const CLOSE_CODES = new Set([401, 403, 411, 412, 413, 414, 501]);

// ---- scopes ------------------------------------------------------------------------
const FIXED_SCOPES = new Set(['auth:ext:pair', 'system:config', 'system:upgrade', 'system:shutdown', 'logger:get', 'logger:del',
  'keymgmt:list', 'keymgmt:search', 'keymgmt:get', 'keymgmt:del', 'keymgmt:gen', 'keymgmt:upd', 'keymgmt:imp', 'keymgmt:derive']);
export function validScopeValue(s) {
  if (typeof s !== 'string' || s.length > 44) return false;
  return FIXED_SCOPES.has(s) || /^keymgmt:use:[0-9a-fA-F]{32}$/.test(s) || /^storage:disk[01](:ro|:rw)?$/.test(s);
}
/** A requested scope (string or array of 1..8): valid, no duplicates, at most one storage value. */
export function validScope(scope) {
  if (typeof scope === 'string') return scope !== '' && validScopeValue(scope);
  if (!Array.isArray(scope) || scope.length < 1 || scope.length > 8) return false;
  if (!scope.every(validScopeValue)) return false;
  if (new Set(scope).size !== scope.length) return false;
  return scope.filter((s) => s.startsWith('storage:')).length <= 1;
}
export const scopes = (tok) => (tok ? (Array.isArray(tok.scope) ? tok.scope : [tok.scope]) : []);
export const hasScope = (tok, s) => scopes(tok).includes(s);

// ---- the request context -------------------------------------------------------------
export class Ctx {
  constructor({ store, prefix, req, path, tls, body, raw, settings }) {
    Object.assign(this, { store, prefix, req, path, tls, body, raw, settings });
    this.method = req.method;
    this.headers = req.headers;
    this.now = Math.floor(Date.now() / 1000);
    this.token = null;
    this.dirty = new Set();
    this.audit = null;
  }
  get dev() { return this._dev; }
  get boot() { return this._boot; }
  get inited() { return this._dev.inited > 0; }
  get busy() { return this._boot.busyUntil > Date.now(); }
  get fls() { return this._dev.fls; }
  get ppa() { return this._dev.variant === 'PPA'; }
  touch(...f) { f.forEach((x) => this.dirty.add(x)); }

  async key(kid) { return kid ? this.store.get(this.prefix, `k:${kid.toLowerCase()}`) : null; }
  async putKey(k) { await this.store.set(this.prefix, { [`k:${k.kid}`]: k }); }
  async delKey(kid) { await this.store.del(this.prefix, `k:${kid.toLowerCase()}`); }
  async keys() {
    const all = await this.store.fields(this.prefix, 'k:*');
    return all.map(([, v]) => v).sort((a, b) => (a.seq ?? a.created) - (b.seq ?? b.created) || (a.kid < b.kid ? -1 : 1));
  }

  async log(type, result = 0, subject = '', data = '') {
    if (!this.audit) {
      this.audit = await this.store.get(this.prefix, `audit:${this._boot.logId}`);
      if (!this.audit) this.audit = newLogFile(this._dev, this._boot);
    }
    logAppend(this.audit, type, result, subject, data);
    this.touch('audit');
  }

  needToken() { if (!this.token) fail(401); }
  needTls() { if (!this.tls) fail(418); }
  /** Exact match of one scope value from `allowed`; role M refused when noM. 403 is audit-logged. */
  async needScope(allowed, { noM = false, logScope = null } = {}) {
    const ok = scopes(this.token).some((s) => allowed.includes(s)) && !(noM && this.token.sub === 'M');
    if (!ok) { await this.log(LOG.FAILED_SCOPE_CHECK, 1, this.token?.sub ?? '', logScope ?? allowed[0]); fail(403); }
  }

  /** Issue a bearer token signed with this boot's token key. */
  issueToken({ scope, sub, exp, ctx }) {
    const p = { scope, sub, iat: this.now, exp, jti: b64(rand(32)) };
    if (typeof ctx === 'string' && ctx.length >= 1 && ctx.length <= 64) p.ctx = ctx;
    return jwtSign(p, Buffer.from(this._boot.tokenKey, 'base64'));
  }
}

/** Validate a bearer token against this boot's key. null when invalid. */
export function checkBearer(boot, header, now) {
  const m = /^bearer\s+(\S+)$/i.exec(header ?? '');
  if (!m) return null;
  const p = jwtVerify(jwtParse(m[1]), Buffer.from(boot.tokenKey, 'base64'), now);
  if (!p || typeof p.exp !== 'number' || p.sub == null) return null;
  if (!(typeof p.scope === 'string' ? p.scope.length > 0 : Array.isArray(p.scope) && p.scope.length > 0)) return null;
  return p;
}

// ---- CORS -------------------------------------------------------------------------------
export function originAllowed(list, origin) {
  const i = origin.indexOf('://');
  if (i < 0) return false;
  const host = origin.slice(i + 3).toLowerCase();
  const entries = (list ?? '*').split(/\s+/).filter(Boolean);
  if (!entries.length) return false;
  return entries.some((e) => {
    e = e.toLowerCase();
    if (e === '*') return true;
    if (e.startsWith('*.')) {
      if (host.includes(':')) return false;
      const dom = e.slice(1);
      return host.endsWith(dom) && !host.slice(0, -dom.length).includes('.') && host.length > dom.length;
    }
    return host === e;
  });
}

// ---- reply ------------------------------------------------------------------------------
export function send(res, ctxInfo, status, { json = null, text = null, close = false, headers = {} } = {}) {
  const body = json != null ? Buffer.from(JSON.stringify(json)) : text != null ? Buffer.from(text) : Buffer.alloc(0);
  const h = {
    'Content-Type': text != null && json == null && status === 200 ? 'text/plain' : 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store, no-cache',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  };
  if (ctxInfo.tls && ctxInfo.hsts !== false) h['Strict-Transport-Security'] = 'max-age=15552000';
  if (ctxInfo.requestId) h['X-Request-ID'] = ctxInfo.requestId;
  if (ctxInfo.origin) { h['Access-Control-Allow-Origin'] = ctxInfo.origin; h.Vary = 'Origin'; }
  if (status === 401) h['WWW-Authenticate'] = 'Bearer realm="hem"';
  const shut = close || CLOSE_CODES.has(status) || status >= 500 || ctxInfo.keepAlive === false;
  h.Connection = shut ? 'close' : 'keep-alive';
  res.writeHead(status, status === 418 ? '' : undefined, h);
  res.end(body);
}
