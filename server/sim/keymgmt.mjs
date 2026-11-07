// /api/keymgmt/*

import crypto from 'node:crypto';
import { unb64, isHex32, isPrintable } from './codec.mjs';
import { fail, hasScope } from './http.mjs';
import { LOG } from './device.mjs';
import * as K from './keys.mjs';

const state409 = (ctx) => { if (ctx.fls || !ctx.inited || ctx.busy) fail(409); };

/** descr: strict base64, 1..128 decoded. `empty`: what an empty string means ('absent' | 'bad'). */
function descrOf(v, empty) {
  if (v === undefined) return { v: null };
  if (typeof v !== 'string') fail(400);
  if (v === '') { if (empty === 'bad') fail(400); return { v: null }; }
  const d = unb64(v);
  if (!d || d.length < 1 || d.length > 128) fail(400);
  return { v };
}
function modeOf(v) {
  if (typeof v !== 'string' || v.length > 12) return null;    // ignored
  const m = K.parseMode(v);
  if (!m) fail(400);
  return m;
}

export function keyJson(k, { kid = false, pubkey = false } = {}) {
  const j = {};
  if (kid) j.kid = k.kid;
  Object.assign(j, { created: k.created, updated: k.updated, type: K.typeString(k), label: k.label });
  if (k.descr) j.descr = k.descr;
  if (pubkey && k.pub && !k.der) j.pubkey = k.pub;      // never for GENERIC_DER records in list / search
  return j;
}

async function store(ctx, rec, logType) {
  const limit = ctx.settings.keysPerModule ?? 512;
  if ((await ctx.store.fields(ctx.prefix, 'k:*')).length >= limit) fail(409);
  if (await ctx.key(rec.kid)) fail(logType === LOG.KEY_GENERATION ? 406 : 409);
  rec.seq = Date.now() + Math.random();
  await ctx.putKey(rec);
  await ctx.log(logType, 0, ctx.token.sub, rec.kid);
}

function pageWithPqc(list, offset, limit, withPub) {
  const out = [];
  let pqc = 0;
  for (const k of list.slice(offset)) {
    if (out.length >= limit) break;
    if (withPub && K.isPqc(k.type)) { if (pqc >= 3) break; pqc++; }
    out.push(k);
  }
  return out;
}

export async function list(ctx, rest) {
  state409(ctx);
  ctx.needToken();
  ctx.needTls();
  await ctx.needScope(['keymgmt:list'], { noM: true });
  const m = /^(?:\/(\d{1,9})(?:\/(\d{1,9})(?:\/(pubkey))?)?)?$/.exec(rest);
  if (!m) fail(400);
  const offset = Number(m[1] ?? 0), limit = Math.min(Number(m[2] ?? 15), 15);
  const withPub = !!m[3] && (ctx.dev.cfg.policy ?? []).includes('pubkey_in_list');
  const all = await ctx.keys();
  const page = pageWithPqc(all, offset, limit, withPub);
  return { json: { offset, deleted: ctx.dev.deletedKeys ?? 0, invalid: 0, total: all.length, listed: page.length, list: page.map((k) => keyJson(k, { kid: true, pubkey: withPub })) } };
}

export async function search(ctx) {
  state409(ctx);
  ctx.needTls();
  const b = ctx.body;
  if (!b || typeof b.descr !== 'string') fail(400);
  let pat = b.descr, how = 'sub';
  if (pat.startsWith('^')) { how = 'pre'; pat = pat.slice(1); } else if (pat.endsWith('$')) { how = 'suf'; pat = pat.slice(0, -1); }
  const needle = unb64(pat);
  if (!needle || needle.length < 1 || needle.length > 128) fail(400);
  const num = (v, def) => { if (v === undefined) return def; if (!Number.isInteger(v) || v < 0 || v > 65535) fail(400); return v; };
  const offset = num(b.offset, 0), limit = Math.min(num(b.limit, 15), 15);
  let mode = null;
  if (b.mode !== undefined) { mode = K.parseMode(b.mode); if (!mode) fail(400); }
  if (b.type !== undefined && !K.ALL_TYPES.includes(b.type)) fail(400);
  const open = !ctx.headers.authorization && how === 'pre' && needle.length >= 6 && ctx.dev.cfg.allow_keysearch !== false;
  if (!open) { ctx.needToken(); await ctx.needScope(['keymgmt:search', 'keymgmt:list', 'auth:ext:pair'], { noM: true }); }
  const withPub = !open && b.return_pubkey === true && (ctx.dev.cfg.policy ?? []).includes('pubkey_in_search');
  const all = await ctx.keys();
  const hits = all.filter((k) => {
    if (!k.descr) return false;
    const d = Buffer.from(k.descr, 'base64');
    const ok = how === 'pre' ? d.subarray(0, needle.length).equals(needle) : how === 'suf' ? d.length >= needle.length && d.subarray(d.length - needle.length).equals(needle) : d.includes(needle);
    if (!ok) return false;
    if (b.type !== undefined && k.type !== b.type) return false;
    if (mode && ((mode.ecdh && !k.ecdh) || (mode.exdsa && !k.exdsa) || (mode.hpke && !k.hpke))) return false;
    return true;
  });
  const page = pageWithPqc(hits, offset, limit, withPub);
  return { json: { offset, deleted: ctx.dev.deletedKeys ?? 0, total: all.length, listed: page.length, list: page.map((k) => keyJson(k, { kid: true, pubkey: withPub })) } };
}

export async function get(ctx, rest) {
  state409(ctx);
  ctx.needToken();
  ctx.needTls();
  const kid = rest.replace(/^\//, '');
  const ok = (hasScope(ctx.token, 'keymgmt:get') || hasScope(ctx.token, 'keymgmt:gen') || hasScope(ctx.token, `keymgmt:use:${kid}`)) && ctx.token.sub !== 'M';
  if (!ok) { await ctx.log(LOG.FAILED_SCOPE_CHECK, 1, ctx.token.sub, 'keymgmt:get'); fail(403); }
  if (!rest.startsWith('/') || !isHex32(kid)) fail(400);
  const k = await ctx.key(kid);
  if (!k) fail(404);
  const j = keyJson(k, { pubkey: true });
  if (k.der && k.pub) j.pubkey = k.pub;                  // TLS private key: the compressed point only
  if (k.cert) j.der = k.certDer;
  return { json: j };
}

async function writeAccess(ctx, scopesAllowed) {
  if (ctx.fls || ctx.busy) fail(409);
  ctx.needToken();
  ctx.needTls();
  if (!ctx.inited) fail(409);
  await ctx.needScope(scopesAllowed, { noM: true });
}

export async function create(ctx) {
  await writeAccess(ctx, ['keymgmt:gen']);
  const b = ctx.body;
  if (!b) fail(400);
  if (!isPrintable(b.label, 1, 64)) fail(400);
  const mode = modeOf(b.mode);
  const { v: descr } = descrOf(b.descr, 'absent');
  if (!K.ALL_TYPES.includes(b.type)) fail(400);
  if (mode?.hpke && !K.HPKE_TYPES.includes(b.type)) fail(400);
  const rec = K.record(b.type, K.generate(b.type), { att: true, label: b.label, descr, mode, now: ctx.now });
  await store(ctx, rec, LOG.KEY_GENERATION);
  return { json: { kid: rec.kid, ...keyJson(rec, { pubkey: b.return_pubkey === true }) } };
}

export async function importKey(ctx) {
  await writeAccess(ctx, ['keymgmt:imp']);
  const b = ctx.body;
  if (!b) fail(400);
  if (!isPrintable(b.label, 1, 64)) fail(400);
  if (!(b.type in K.PUB_LEN)) fail(400);
  const mode = modeOf(b.mode);
  if (mode?.hpke) fail(400);
  const { v: descr } = descrOf(b.descr, 'bad');
  const raw = unb64(b.pubkey);
  if (!raw) fail(400);
  const pub = K.importPub(b.type, raw);
  if (!pub) fail(400);
  const rec = K.record(b.type, { priv: null, pub }, { att: false, label: b.label, descr, mode, now: ctx.now });
  await store(ctx, rec, LOG.KEY_IMPORT);
  return { json: { kid: rec.kid } };
}

export async function update(ctx) {
  await writeAccess(ctx, ['keymgmt:upd']);
  const b = ctx.body;
  if (!b || !isHex32(b.kid) || !isPrintable(b.label, 1, 64)) fail(400);
  const { v: descr } = descrOf(b.descr, 'absent');
  const k = await ctx.key(b.kid);
  if (!k) fail(404);
  if (k.der) fail(409);                                   // system DER records are read-only (DEV-506)
  k.label = b.label; k.descr = descr; k.updated = ctx.now;
  await ctx.putKey(k);
  ctx.dev.deletedKeys = (ctx.dev.deletedKeys ?? 0) + 1; ctx.dev.deletedBytes = (ctx.dev.deletedBytes ?? 0) + 192; ctx.touch('dev');
  await ctx.log(LOG.KEY_ATTRIBUTES_CHANGED, 0, ctx.token.sub, k.kid);
  return {};
}

export async function derive(ctx) {
  await writeAccess(ctx, ['keymgmt:derive', 'keymgmt:gen']);
  const b = ctx.body;
  if (!b || !isHex32(b.kid) || !isPrintable(b.label, 1, 64) || typeof b.type !== 'string') fail(400);
  const mode = typeof b.mode === 'string' && b.mode.length <= 12 ? (K.parseMode(b.mode) ?? fail(400)) : null;
  const { v: descr } = descrOf(b.descr, 'bad');
  let salt = Buffer.alloc(0);
  if (b.hkdf_salt !== undefined) { const s = typeof b.hkdf_salt === 'string' ? unb64(b.hkdf_salt) : null; if (!s || !s.length || s.length > 128) fail(400); salt = s; }
  const hasExt = b.ext_kid !== undefined, hasPub = b.pubkey !== undefined;
  if (hasExt && !isHex32(b.ext_kid) && !(hasPub && typeof b.pubkey === 'string')) fail(400);
  const main = await ctx.key(b.kid);
  let ikm;
  if (hasExt || hasPub) {
    if (!main || !main.pkey || !main.ecdh) fail(406);
    let peer;
    if (hasExt && isHex32(b.ext_kid)) {
      const e = await ctx.key(b.ext_kid);
      if (!e || !e.ecdh || K.ecdhFamily(e) !== K.ecdhFamily(main)) fail(406);
      peer = K.peerBytesOf(e);
    } else {
      peer = unb64(b.pubkey);
      if (!peer) fail(400);
      if (peer.length > 70 || peer.length !== K.peerLen(main)) fail(406);
    }
    try { ikm = K.ecdh(main, peer); } catch { fail(406); }
  } else {
    if (!main || !['SHA2-256', 'SHA2-384', 'SHA2-512'].includes(main.type)) fail(406);
    ikm = Buffer.from(main.priv, 'base64');
  }
  if (!K.ALL_TYPES.includes(b.type) || K.isPqc(b.type)) fail(400);
  if (mode?.hpke && !K.HPKE_TYPES.includes(b.type)) fail(400);
  const okm = Buffer.from(crypto.hkdfSync('sha512', ikm, salt, Buffer.from(`encedo-derive:v1:${b.type.toLowerCase()}`), K.deriveLen(b.type)));
  const rec = K.record(b.type, K.fromSecret(b.type, okm), { att: false, label: b.label, descr, mode, now: ctx.now });
  await store(ctx, rec, LOG.KEY_DERIVE);
  return { json: { kid: rec.kid, ...keyJson(rec, { pubkey: b.return_pubkey === true }) } };
}

export async function del(ctx, rest) {
  state409(ctx);
  ctx.needToken();
  ctx.needTls();
  await ctx.needScope(['keymgmt:del'], { noM: true });
  const kid = rest.replace(/^\//, '');
  if (!rest.startsWith('/') || !isHex32(kid)) fail(400);
  const k = await ctx.key(kid);
  if (!k) fail(404);
  await ctx.delKey(kid);
  ctx.dev.deletedKeys = (ctx.dev.deletedKeys ?? 0) + 1;
  ctx.dev.deletedBytes = (ctx.dev.deletedBytes ?? 0) + 192 + (k.pub?.length ?? 0) + (k.priv?.length ?? 0);
  ctx.touch('dev');
  await ctx.log(LOG.KEY_DELETE, 0, ctx.token.sub, k.kid);
  return {};
}
