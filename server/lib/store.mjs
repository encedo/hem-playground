// Storage layout: ONE Redis hash per virtual module, named by its prefix.
// Fields (JSON values):
//   meta        owner, variant, state (active | pending | blocked), dates, counters
//   dev         the module's persistent state: identity keys, config, init time
//   boot        what a power cycle resets: session key, issued nonces, uptime base
//   k:<kid>     one key record
//   log         the last N API requests (admin view), newest first
//   audit:<id>  one audit-log file (PPA logger), id = 8 hex of the boot time
// Global settings live in the hash "@settings" ("@" never appears in a prefix).
// A module's values are encrypted at rest when PG_DATA_KEY is set (datakey.mjs); field
// names and the "@" hashes stay plain.

import { Redis } from './redis.mjs';
import * as dk from './datakey.mjs';

const RESEAL_LUA = "if redis.call('HGET', KEYS[1], ARGV[1]) == ARGV[2] then redis.call('HSET', KEYS[1], ARGV[1], ARGV[3]) return 1 end return 0";

/** Module hashes are sealed; the global "@" hashes are not. */
const sealed = (prefix) => !prefix.startsWith('@');
const dec = (prefix, field, raw) => (raw == null ? null : JSON.parse(sealed(prefix) ? dk.open(prefix, field, raw) : raw));
const enc = (prefix, field, v) => (sealed(prefix) ? dk.seal(prefix, field, JSON.stringify(v)) : JSON.stringify(v));

export const SETTINGS_KEY = '@settings';
export const PREFIX_RE = /^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])$/;

export class Store {
  constructor(url) { this.redis = new Redis(url); this.locks = new Map(); }

  /** Run fn with the module's lock held, so two requests never interleave their read-modify-write. */
  async withLock(prefix, fn) {
    const prev = this.locks.get(prefix) ?? Promise.resolve();
    let release;
    const mine = new Promise((r) => { release = r; });
    const chained = prev.then(() => mine);
    this.locks.set(prefix, chained);
    await prev;
    try { return await fn(); } finally {
      release();
      if (this.locks.get(prefix) === chained) this.locks.delete(prefix);
    }
  }

  async exists(prefix) { return (await this.redis.call('EXISTS', prefix)) === 1; }

  async get(prefix, field) {
    return dec(prefix, field, await this.redis.call('HGET', prefix, field));
  }

  async getMany(prefix, fields) {
    const vals = await this.redis.call('HMGET', prefix, ...fields);
    const out = {};
    fields.forEach((f, i) => { out[f] = dec(prefix, f, vals[i]); });
    return out;
  }

  async set(prefix, obj) {
    const args = [];
    for (const [k, v] of Object.entries(obj)) args.push(k, enc(prefix, k, v));
    if (args.length) await this.redis.call('HSET', prefix, ...args);
  }

  async del(prefix, ...fields) { if (fields.length) await this.redis.call('HDEL', prefix, ...fields); }

  async fields(prefix, match) {
    const out = [];
    let cursor = '0';
    do {
      const [next, items] = await this.redis.call('HSCAN', prefix, cursor, 'MATCH', match, 'COUNT', 500);
      for (let i = 0; i < items.length; i += 2) out.push([items[i], dec(prefix, items[i], items[i + 1])]);
      cursor = next;
    } while (cursor !== '0');
    return out;
  }

  /** Every field of a hash as Redis holds it (encrypted or not), for the migration tool. */
  async raw(prefix) {
    const r = await this.redis.call('HGETALL', prefix), out = [];
    for (let i = 0; i < r.length; i += 2) out.push([r[i], r[i + 1]]);
    return out;
  }

  /**
   * Rewrite one stored value under the current key, from plain JSON or from PG_DATA_KEY_OLD,
   * only if Redis still holds `raw` (the app may have written it meanwhile). True when rewritten.
   */
  async reseal(prefix, field, raw) {
    const next = dk.seal(prefix, field, dk.open(prefix, field, raw));
    return (await this.redis.call('EVAL', RESEAL_LUA, 1, prefix, field, raw, next)) === 1;
  }

  /**
   * Start-up check on every module's meta: refuse to run when Redis holds module data under
   * a key the app does not have (PG_DATA_KEY missing or wrong), because every such module
   * would answer 500.
   */
  async checkDataKey() {
    for (const p of await this.prefixes()) {
      const id = dk.keyIdOf(await this.redis.call('HGET', p, 'meta'));
      if (id && !dk.knows(id)) {
        throw new Error(dk.enabled()
          ? `Redis holds module data under key ${id} (e.g. ${p}), which is neither PG_DATA_KEY nor PG_DATA_KEY_OLD`
          : 'Redis holds encrypted module data, but PG_DATA_KEY is not set');
      }
    }
    return dk.enabled() ? `data at rest encrypted (key ${dk.currentId()})` : 'PG_DATA_KEY not set: module data is stored in plain text';
  }

  async drop(prefix) { await this.redis.call('DEL', prefix); }

  /** Every module prefix, by scanning hash keys and leaving out the "@" ones. */
  async prefixes() {
    const out = [];
    let cursor = '0';
    do {
      const [next, keys] = await this.redis.call('SCAN', cursor, 'COUNT', 500, 'TYPE', 'hash');
      for (const k of keys) if (!k.startsWith('@')) out.push(k);
      cursor = next;
    } while (cursor !== '0');
    return out.sort();
  }

  async settings() {
    const raw = await this.redis.call('HGETALL', SETTINGS_KEY);
    const out = {};
    for (let i = 0; i < raw.length; i += 2) out[raw[i]] = JSON.parse(raw[i + 1]);
    return out;
  }
  async saveSettings(obj) { await this.set(SETTINGS_KEY, obj); }
}
