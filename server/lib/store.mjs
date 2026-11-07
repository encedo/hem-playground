// Storage layout: ONE Redis hash per virtual module, named by its prefix.
// Fields (JSON values):
//   meta        owner, variant, state (active | pending | blocked), dates, counters
//   dev         the module's persistent state: identity keys, config, init time
//   boot        what a power cycle resets: session key, issued nonces, uptime base
//   k:<kid>     one key record
//   log         the last N API requests (admin view), newest first
//   audit:<id>  one audit-log file (PPA logger), id = 8 hex of the boot time
// Global settings live in the hash "@settings" ("@" never appears in a prefix).

import { Redis } from './redis.mjs';

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
    const v = await this.redis.call('HGET', prefix, field);
    return v == null ? null : JSON.parse(v);
  }

  async getMany(prefix, fields) {
    const vals = await this.redis.call('HMGET', prefix, ...fields);
    const out = {};
    fields.forEach((f, i) => { out[f] = vals[i] == null ? null : JSON.parse(vals[i]); });
    return out;
  }

  async set(prefix, obj) {
    const args = [];
    for (const [k, v] of Object.entries(obj)) args.push(k, JSON.stringify(v));
    if (args.length) await this.redis.call('HSET', prefix, ...args);
  }

  async del(prefix, ...fields) { if (fields.length) await this.redis.call('HDEL', prefix, ...fields); }

  async fields(prefix, match) {
    const out = [];
    let cursor = '0';
    do {
      const [next, items] = await this.redis.call('HSCAN', prefix, cursor, 'MATCH', match, 'COUNT', 500);
      for (let i = 0; i < items.length; i += 2) out.push([items[i], JSON.parse(items[i + 1])]);
      cursor = next;
    } while (cursor !== '0');
    return out;
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
