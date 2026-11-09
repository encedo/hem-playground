// Modules as the playground sees them: registration, the admin's actions, settings.

import crypto from 'node:crypto';
import { PREFIX_RE } from './lib/store.mjs';
import { createModule } from './sim/index.mjs';
import { newBoot, newDevice, newLogFile, logAppend, LOG } from './sim/device.mjs';

export const DEFAULT_SETTINGS = {
  mode: 'auto',                // auto | email | approve
  modulesPerEmail: 3, keysPerModule: 512, rpm: 3000, idleDays: 30, logKeep: 200,
  notifyNew: true,             // e-mail the administrators on a registration and on its confirmation
  admins: [],                  // administrators added in the panel (besides ADMIN_EMAILS)
};

// Reserved prefixes. The system names are fixed here (the sites, and the DNS names
// that have records of their own: acme / ns-acme are the certificate's acme-dns).
// Everything else is the hash "@reserved": field = pattern (a-z 0-9 - and * for
// "anything"), value = { kind, note, added, by }.
export const RESERVED_KEY = '@reserved';
export const SYSTEM_RESERVED = ['www', 'admin', 'account', 'manager', 'acme', 'ns-acme', 'api', 'broker', 'mail', 'smtp', 'mx', 'ns', 'ns1', 'ns2', 'playground', 'static', 'status', 'health'];
export const RESERVED_KINDS = { brand: 'Brand', offensive: 'Offensive', premium: 'Premium', other: 'Other' };
export const PATTERN_RE = /^[a-z0-9*-]{1,40}$/;
const globRe = (p) => new RegExp('^' + p.split('*').map((x) => x.replace(/[-]/g, '\\-')).join('.*') + '$');
export const patternMatches = (pattern, prefix) => globRe(pattern).test(prefix);
export const MODE_LABEL = { auto: 'automatic', email: 'e-mail confirmation', approve: 'e-mail and approval' };

/**
 * The audit log a module starts with: the factory session before it was handed
 * over (a real PPA always has older files), and the file of the current boot.
 */
function factoryLogs(dev, boot) {
  const before = { logId: Math.floor(boot.started / 1000 - 3600).toString(16).padStart(8, '0') };
  const f0 = newLogFile(dev, before);
  logAppend(f0, LOG.STARTUP, 0); logAppend(f0, LOG.SELFTEST_PASSED, 0); logAppend(f0, LOG.SHUTDOWN, 0);
  const f1 = newLogFile(dev, boot); logAppend(f1, LOG.STARTUP, 0);
  return { [`audit:${f0.id}`]: f0, [`audit:${f1.id}`]: f1 };
}

export class Registry {
  /** admins(settings): the administrators' addresses, told of new modules. */
  constructor(store, domain, mailer, admins = () => []) { Object.assign(this, { store, domain, mailer, admins }); }

  /** Tell the administrators of a registration or a confirmation, when the setting asks for it. Never fails the caller. */
  async notifyAdmins(s, meta, what) {
    const to = this.admins(s);
    if (!s.notifyNew || !to.length) return;
    const host = `${meta.prefix}.${this.domain}`;
    const text = `${what}\n\nPrefix:   ${meta.prefix}\nE-mail:   ${meta.email}\nVariant:  ${meta.variant}\nState:    ${meta.state}\n\nhttps://admin.${this.domain}/m/${encodeURIComponent(meta.prefix)}\n\nThese messages are switched off under Settings, Options.`;
    for (const a of to) await this.mailer.send(a, `${what.split('.')[0]}: ${host}`, text).catch((e) => console.error('mail', e.message));
  }

  async addAdmin(email) {
    email = String(email ?? '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 120) return { error: 'That does not look like an e-mail address.' };
    const s = await this.settings();
    if (!s.admins.includes(email)) await this.store.saveSettings({ admins: [...s.admins, email].sort() });
    return { email };
  }
  async removeAdmin(email) {
    const s = await this.settings();
    await this.store.saveSettings({ admins: s.admins.filter((x) => x !== String(email ?? '').toLowerCase()) });
  }

  async settings() { const { reserved, ...rest } = await this.store.settings(); return { ...DEFAULT_SETTINGS, ...rest }; }

  // ---- reserved prefixes ----------------------------------------------------------------
  async reservedList() {
    const raw = await this.store.redis.call('HGETALL', RESERVED_KEY);
    const out = [];
    for (let i = 0; i < raw.length; i += 2) out.push({ pattern: raw[i], ...JSON.parse(raw[i + 1]) });
    return out.sort((a, b) => a.kind.localeCompare(b.kind) || a.pattern.localeCompare(b.pattern));
  }
  async reserve(patterns, kind, note, by) {
    const now = Math.floor(Date.now() / 1000);
    const ok = [], bad = [];
    for (let p of patterns) {
      p = p.trim().toLowerCase();
      if (!p) continue;
      if (!PATTERN_RE.test(p) || SYSTEM_RESERVED.includes(p)) { bad.push(p); continue; }
      ok.push(p);
    }
    if (ok.length) {
      const args = [];
      for (const p of ok) args.push(p, JSON.stringify({ kind: RESERVED_KINDS[kind] ? kind : 'other', note: String(note ?? '').slice(0, 200), added: now, by }));
      await this.store.redis.call('HSET', RESERVED_KEY, ...args);
    }
    return { ok, bad };
  }
  async unreserve(pattern) { await this.store.redis.call('HDEL', RESERVED_KEY, pattern); }
  /** The rule that reserves `prefix`: { pattern, kind, system } or null. */
  async reservedBy(prefix) {
    if (SYSTEM_RESERVED.includes(prefix)) return { pattern: prefix, kind: 'system', system: true };
    for (const r of await this.reservedList()) if (patternMatches(r.pattern, prefix)) return r;
    return null;
  }
  /** One-off: the old space-separated settings field becomes rows of @reserved. */
  async migrateReserved() {
    const old = (await this.store.settings()).reserved;
    if (typeof old !== 'string') return;
    await this.reserve(old.split(/\s+/).filter((p) => p && !SYSTEM_RESERVED.includes(p)), 'other', 'from the earlier settings', 'migration');
    await this.store.redis.call('HDEL', '@settings', 'reserved');
  }

  /** Why `prefix` cannot be registered, or null. byAdmin: reserved prefixes other than the system ones are allowed. */
  async whyNot(prefix, s, { byAdmin = false } = {}) {
    if (!PREFIX_RE.test(prefix)) return 'A prefix is 3 to 32 characters of a–z, 0–9 and hyphens, starting and ending with a letter or digit.';
    const r = await this.reservedBy(prefix);
    if (r && (r.system || !byAdmin)) return `${prefix} is not available.`;   // the reason stays with the administrator
    if (await this.store.exists(prefix)) return `${prefix}.${this.domain} is taken.`;
    return null;
  }

  async all() {
    const out = [];
    for (const p of await this.store.prefixes()) {
      const { meta, dev } = await this.store.getMany(p, ['meta', 'dev']);
      if (!meta) continue;
      const keys = (await this.store.redis.call('HKEYS', p)).filter((f) => f.startsWith('k:')).length;
      out.push({ ...meta, inited: dev?.inited ?? 0, user: dev?.cfg?.user ?? '', keys });
    }
    return out;
  }

  /**
   * byAdmin: a module the administrator makes for someone - reserved (not system) prefixes allowed, no limit, live at once.
   * verified: the e-mail is already proven (an owner signed in), so there is no confirmation; approval still applies.
   */
  async register({ prefix, email, variant }, { byAdmin = false, verified = false } = {}) {
    const s = await this.settings(), s0 = { ...s };
    if (byAdmin) s.mode = 'auto';
    const approve = verified && s.mode === 'approve';
    if (verified) s.mode = 'auto';
    prefix = String(prefix ?? '').trim().toLowerCase();
    email = String(email ?? '').trim();
    variant = variant === 'EPA' ? 'EPA' : 'PPA';
    const why = await this.whyNot(prefix, s, { byAdmin });
    if (why) return { error: why };
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 120) return { error: 'That does not look like an e-mail address.' };
    if (s.modulesPerEmail > 0 && !byAdmin) {
      const mine = (await this.all()).filter((m) => m.email.toLowerCase() === email.toLowerCase()).length;
      if (mine >= s.modulesPerEmail) return { error: `${email} already has ${mine} modules, the most one address may have here.` };
    }
    const now = Math.floor(Date.now() / 1000);
    const meta = { prefix, email, variant, created: now, lastReq: 0, state: approve ? 'pending' : s.mode === 'auto' ? 'active' : 'unconfirmed' };
    if (verified) meta.confirmed = now;
    if (byAdmin) meta.byAdmin = true;
    if (s.mode !== 'auto') { meta.confirm = crypto.randomBytes(24).toString('base64url'); meta.confirmExp = now + 86400; }
    const { dev, boot } = createModule(variant, `${prefix}.${this.domain}`);
    await this.store.set(prefix, { meta, dev, boot, ...factoryLogs(dev, boot) });
    if (s.mode !== 'auto') {
      const link = `https://${this.domain}/confirm?p=${encodeURIComponent(prefix)}&t=${meta.confirm}`;
      await this.mailer.send(email, `Confirm ${prefix}.${this.domain}`,
        `Open this link to confirm the virtual module ${prefix}.${this.domain}:\n\n${link}\n\nThe link is good for 24 hours. If you did not ask for it, ignore this message and the prefix is freed.`);
    }
    if (!byAdmin) await this.notifyAdmins(s0, meta, 'New module registered.');
    return { meta };
  }

  async confirm(prefix, token) {
    const meta = await this.store.get(prefix, 'meta');
    if (!meta || meta.state !== 'unconfirmed' || !meta.confirm || meta.confirm !== token) return { error: 'This link is not valid any more.' };
    if (meta.confirmExp < Date.now() / 1000) { await this.store.drop(prefix); return { error: 'The link has expired and the prefix is free again.' }; }
    const s = await this.settings();
    meta.state = s.mode === 'approve' ? 'pending' : 'active';
    meta.confirmed = Math.floor(Date.now() / 1000);
    delete meta.confirm; delete meta.confirmExp;
    await this.store.set(prefix, { meta });
    await this.notifyAdmins(s, meta, 'Module confirmed by e-mail.');
    return { meta };
  }

  /** approve | reject | block | unblock | reboot | reset | delete */
  async act(prefix, action) {
    return this.store.withLock(prefix, async () => {
      const { meta, dev } = await this.store.getMany(prefix, ['meta', 'dev']);
      if (!meta) return { error: 'No such module.' };
      switch (action) {
        case 'approve': meta.state = 'active'; break;
        case 'reject': case 'delete': await this.store.drop(prefix); return { gone: true };
        case 'block': meta.state = 'blocked'; break;
        case 'unblock': meta.state = 'active'; break;
        case 'reboot': {
          const b = newBoot(dev); const f = newLogFile(dev, b); logAppend(f, LOG.STARTUP, 0);
          await this.store.set(prefix, { dev, boot: b, [`audit:${f.id}`]: f });
          return { meta };
        }
        case 'reset': {
          const fresh = newDevice(dev.variant); fresh.hostname = dev.hostname;
          await this.store.drop(prefix);
          const b = newBoot(fresh);
          await this.store.set(prefix, { meta, dev: fresh, boot: b, ...factoryLogs(fresh, b) });
          return { meta };
        }
        default: return { error: 'Unknown action.' };
      }
      await this.store.set(prefix, { meta });
      return { meta };
    });
  }

  /** Drop modules idle for longer than the setting; unconfirmed ones after their link expires. */
  async sweep() {
    const s = await this.settings();
    const now = Date.now() / 1000;
    for (const m of await this.all()) {
      if (m.state === 'unconfirmed' && m.confirmExp && m.confirmExp < now) await this.store.drop(m.prefix);
      else if (s.idleDays > 0 && m.state !== 'pending' && now - Math.max(m.lastReq, m.created) > s.idleDays * 86400) await this.store.drop(m.prefix);
    }
  }
}
