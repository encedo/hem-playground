// Modules as the playground sees them: registration, the admin's actions, settings.

import crypto from 'node:crypto';
import { PREFIX_RE } from './lib/store.mjs';
import { createModule } from './sim/index.mjs';
import { newBoot, newDevice, newLogFile, logAppend, LOG } from './sim/device.mjs';

export const DEFAULT_SETTINGS = {
  mode: 'auto',                // auto | email | approve
  modulesPerEmail: 3, keysPerModule: 512, rpm: 3000, idleDays: 30, logKeep: 200,
  reserved: 'admin manager www api broker mail smtp playground test-*',
};
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
  constructor(store, domain, mailer) { Object.assign(this, { store, domain, mailer }); }

  async settings() { return { ...DEFAULT_SETTINGS, ...(await this.store.settings()) }; }

  isReserved(prefix, s) {
    return s.reserved.split(/\s+/).filter(Boolean).some((r) => (r.endsWith('*') ? prefix.startsWith(r.slice(0, -1)) : prefix === r));
  }

  /** Why `prefix` cannot be registered, or null. */
  async whyNot(prefix, s) {
    if (!PREFIX_RE.test(prefix)) return 'A prefix is 3 to 32 characters of a–z, 0–9 and hyphens, starting and ending with a letter or digit.';
    if (this.isReserved(prefix, s)) return `${prefix} is reserved.`;
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

  async register({ prefix, email, variant }) {
    const s = await this.settings();
    prefix = String(prefix ?? '').trim().toLowerCase();
    email = String(email ?? '').trim();
    variant = variant === 'EPA' ? 'EPA' : 'PPA';
    const why = await this.whyNot(prefix, s);
    if (why) return { error: why };
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 120) return { error: 'That does not look like an e-mail address.' };
    if (s.modulesPerEmail > 0) {
      const mine = (await this.all()).filter((m) => m.email.toLowerCase() === email.toLowerCase()).length;
      if (mine >= s.modulesPerEmail) return { error: `${email} already has ${mine} modules, the most one address may have here.` };
    }
    const now = Math.floor(Date.now() / 1000);
    const meta = { prefix, email, variant, created: now, lastReq: 0, state: s.mode === 'auto' ? 'active' : 'unconfirmed' };
    if (s.mode !== 'auto') { meta.confirm = crypto.randomBytes(24).toString('base64url'); meta.confirmExp = now + 86400; }
    const { dev, boot } = createModule(variant, `${prefix}.${this.domain}`);
    await this.store.set(prefix, { meta, dev, boot, ...factoryLogs(dev, boot) });
    if (s.mode !== 'auto') {
      const link = `https://${this.domain}/confirm?p=${encodeURIComponent(prefix)}&t=${meta.confirm}`;
      await this.mailer.send(email, `Confirm ${prefix}.${this.domain}`,
        `Open this link to confirm the virtual module ${prefix}.${this.domain}:\n\n${link}\n\nThe link is good for 24 hours. If you did not ask for it, ignore this message and the prefix is freed.`);
    }
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
