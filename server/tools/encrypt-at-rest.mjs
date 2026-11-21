// Bring every module's data under the current PG_DATA_KEY: plain fields from before the
// key, and fields under PG_DATA_KEY_OLD after a rotation. Safe to run while the app runs:
// a field is rewritten only if Redis still holds the value read (compare-and-set in Lua),
// and one the app wrote meanwhile is already under the current key. Safe to run again:
// with nothing to do it does nothing.
//   node server/tools/encrypt-at-rest.mjs [--dry-run]
// In the container: docker compose exec -T app node server/tools/encrypt-at-rest.mjs
// After a run that changed something it rewrites the AOF and saves a snapshot, so Redis's
// files on disk no longer hold the plain values. Copies made earlier still do.

import { Store } from '../lib/store.mjs';
import * as dk from '../lib/datakey.mjs';

const dry = process.argv.includes('--dry-run');
const store = new Store(process.env.REDIS_URL || 'redis://127.0.0.1:6379');
const cur = dk.currentId();
if (!cur && !dry) { console.error('PG_DATA_KEY is not set: nothing to encrypt with'); process.exit(2); }

const count = {};                         // 'plain' or a key id -> fields
let modules = 0, changed = 0, failed = 0;
for (const prefix of await store.prefixes()) {
  modules++;
  for (const [field, raw] of await store.raw(prefix)) {
    const id = dk.keyIdOf(raw) ?? 'plain';
    count[id] = (count[id] ?? 0) + 1;
    if (dry || id === cur) continue;
    try { if (await store.reseal(prefix, field, raw)) changed++; } catch (e) { failed++; console.error(e.message); }
  }
}

const summary = Object.entries(count).map(([k, n]) => `${n} ${k === 'plain' ? 'plain' : `under key ${k}${k === cur ? ' (current)' : ''}`}`).join(', ') || 'no fields';
console.log(`${modules} modules: ${summary}`);
if (dry) {
  const todo = Object.entries(count).filter(([k]) => k !== cur).reduce((a, [, n]) => a + n, 0);
  console.log(cur ? `${todo} fields to encrypt under key ${cur}` : 'PG_DATA_KEY is not set');
} else {
  console.log(`${changed} fields encrypted under key ${cur}${failed ? `, ${failed} failed` : ''}`);
  if (changed) {
    await store.redis.call('BGREWRITEAOF').catch((e) => console.error('BGREWRITEAOF:', e.message));
    await store.redis.call('BGSAVE', 'SCHEDULE').catch((e) => console.error('BGSAVE:', e.message));
    console.log('Redis rewrites its AOF and snapshot in the background');
  }
}
store.redis.close();
process.exit(failed ? 1 : 0);
