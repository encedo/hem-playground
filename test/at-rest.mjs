// Encryption at rest (server/lib/datakey.mjs, store.mjs).
//   node test/at-rest.mjs                              the cipher alone: format, AAD, rotation, wrong key
//   node test/at-rest.mjs redis://127.0.0.1:6379 test  also: every value of module "test" in that Redis
//                                                      is encrypted, and no "@" hash is
// With docker compose Redis is not published; check a module there with
//   docker compose exec -T redis redis-cli HVALS test | grep -vc '^e1:'      (0 = all encrypted)
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const A = crypto.randomBytes(32).toString('base64'), B = crypto.randomBytes(32).toString('base64');
let n = 0;
/** A fresh copy of datakey.mjs that has read these environment variables. */
async function withKeys(cur, old) {
  const env = { PG_DATA_KEY: process.env.PG_DATA_KEY, PG_DATA_KEY_OLD: process.env.PG_DATA_KEY_OLD };
  process.env.PG_DATA_KEY = cur ?? ''; process.env.PG_DATA_KEY_OLD = old ?? '';
  try { return await import(`../server/lib/datakey.mjs?${++n}`); } finally { Object.assign(process.env, env); }
}
const ok = (name) => console.log(`ok   ${name}`);

const none = await withKeys(null);
assert.equal(none.seal('test', 'dev', '{"a":1}'), '{"a":1}'); ok('no key: stored as plain JSON');

const a = await withKeys(A);
const v = a.seal('test', 'k:abc', '{"secret":"x"}');
assert.match(v, /^e1:[0-9a-f]{8}:[A-Za-z0-9+/=]+$/); assert.ok(!v.includes('secret')); ok('with a key: e1:<id>:<base64>, no plain text');
assert.notEqual(a.seal('test', 'k:abc', '{"secret":"x"}'), v); ok('a new IV for every write');
assert.equal(a.open('test', 'k:abc', v), '{"secret":"x"}'); ok('decrypts');
assert.equal(a.open('test', 'dev', '{"plain":true}'), '{"plain":true}'); ok('plain JSON from before the key is read as it is');
assert.throws(() => a.open('other', 'k:abc', v), /does not decrypt/); ok('AAD: copied to another module, does not decrypt');
assert.throws(() => a.open('test', 'k:def', v), /does not decrypt/); ok('AAD: moved to another field, does not decrypt');
const t = Buffer.from(v.split(':')[2], 'base64'); t[20] ^= 1;
assert.throws(() => a.open('test', 'k:abc', `e1:${a.currentId()}:${t.toString('base64')}`), /does not decrypt/); ok('a changed byte does not decrypt');

const b = await withKeys(B, A);
assert.equal(b.open('test', 'k:abc', v), '{"secret":"x"}'); ok('rotation: the old key still reads');
assert.equal(b.keyIdOf(b.seal('test', 'k:abc', '{}')), b.currentId()); assert.notEqual(b.currentId(), a.currentId()); ok('rotation: writes use the new key');
const onlyB = await withKeys(B);
assert.throws(() => onlyB.open('test', 'k:abc', v), /neither PG_DATA_KEY nor PG_DATA_KEY_OLD/); ok('an unknown key id is named, not guessed');
await assert.rejects(withKeys('c2hvcnQ='), /not 32 bytes/); ok('a key that is not 32 bytes stops the start');

// a live Redis: every value of the module is sealed, the "@" hashes are not
const [url, prefix] = process.argv.slice(2);
if (url && prefix) {
  const { Redis } = await import('../server/lib/redis.mjs');
  const r = new Redis(url);
  const vals = await r.call('HVALS', prefix);
  assert.ok(vals.length, `no module ${prefix} in ${url}`);
  const plain = vals.filter((x) => !x.startsWith('e1:'));
  assert.equal(plain.length, 0, `${plain.length} of ${vals.length} fields of ${prefix} are plain`); ok(`${prefix}: all ${vals.length} fields encrypted`);
  for (const h of ['@settings', '@reserved']) {
    const hv = await r.call('HVALS', h);
    assert.ok(hv.every((x) => !x.startsWith('e1:')), `${h} is encrypted`);
  }
  ok('@ hashes stay plain');
  r.close();
}
console.log('all passed');
