// Module data encrypted at rest. Every field of a module's hash is AES-256-GCM under
// PG_DATA_KEY before it goes into Redis; the field's place (prefix and name) is the AAD,
// so a value copied to another module or field does not decrypt.
//
//   PG_DATA_KEY      32 random bytes, base64 (openssl rand -base64 32) - only in the
//                    server's .env, never in Redis
//   PG_DATA_KEY_OLD  the previous key, read only, while a rotation runs
//
// Stored value: e1:<key id>:<base64 of iv[12] | ciphertext | tag[16]>, key id = the first
// 8 hex of SHA-256(key). A value without "e1:" is plain JSON from before, read as it is.
// Without PG_DATA_KEY nothing is encrypted (local development).

import crypto from 'node:crypto';

const TAG = 'e1:';

function load(name) {
  const v = String(process.env[name] ?? '').trim().replace(/^"|"$/g, '');
  if (!v) return null;
  const key = Buffer.from(v, 'base64');
  if (key.length !== 32) throw new Error(`${name} is not 32 bytes in base64 (openssl rand -base64 32)`);
  return { id: crypto.createHash('sha256').update(key).digest('hex').slice(0, 8), key };
}

const current = load('PG_DATA_KEY');
const old = load('PG_DATA_KEY_OLD');
const byId = new Map([old, current].filter(Boolean).map((k) => [k.id, k]));

const aad = (prefix, field) => Buffer.from(`${prefix}\0${field}`, 'utf8');

/** Is a data key set? */
export const enabled = () => !!current;
/** The id of the key new writes use, or null. */
export const currentId = () => current?.id ?? null;
/** Can a value under this key id be read (PG_DATA_KEY or PG_DATA_KEY_OLD)? */
export const knows = (id) => byId.has(id);
/** Is this stored value encrypted, and under which key id (null when plain)? */
export const keyIdOf = (raw) => (typeof raw === 'string' && raw.startsWith(TAG) ? raw.slice(TAG.length, raw.indexOf(':', TAG.length)) : null);

/** The JSON text of one field, as Redis is to hold it. */
export function seal(prefix, field, text) {
  if (!current) return text;
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', current.key, iv);
  c.setAAD(aad(prefix, field));
  const body = Buffer.concat([iv, c.update(text, 'utf8'), c.final(), c.getAuthTag()]);
  return `${TAG}${current.id}:${body.toString('base64')}`;
}

/** The JSON text of one field, from what Redis holds. Throws when it cannot be decrypted. */
export function open(prefix, field, raw) {
  if (raw == null || !raw.startsWith(TAG)) return raw;
  const id = keyIdOf(raw);
  const k = byId.get(id);
  if (!k) throw new Error(`${prefix}/${field}: encrypted under key ${id}, which is neither PG_DATA_KEY nor PG_DATA_KEY_OLD`);
  const body = Buffer.from(raw.slice(TAG.length + id.length + 1), 'base64');
  if (body.length < 28) throw new Error(`${prefix}/${field}: encrypted value is too short`);
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', k.key, body.subarray(0, 12));
    d.setAAD(aad(prefix, field));
    d.setAuthTag(body.subarray(body.length - 16));
    return Buffer.concat([d.update(body.subarray(12, body.length - 16)), d.final()]).toString('utf8');
  } catch { throw new Error(`${prefix}/${field}: does not decrypt (wrong key, or the value was moved from another field)`); }
}
