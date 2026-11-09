// Passkeys (WebAuthn) for the panel: an administrator or an owner adds one after signing in,
// and signs in with it afterwards, by Touch ID, Windows Hello or a phone. node:crypto only.
//
// The relying party is the playground's domain, so one passkey serves admin. and account.;
// the role comes from the address, as for a sign-in link. Attestation is "none": who made the
// authenticator does not matter here. The server keeps the public key only, in the hash
// "@passkeys": field = credential id (base64url), value = { email, spki, alg, counter, name, created, used }.

import crypto from 'node:crypto';

export const PASSKEYS = '@passkeys';
const TTL = 300_000;                                   // a challenge is good for five minutes, once
const challenges = new Map();                          // challenge -> { kind, email, exp }

const b64u = (b) => Buffer.from(b).toString('base64url');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();

function newChallenge(kind, email = null) {
  const now = Date.now();
  for (const [k, v] of challenges) if (v.exp < now) challenges.delete(k);
  const c = b64u(crypto.randomBytes(32));
  challenges.set(c, { kind, email, exp: now + TTL });
  return c;
}
function takeChallenge(c, kind) {
  const v = challenges.get(c);
  challenges.delete(c);
  return v && v.kind === kind && v.exp > Date.now() ? v : null;
}

// ---- CBOR, as much as WebAuthn needs (maps, arrays, ints, byte and text strings) ----------------
function cbor(buf, pos = 0) {
  const ib = buf[pos++], major = ib >> 5, info = ib & 31;
  let n = info;
  if (info === 24) n = buf[pos++];
  else if (info === 25) { n = buf.readUInt16BE(pos); pos += 2; }
  else if (info === 26) { n = buf.readUInt32BE(pos); pos += 4; }
  else if (info === 27) { n = Number(buf.readBigUInt64BE(pos)); pos += 8; }
  else if (info > 27) throw new Error('CBOR: indefinite lengths are not used here');
  switch (major) {
    case 0: return [n, pos];
    case 1: return [-1 - n, pos];
    case 2: return [buf.subarray(pos, pos + n), pos + n];
    case 3: return [buf.subarray(pos, pos + n).toString('utf8'), pos + n];
    case 4: { const a = []; for (let i = 0; i < n; i++) { let v; [v, pos] = cbor(buf, pos); a.push(v); } return [a, pos]; }
    case 5: { const m = new Map(); for (let i = 0; i < n; i++) { let k, v; [k, pos] = cbor(buf, pos); [v, pos] = cbor(buf, pos); m.set(k, v); } return [m, pos]; }
    case 7: return [info === 21 ? true : info === 20 ? false : null, pos];
    default: throw new Error('CBOR: unexpected item');
  }
}

/** A COSE public key as a node KeyObject, and its algorithm (-7 ES256, -8 EdDSA, -257 RS256). */
function coseKey(m) {
  const kty = m.get(1), alg = m.get(3);
  let jwk;
  if (kty === 2 && m.get(-1) === 1) jwk = { kty: 'EC', crv: 'P-256', x: b64u(m.get(-2)), y: b64u(m.get(-3)) };
  else if (kty === 1 && m.get(-1) === 6) jwk = { kty: 'OKP', crv: 'Ed25519', x: b64u(m.get(-2)) };
  else if (kty === 3) jwk = { kty: 'RSA', n: b64u(m.get(-1)), e: b64u(m.get(-2)) };
  else throw new Error('That kind of key is not supported.');
  return { key: crypto.createPublicKey({ key: jwk, format: 'jwk' }), alg };
}

/** authenticatorData: rpIdHash, flags, counter and, at registration, the credential. */
function authData(buf) {
  const out = { rpIdHash: buf.subarray(0, 32), flags: buf[32], counter: buf.readUInt32BE(33) };
  if (out.flags & 0x40) {
    const len = buf.readUInt16BE(53);
    out.credId = buf.subarray(55, 55 + len);
    [out.cose] = cbor(buf, 55 + len);
  }
  return out;
}

/** clientDataJSON, checked: the type, a challenge we gave out, and one of our own sites. */
function clientData(raw, type, origins) {
  const c = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
  if (c.type !== type) throw new Error('Wrong ceremony.');
  if (!origins.includes(c.origin)) throw new Error('Wrong site.');
  return c;
}

function checkFlags(a, rpId) {
  if (!crypto.timingSafeEqual(a.rpIdHash, sha256(rpId))) throw new Error('Wrong relying party.');
  if (!(a.flags & 0x01)) throw new Error('The authenticator did not see you.');
  if (!(a.flags & 0x04)) throw new Error('The authenticator did not verify you.');
}

export class Passkeys {
  /** domain: the playground's; origins: the sites a ceremony may come from. */
  constructor(store, domain, origins) { Object.assign(this, { store, domain, origins }); }

  /** The relying party for a site: the domain, so one passkey serves admin. and account.;
   *  a dotless local domain (localhost) is no registrable suffix, so there each site is its own. */
  rpIdOf(origin) { return this.domain.includes('.') ? this.domain : new URL(origin).hostname; }

  /** email -> number of passkeys. */
  async owners() {
    const raw = await this.store.redis.call('HVALS', PASSKEYS), out = new Map();
    for (const v of raw) { const e = JSON.parse(v).email; out.set(e, (out.get(e) ?? 0) + 1); }
    return out;
  }

  async list(email) {
    const raw = await this.store.redis.call('HGETALL', PASSKEYS);
    const out = [];
    for (let i = 0; i < raw.length; i += 2) {
      const v = JSON.parse(raw[i + 1]);
      if (v.email === email.toLowerCase()) out.push({ id: raw[i], ...v });
    }
    return out.sort((a, b) => a.created - b.created);
  }

  /** Options for navigator.credentials.create(), for a signed-in address. */
  async registerOptions(email, origin) {
    email = email.toLowerCase();
    return {
      challenge: newChallenge('create', email),
      rp: { id: this.rpIdOf(origin), name: 'HEM Playground' },
      user: { id: b64u(sha256(`${this.domain}:${email}`).subarray(0, 16)), name: email, displayName: email },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      excludeCredentials: (await this.list(email)).map((k) => ({ type: 'public-key', id: k.id })),
      attestation: 'none', timeout: TTL,
    };
  }

  /** The browser's answer to create(): { clientDataJSON, attestationObject } in base64url, and a name. */
  async register(email, { clientDataJSON, attestationObject }, name) {
    email = email.toLowerCase();
    const c = clientData(clientDataJSON, 'webauthn.create', this.origins);
    const ch = takeChallenge(c.challenge, 'create');
    if (!ch || ch.email !== email) throw new Error('This request has expired. Try again.');
    const [att] = cbor(Buffer.from(attestationObject, 'base64url'));
    const a = authData(att.get('authData'));
    checkFlags(a, this.rpIdOf(c.origin));
    if (!a.credId) throw new Error('No credential in the answer.');
    const { key, alg } = coseKey(a.cose);
    const id = b64u(a.credId);
    if (await this.store.get(PASSKEYS, id)) throw new Error('This passkey is already registered.');
    const now = Math.floor(Date.now() / 1000);
    const rec = { email, spki: key.export({ format: 'der', type: 'spki' }).toString('base64'), alg, counter: a.counter, name: String(name || 'Passkey').slice(0, 60), created: now, used: 0 };
    await this.store.set(PASSKEYS, { [id]: rec });
    return { id, ...rec };
  }

  /** Options for navigator.credentials.get(): no address, the browser offers the passkeys it has. */
  loginOptions(origin) {
    return { challenge: newChallenge('get'), rpId: this.rpIdOf(origin), userVerification: 'required', timeout: TTL };
  }

  /** The browser's answer to get(): the address the passkey belongs to, or an error. */
  async login({ id, clientDataJSON, authenticatorData, signature }) {
    const c = clientData(clientDataJSON, 'webauthn.get', this.origins);
    if (!takeChallenge(c.challenge, 'get')) throw new Error('This request has expired. Try again.');
    const rec = await this.store.get(PASSKEYS, String(id));
    if (!rec) throw new Error('This passkey is not known here. Sign in with a link and add it again.');
    const ad = Buffer.from(authenticatorData, 'base64url');
    const a = authData(ad);
    checkFlags(a, this.rpIdOf(c.origin));
    const key = crypto.createPublicKey({ key: Buffer.from(rec.spki, 'base64'), format: 'der', type: 'spki' });
    const data = Buffer.concat([ad, sha256(Buffer.from(clientDataJSON, 'base64url'))]);
    const sig = Buffer.from(signature, 'base64url');
    const ok = rec.alg === -8 ? crypto.verify(null, data, key, sig) : crypto.verify('sha256', data, key, sig);
    if (!ok) throw new Error('The signature does not verify.');
    if ((a.counter || rec.counter) && a.counter <= rec.counter) throw new Error('This passkey looks cloned; it is not accepted.');
    await this.store.set(PASSKEYS, { [id]: { ...rec, counter: a.counter, used: Math.floor(Date.now() / 1000) } });
    return rec.email;
  }

  async remove(email, id) {
    const rec = await this.store.get(PASSKEYS, String(id));
    if (!rec || rec.email !== email.toLowerCase()) return null;
    await this.store.del(PASSKEYS, String(id));
    return rec;
  }
}

/** The browser side: base64url both ways, and the two ceremonies. Inlined into the pages. */
export const CLIENT = `
const pkB = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
const pkU = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
async function pkPost(url, body, csrf) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF': csrf } : {}) }, body: JSON.stringify(body ?? {}) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'The server said no.');
  return j;
}
async function pkLogin(note) {
  try {
    const o = await pkPost('/passkey/options');
    const c = await navigator.credentials.get({ publicKey: { ...o, challenge: pkU(o.challenge) } });
    const r = await pkPost('/passkey/login', { id: c.id, clientDataJSON: pkB(c.response.clientDataJSON), authenticatorData: pkB(c.response.authenticatorData), signature: pkB(c.response.signature) });
    location.href = r.to;
  } catch (e) { if (e.name !== 'NotAllowedError') { note.textContent = e.message; note.hidden = false; } }
}
async function pkAdd(csrf, note) {
  try {
    const o = await pkPost('/passkey/new', {}, csrf);
    const c = await navigator.credentials.create({ publicKey: { ...o, challenge: pkU(o.challenge), user: { ...o.user, id: pkU(o.user.id) }, excludeCredentials: o.excludeCredentials.map((x) => ({ ...x, id: pkU(x.id) })) } });
    const ua = navigator.userAgent, name = /iPhone|iPad/.test(ua) ? 'iPhone or iPad' : /Android/.test(ua) ? 'Android' : /Mac/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : 'Passkey';
    await pkPost('/passkey/add', { name, clientDataJSON: pkB(c.response.clientDataJSON), attestationObject: pkB(c.response.attestationObject) }, csrf);
    location.reload();
  } catch (e) { if (e.name === 'InvalidStateError') e.message = 'This device already has a passkey for your address.'; if (e.name !== 'NotAllowedError') { note.textContent = e.message; note.hidden = false; } }
}
`;
