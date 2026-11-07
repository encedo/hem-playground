// A minimal Redis client: RESP2 over one TCP connection, commands pipelined in
// order. Enough for the hash-per-module layout; no dependency to keep current.

import net from 'node:net';

export class Redis {
  #url; #sock = null; #buf = Buffer.alloc(0); #queue = []; #connecting = null;

  constructor(url = 'redis://127.0.0.1:6379') { this.#url = new URL(url); }

  #connect() {
    if (this.#sock) return Promise.resolve();
    if (this.#connecting) return this.#connecting;
    this.#connecting = new Promise((resolve, reject) => {
      const sock = net.createConnection({ host: this.#url.hostname, port: Number(this.#url.port || 6379) });
      sock.setNoDelay(true);
      sock.once('connect', async () => {
        this.#sock = sock; this.#connecting = null;
        try {
          if (this.#url.password) await this.call('AUTH', decodeURIComponent(this.#url.password));
          const db = this.#url.pathname.slice(1);
          if (db) await this.call('SELECT', db);
          resolve();
        } catch (e) { reject(e); }
      });
      sock.on('data', (d) => { this.#buf = Buffer.concat([this.#buf, d]); this.#drain(); });
      const fail = (err) => {
        this.#sock = null; this.#connecting = null; this.#buf = Buffer.alloc(0);
        const q = this.#queue; this.#queue = [];
        for (const p of q) p.reject(err ?? new Error('redis connection closed'));
        reject(err ?? new Error('redis connection closed'));
      };
      sock.once('error', fail);
      sock.once('close', () => fail(null));
    });
    return this.#connecting;
  }

  #drain() {
    while (this.#queue.length) {
      const r = parse(this.#buf, 0);
      if (!r) return;
      this.#buf = this.#buf.subarray(r.end);
      const p = this.#queue.shift();
      if (r.value instanceof Error) p.reject(r.value); else p.resolve(r.value);
    }
  }

  async call(...args) {
    if (!this.#sock) await this.#connect();
    const parts = [`*${args.length}\r\n`];
    const bufs = [];
    for (const a of args) {
      const b = Buffer.isBuffer(a) ? a : Buffer.from(String(a), 'utf8');
      bufs.push(Buffer.from(`$${b.length}\r\n`), b, Buffer.from('\r\n'));
    }
    const payload = Buffer.concat([Buffer.from(parts[0]), ...bufs]);
    return new Promise((resolve, reject) => {
      this.#queue.push({ resolve, reject });
      this.#sock.write(payload);
    });
  }

  close() { this.#sock?.end(); }
}

/** Parse one RESP2 value at `at`; null when the buffer does not hold it yet. Bulk strings come back as utf8 strings. */
function parse(buf, at) {
  if (at >= buf.length) return null;
  const nl = buf.indexOf('\r\n', at);
  if (nl < 0) return null;
  const type = String.fromCharCode(buf[at]);
  const line = buf.toString('utf8', at + 1, nl);
  const next = nl + 2;
  switch (type) {
    case '+': return { value: line, end: next };
    case '-': return { value: new Error(line), end: next };
    case ':': return { value: Number(line), end: next };
    case '$': {
      const len = Number(line);
      if (len < 0) return { value: null, end: next };
      if (buf.length < next + len + 2) return null;
      return { value: buf.toString('utf8', next, next + len), end: next + len + 2 };
    }
    case '*': {
      const n = Number(line);
      if (n < 0) return { value: null, end: next };
      const out = [];
      let pos = next;
      for (let i = 0; i < n; i++) {
        const r = parse(buf, pos);
        if (!r) return null;
        out.push(r.value); pos = r.end;
      }
      return { value: out, end: pos };
    }
    default: throw new Error(`redis: unexpected reply type ${type}`);
  }
}
