// Plain-text mail over SMTP (STARTTLS on 587, implicit TLS on 465). Without
// SMTP_HOST the message is written to the log instead, which is enough locally.

import net from 'node:net';
import tls from 'node:tls';

export class Mailer {
  constructor(env = process.env) {
    this.host = env.SMTP_HOST; this.port = Number(env.SMTP_PORT || 587);
    this.user = env.SMTP_USER; this.pass = env.SMTP_PASS; this.from = env.MAIL_FROM || 'playground@ence.do';
  }
  get configured() { return !!this.host; }

  async send(to, subject, text) {
    if (!this.configured) { console.log(`[mail] to ${to}: ${subject}\n${text}`); return; }
    let sock = this.port === 465 ? tls.connect({ host: this.host, port: this.port, servername: this.host }) : net.connect({ host: this.host, port: this.port });
    let buf = '';
    const waiters = [];
    const onData = (d) => { buf += d.toString(); let m; while ((m = /^(\d{3}) .*\r\n/m.exec(buf))) { const end = buf.indexOf(m[0]) + m[0].length; const reply = buf.slice(0, end); buf = buf.slice(end); waiters.shift()?.(reply); } };
    const read = () => new Promise((r) => waiters.push(r));
    const cmd = async (line, ok = /^[23]/) => { if (line) sock.write(line + '\r\n'); const r = await read(); if (!ok.test(r)) throw new Error(`SMTP: ${line?.split(' ')[0]} → ${r.trim()}`); return r; };
    sock.on('data', onData);
    await new Promise((res, rej) => { sock.once(this.port === 465 ? 'secureConnect' : 'connect', res); sock.once('error', rej); });
    await cmd(null);
    await cmd(`EHLO playground`);
    if (this.port !== 465) {
      await cmd('STARTTLS');
      sock.removeListener('data', onData);
      sock = tls.connect({ socket: sock, servername: this.host });
      await new Promise((res, rej) => { sock.once('secureConnect', res); sock.once('error', rej); });
      sock.on('data', onData);
      await cmd(`EHLO playground`);
    }
    if (this.user) await cmd(`AUTH PLAIN ${Buffer.from(`\0${this.user}\0${this.pass}`).toString('base64')}`);
    await cmd(`MAIL FROM:<${this.from}>`);
    await cmd(`RCPT TO:<${to}>`);
    await cmd('DATA');
    const body = [`From: HEM Playground <${this.from}>`, `To: <${to}>`, `Subject: ${subject}`, `Date: ${new Date().toUTCString()}`, 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', '', ...text.split('\n').map((l) => (l.startsWith('.') ? '.' + l : l))].join('\r\n');
    await cmd(`${body}\r\n.`);
    await cmd('QUIT', /^2/).catch(() => {});
    sock.end();
  }
}
