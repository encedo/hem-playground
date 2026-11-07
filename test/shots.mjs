// Screenshots of the public site and the admin panel, at desk and phone width.
//   LINK=<sign-in link> node test/shots.mjs <out-dir> [domain] [prefix]   (INSECURE=1 for the local Caddy CA)
// Chromium over the DevTools protocol, no dependencies (Node 22+ WebSocket).
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const out = path.resolve(process.argv[2] ?? 'shots');
const domain = process.argv[3] ?? 'playground.ence.do';
const prefix = process.argv[4] ?? 'test';
const chromium = process.env.CHROMIUM ?? '/usr/bin/chromium-browser';
const PORT = 9400 + Math.floor(Math.random() * 500);   // never the port of another headless Chromium
await fs.mkdir(out, { recursive: true });
const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'shots-'));
const chrome = spawn(chromium, ['--headless=new', '--disable-gpu', '--no-sandbox', `--user-data-dir=${profile}`, `--remote-debugging-port=${PORT}`, '--hide-scrollbars', ...(process.env.INSECURE ? ['--ignore-certificate-errors'] : []), 'about:blank'], { stdio: 'ignore' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let target;
for (let i = 0; i < 50 && !target; i++) { await sleep(200); try { target = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find((t) => t.type === 'page'); } catch {} }
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let id = 0; const wait = new Map(); const events = [];
ws.addEventListener('message', (m) => { const d = JSON.parse(m.data); if (d.id && wait.has(d.id)) { wait.get(d.id)(d); wait.delete(d.id); } else events.push(d); });
const cdp = (method, params = {}) => new Promise((r) => { const i = ++id; wait.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
await cdp('Page.enable');
async function go(url) {
  events.length = 0;
  await cdp('Page.navigate', { url });
  for (let i = 0; i < 100 && !events.some((e) => e.method === 'Page.loadEventFired'); i++) await sleep(100);
  await sleep(300);
}
const evalJs = async (expr) => (await cdp('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true })).result?.result?.value;
async function shot(name, width, mobile) {
  await cdp('Emulation.setDeviceMetricsOverride', { width, height: mobile ? 844 : 900, deviceScaleFactor: 1, mobile });
  await sleep(200);
  const { result } = await cdp('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
  await fs.writeFile(path.join(out, `${name}-${width}.png`), Buffer.from(result.data, 'base64'));
  const over = await evalJs(`(() => { const o = []; for (const el of document.querySelectorAll('body *')) { const r = el.getBoundingClientRect(); if (el.scrollWidth > el.clientWidth + 1 && getComputedStyle(el).overflowX === 'visible' && el.children.length === 0) o.push(el.tagName + '.' + el.className + ': ' + (el.textContent || '').trim().slice(0, 40)); } if (document.documentElement.scrollWidth > innerWidth) o.unshift('PAGE SCROLLS SIDEWAYS ' + document.documentElement.scrollWidth); return o.slice(0, 12); })()`);
  console.log(`${name}-${width}`, over?.length ? over : 'ok');
}
const pages = [
  ['public', `https://${domain}/`],
  ['login', `https://admin.${domain}/login`],
];
for (const [n, u] of pages) { await go(u); await shot(n, 1440, false); await shot(n, 390, true); }
await cdp('Emulation.clearDeviceMetricsOverride');
// sign in with a sign-in link (LINK=https://admin.<domain>/login/link?t=...)
await go(process.env.LINK);
await sleep(500);
for (const [n, u] of [['modules', `https://admin.${domain}/`], ['module', `https://admin.${domain}/m/${prefix}`], ['reserved', `https://admin.${domain}/reserved`], ['settings', `https://admin.${domain}/settings`]]) {
  await go(u); await shot(n, 1440, false); await shot(n, 390, true);
}
ws.close(); try { chrome.kill(); } catch {} await fs.rm(profile, { recursive: true, force: true });
