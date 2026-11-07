// Personalise a module that is still in its box, the way hem-api-tester does:
// user password "example passphrase", master "example admin passphrase", all three policies.
//   NODE_EXTRA_CA_CERTS=.local/caddy-root.crt node test/personalise.mjs https://test.localhost
import { HEM } from '../sdk/hem-sdk.js';

const url = process.argv[2] ?? 'https://test.localhost';
const hem = new HEM(url);
const st = await hem.getStatus();
if (!('inited' in st)) { console.log(`${url} is personalised already`); process.exit(0); }
const host = new URL(url).hostname;
const r = await hem.initialize('example admin passphrase', 'example passphrase', {
  user: 'Playground tester', email: 'test@playground.local', hostname: host, origin: '*',
  trusted_ts: false, trusted_backend: false, allow_keysearch: true,
  ip: '192.168.7.1/24', storage_mode: 0, storage_disk0size: 8388608, dnsd: false,
  policy: ['raw_ecdh_enabled', 'pubkey_in_search', 'pubkey_in_list'],
});
console.log('personalised', url, Object.keys(r));
for (let i = 0; i < 20; i++) { const s = await hem.getStatus(); if (!s.format || s.format === 'done') break; await new Promise((r) => setTimeout(r, 500)); }
