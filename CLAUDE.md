# Working in this repository

The [README](README.md) says what the playground is and how to run, test and
deploy it — read it first and do not repeat it here. This file is what an agent
has to be told: what must not change, what to check before calling something
done, and the facts that have already cost time.

## Ground rules

- **The firmware is the specification.** The simulator follows the HEM REST API
  reference for FW 1.3.x: `~/develop/encedo_firmware/docs/HEM_API_reference_1.3.x.md`
  (also published as an artifact; the two have the same content). When the
  reference and the simulator disagree, the simulator is wrong. When the
  reference is silent, read the firmware source (`encedo_firmware/Firmware/src`),
  not a guess.
- **The acceptance tests are other people's code.** `sdk/test/device.mjs` (the
  hem-sdk-js suite for a real device) and hem-api-tester on branch `fw-1.3.x`
  (`~/develop/hem-api-tester`, the user's checkout — never edit it, never switch
  its branch). Make the simulator pass them; do not bend a test.
- **One Redis hash per module, named by its prefix.** Everything a module has is
  a field of that hash (`meta`, `dev`, `boot`, `k:<kid>`, `log`, `audit:<id>`).
  Do not spread a module over several keys. Global state is `@settings` and
  `@reserved` (reserved prefix patterns).
- **No passwords.** Sign-in is a one-time link by e-mail or Encedo OIDC; the role
  (admin from `ADMIN_EMAILS`, otherwise owner) travels in the session. Every admin
  route checks it: an owner sees only modules whose `meta.email` is theirs.
- **Submodules, not copies.** `sdk/` is hem-sdk-js, `manager/` is encedo-manager.
  Changes to them are made in their own repositories, following their own
  CLAUDE.md; ask before pushing either.
- **Nothing real goes in.** No keys, passwords or logs from a real module, no
  customer data. `.env` and `.local/` are ignored and stay so.
- **The server is shared.** Its secrets (`/opt/hem-playground/.env`) never leave it. `attest.encedo.com` runs the production attestation
  service and pki.encedo.com. Show every change to its nginx, packages or
  certificates and wait for the owner's go; never touch the attest / pki files.
- Commits end with the `Co-Authored-By` line. Interface and comments in British
  English, in the voice of `manager/design/STYLE.md`; the pages use the
  Manager's own style sheet (`manager/app/style.css`) plus `server/web/pg.css`.

## How it is put together

- `server/index.mjs` routes by host: `<domain>` public site (`www.` redirects), `admin.<domain>`
  panel, `manager.<domain>` the Manager (static), `<prefix>.<domain>` a module.
- `server/sim/index.mjs` runs one request to one module **under that module's
  lock**: load → firmware pre-checks (`http.mjs`, in the firmware's order) →
  handler → save what the handler marked dirty → reply. A handler returns
  `{ status, json | text, close, delay }` or throws `fail(code)`; it never
  writes to the socket.
- A handler that takes time on hardware (`selftest`) returns `delay`: the reply
  waits *after* the lock is released, so a concurrent request sees the module busy.
- Crypto: node:crypto first; `ec.mjs` (BigInt) for prehashed / RFC 6979 ECDSA;
  `mldsa-ext.mjs` calls the OpenSSL 3.5 CLI for HashML-DSA, external μ and
  Ed25519ph / Ed448ph; `hpke.mjs` is RFC 9180 by hand.

## Before saying it works

```bash
docker compose up -d --build app
docker compose exec -T redis redis-cli DEL test && docker compose restart app   # a module in its box
export NODE_EXTRA_CA_CERTS=.local/caddy-root.crt
node test/personalise.mjs https://test.localhost
node sdk/test/device.mjs https://test.localhost                                # 35/35
test/run-tester.sh test_1.php test_3.php test_4.php test_9.php test_10.php \
  test_11.php test_12.php test_13.php test_14.php test_15.php                   # all PASS but T-13.6
```

T-2, T-13.6 and T-16 cannot pass on a virtual module (genuine device certificate,
domain registration at api.encedo.com) — that is agreed, not a bug to chase.
The default rate limit (3000 requests a minute) is there because the tester is fast.

## Facts that bite

- **The proxy rewrites what the firmware checks.** On HTTPS the module is the TLS
  server name; the client's own `Host` and `Content-Length` (also when absent)
  reach the simulator as `X-Orig-Host` / `X-Orig-Content-Length`, and
  `X-Forwarded-Proto` says whether the request came over TLS (418 depends on it).
  Caddy locally and nginx on the server must both set these.
- Caddy drops `Connection: keep-alive` from the upstream reply; the Caddyfile
  sets it again (T-1.6). nginx sends it by itself.
- node's `hkdfSync` refuses an `info` over 1024 bytes; an ML-KEM public key is
  longer. Use `hkdf()` from `codec.mjs`.
- Signed-request nonces are single use (DEV-499): consume on the first request
  whose signature and `exp` pass.
- The audit log is format v2 (DEV-500): per-file Ed25519 key certified by the
  device log key, every line signed. A new module starts with a factory-session
  file, because tests expect at least one downloadable file.
- KIDs: asymmetric = SHA-1 of the raw public key; symmetric = SHA-1 of the secret;
  GENERIC_DER = SHA-1 of the 2-byte LE length and the DER (all first 16 bytes).
