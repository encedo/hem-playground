# HEM Playground

Virtual Encedo HEM modules for testing: anyone registers a prefix and gets
`https://<prefix>.playground.ence.do`, a simulated module that answers the
HEM REST API 1.3.x the way a PPA (or an EPA) does — the same endpoints, checks,
status codes and real cryptography — so the
[Manager](https://github.com/encedo/encedo-manager),
[hem-sdk-js](https://github.com/encedo/hem-sdk-js) and
[hem-api-tester](https://github.com/encedo/hem-api-tester) work against it
unchanged. An admin panel lists the modules and approves, blocks, resets,
reboots or deletes them.

A virtual module is **not** a secure element: its keys sit in Redis on a shared
server, and it is not genuine (its device certificate comes from the
playground, not from Encedo). Never put a real key or secret in it.

## Sites

One Node process, routed by the `Host` header (on HTTPS: the TLS server name).
DNS has `playground.ence.do` and the wildcard `*.playground.ence.do` pointing to the
server and TLS one certificate for both, so a new module needs no DNS, certificate
or proxy change.

| Host | What |
|---|---|
| `playground.ence.do` | Register a module: prefix, e-mail, variant (PPA / EPA); `www.` redirects here |
| `admin.playground.ence.do` | Panel: sign in with a link by e-mail (no passwords) or Encedo OIDC. Administrators (`ADMIN_EMAILS`) see every module, reserved prefixes and settings; an owner sees and runs only the modules registered with their e-mail (reboot, reset, give the prefix up) |
| `manager.playground.ence.do` | The Manager (the `manager/` submodule), opened with `?hem=https://<prefix>.playground.ence.do` |
| `<prefix>.playground.ence.do` | One virtual module |

Locally the domain is `localhost`: `https://localhost`, `https://admin.localhost`,
`https://manager.localhost`, `https://<prefix>.localhost`.

## Layout

```
server/
  index.mjs          HTTP server, Host routing, request log, rate limit
  registry.mjs       registration, admin actions, settings
  lib/               Redis client (RESP, no dependency), store, SMTP mailer
  sim/               the simulated module
    http.mjs         pre-handler checks in firmware order, CORS, tokens, reply headers
    auth.mjs         /api/auth/*  (personalisation, password and phone sign-in)
    system.mjs       /api/system/*, /api/storage/*, /api/logger/*
    keymgmt.mjs      /api/keymgmt/*
    crypto.mjs       /api/crypto/*
    keys.mjs ec.mjs  key types, ECDSA (RFC 6979, prehashed), Ed25519 -> X25519
    device.mjs       module state, boots, nonces, audit log (format v2)
    attest.mjs       the simulated secure element: genuine token, attestation JWT
  web/               public site and admin panel (the Manager's style sheet + pg.css)
sdk/                 hem-sdk-js (submodule) — tests and tools
manager/             encedo-manager (submodule) — served on manager.<domain>
deploy/              Caddyfile for local runs
test/                personalise a module, run the suites
```

Reserved prefixes are the hash `@reserved` (pattern → kind brand / offensive / premium / other, note); the playground's own names are fixed in `registry.mjs`. Redis holds **one hash per module, named by its prefix**; its fields are
`meta`, `dev`, `boot`, `k:<kid>` (one per key), `log` (the last requests) and
`audit:<id>` (one audit-log file per boot). Global settings are the hash
`@settings`.

## Run it locally

```bash
git submodule update --init --recursive
cp .env.example .env               # then fill it in, see below
docker compose up -d --build
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt .local/caddy-root.crt
```

Trust `.local/caddy-root.crt` once (browser, or `NODE_EXTRA_CA_CERTS` for Node).
`SEED_HEM=test` (the default) creates `test.localhost`, approved and still in its box.

`.env`:

| Variable | |
|---|---|
| `ADMIN_EMAILS` | administrators; everyone else who signs in is an owner of their own modules |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI` | Encedo OIDC client (test: `https://test.oidc.encedo.com`) |
| `SESSION_SECRET` | long random string |
| `SMTP_HOST`, `SMTP_MODE` (`starttls` / `ssl`), `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM` | sign-in links and e-mail confirmation; without them both go to the app log (`docker compose logs app`) |

## Test it

```bash
export NODE_EXTRA_CA_CERTS=.local/caddy-root.crt
node test/personalise.mjs https://test.localhost      # as hem-api-tester does: "example passphrase"
node sdk/test/device.mjs https://test.localhost       # the SDK's real-device suite
```

hem-api-tester (branch `fw-1.3.x`, checked out next to this repo) runs in a PHP
container that trusts the Caddy root; the tester's own `config.php` is left
alone and only pointed at the module:

```bash
test/run-tester.sh test_1.php test_3.php test_4.php     # or no argument: every test
```

State of the suites (local `test.localhost` and production `test.playground.ence.do`):

| Suite | Result |
|---|---|
| `sdk/test/device.mjs` | 35 / 35 |
| tester T-1, T-3, T-4, T-9, T-10, T-11, T-12, T-14 | PASS (DIAG subtests skipped, as on a release build) |
| T-5, T-6 | PASS with `EXTAUTH=1` (`ExtAuth_Simulator.php` as the phone, through the real api.encedo.com) |
| T-7 | 7.2 (firmware upload) and 7.3 (Manager upload) PASS with `TESTER_INPUT='2\n'` / `'3\n'`; 7.1 flashes over USB, not for a virtual module |
| T-8 | PASS (8.1; 8.2–8.5 need a DIAG build) |
| T-13 | 13.1–13.5 pass; 13.6 needs a device certificate chained to the Encedo Root CA — a virtual module is not genuine |
| T-15 | PASS locally; on production 15.13 gets nginx's own 400 for Transfer-Encoding + Content-Length (the firmware says 501) |
| T-2, T-16 | not on the playground: they register `my.ence.do` at api.encedo.com with the genuine token (T-16 runs T-2 per policy); `test/personalise.mjs` personalises the same way without that step |

Reset the module (admin panel, or `docker compose exec redis redis-cli DEL test`
and restart `app`) before a run that starts from a module in its box.

## Deploy

`deploy/deploy.sh` streams the build context over ssh and builds the image on
the server (amd64), then restarts it with `deploy/compose.prod.yaml` in
`/opt/hem-playground` (its `.env` lives only there). The host's nginx
(`deploy/nginx-playground.conf`, `deploy/playground-proxy.conf`; needs
`libnginx-mod-http-headers-more-filter` to drop the `Server` header) ends TLS for
`playground.ence.do` and `*.playground.ence.do` with one Let's Encrypt
certificate, issued and renewed through a CNAME to acme-dns on the same host
(`deploy/acme-dns/`).

## Differences from a real module

- The clock is always set (the server's), so `RTC not set` (403) never happens.
- Check-in runs against the real `api.encedo.com`; remote actions (lock, wipe,
  brick) are reported but never carried out.
- No TLS key import, CSR or provisioning: the playground ends TLS itself.
- Firmware and Manager uploads are accepted and "verified", nothing is installed.
- There is no disk: `storage/unlock` / `lock` change the state `status` reports
  (`:ro`, `:rw`, `:-`) and write the audit entries, nothing is exposed anywhere.
- The TLS records in the key repository ("TLS PrivateKey", "TLS Certificate") are
  made at personalisation with a self-signed certificate; the proxy serves the real one.
- After a factory wipe `status` reports `https: false` until the TLS bootstrap,
  but the proxy keeps serving HTTPS so the Manager can personalise the module again.
- Ed25519ph / Ed448ph, HashML-DSA and external μ go through the OpenSSL 3.5
  command line (node:crypto has no API for them).
- The proxy picks the module by the TLS server name and passes the client's own
  `Host` and `Content-Length` in `X-Orig-Host` / `X-Orig-Content-Length`, so a
  request without them is answered as the firmware answers it.
