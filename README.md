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

**Nothing in a virtual module is secret.** Its keys, private halves and
secrets included, are stored **unencrypted** in Redis on a shared server, and
anyone with access to that server or to a copy of its data can read them. Its
attestation is signed with one key shared by the whole playground, which lies
in the server's `.env`. The key's certificate comes from the Encedo EPA Custody
CA for `*.playground.ence.do`, so it proves "a playground module", not a device.
Use test keys and test data only. How it is built, and its limits:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Sites

- `playground.ence.do`: register a module (`www.` redirects here)
- `admin.playground.ence.do`: administrators (`ADMIN_EMAILS`)
- `account.playground.ence.do`: an owner's own modules
- `manager.playground.ence.do`: the Manager, opened with `?hem=https://<prefix>.playground.ence.do`
- `<prefix>.playground.ence.do`: one virtual module

What each one does and how a request reaches a module: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#how-it-is-built).

Locally the domain is `localhost`: `https://localhost`, `https://admin.localhost`, `https://account.localhost`,
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
docs/                ARCHITECTURE.md: purpose, how it is built, limits
deploy/              Caddyfile for local runs
test/                personalise a module, run the suites
```

What Redis holds, field by field: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#where-things-are-kept).

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
| `ADMIN_EMAILS` | administrators who cannot be removed in the panel (more are added under Settings, Administrators); everyone else who signs in is an owner of their own modules. They are also the addresses told of new modules (Settings, Options; on by default) |
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
| T-13 | 13.1–13.5 pass; 13.6 does not. On a PPA it expects a chain through the PPA Custody CA; the playground's certificate is from the EPA Custody CA. On an EPA it expects a CSR and no certificate |
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
- Attestation is signed with one key for the whole playground (`PG_ATT_KEY`), and
  every module, EPA included, returns its certificate as `crt`. A real EPA
  returns the CSR of its own attestation key instead.
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
