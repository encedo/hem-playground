# HEM Playground: architecture

> **Warning: nothing in the playground is secret.** Every key a virtual module
> holds is stored **unencrypted** on the server: the private halves of the
> asymmetric keys, the symmetric secrets, and the module's own device keys.
> They sit in Redis as plain base64 and on the server's disk in Redis's own
> files. Anyone with access to that server or to a copy of its data can read
> every key of every module. There is no secure element, no encryption at rest
> and no key wrapping. Treat every key made here as public. Never import a real
> key, and never put real data or a real password near it.
>
> The same goes for the playground's **attestation key**, which signs every
> module's attestation. It lies in plain text in the server's `.env`, and its
> certificate chains to the Encedo Root CA. Anyone with access to the server
> can sign an attestation that passes that chain, for the `*.playground.ence.do`
> profile.

## What it is for

The playground gives anyone a HEM to work against without the hardware. It
gives a developer, a tester or someone trying the Manager a virtual module of
their own at `<prefix>.playground.ence.do` in a minute. That module answers
the HEM REST API of firmware 1.3.x the way a PPA or an EPA does, so the
Manager, hem-sdk-js and hem-api-tester work against it unchanged.

It is for:

- writing and testing applications on hem-sdk-js before a module is on the desk;
- running hem-api-tester and the SDK's device test against a known, resettable
  module;
- showing the Manager and the HEM to someone who has none.

It is not a key store. See the warning above, and *Limits* below.

## How it is built

### One server, four kinds of site

One Node.js process answers every name; the `Host` decides what it serves:

| Name | What answers |
|---|---|
| `playground.ence.do` | The public site: register a prefix (`www.` redirects here) |
| `admin.playground.ence.do` | The panel for administrators (`ADMIN_EMAILS`): every module, reserved prefixes, settings |
| `account.playground.ence.do` | The same panel for an owner: their own modules, reboot, reset, give the prefix up, add another |
| `manager.playground.ence.do` | The Encedo HEM Manager, served as static files |
| `<prefix>.playground.ence.do` | One virtual module |

The prefixes are told apart in the proxy and the code, not in DNS. One wildcard
record and one wildcard certificate cover them all.

### The path of a request

```
browser / SDK / tester
   │  https://<prefix>.playground.ence.do
   ▼
nginx on the host  ── TLS (Let's Encrypt wildcard, issued through acme-dns)
   │  passes on the client's own Host and Content-Length
   │  (X-Orig-Host, X-Orig-Content-Length) and whether it came over TLS
   ▼
app container (Node 24)  ── routes by host
   │  per-module lock
   │  load → firmware pre-checks → handler → save → reply
   ▼
Redis container  ── one hash per module
```

On the server the app listens on `127.0.0.1:8090`, and Redis is on the private
Docker network only. Locally, Caddy with its own CA stands in for nginx.

### The simulator

`server/sim/` follows the firmware, not a guess at it. The specification is the
HEM API reference for 1.3.x, generated from the firmware source; where that is
silent, the firmware source decides.

- **One request, one module, one lock.** The module is loaded from Redis. Then
  come the firmware's checks in the firmware's order: path, method, CORS,
  `Content-Length`, bearer token, body. The handler runs, and only the fields
  it changed are written back. A handler returns a status and a body; it never
  touches the socket.
- **Time-consuming operations.** A handler that takes time on hardware
  (self-test, formatting) answers after the lock is released. A second
  request in the meantime sees the module busy, as it would on hardware.
- **Cryptography is real.** node:crypto does the work (Node 24 with OpenSSL
  3.5: ML-KEM, ML-DSA, Ed448, X448, secp256k1, SHA-3). Three things it has no
  API for are done separately:
  - prehashed and RFC 6979 ECDSA: a small BigInt implementation;
  - HashML-DSA, external μ and Ed25519ph / Ed448ph: the OpenSSL command line;
  - HPKE (RFC 9180): written out by hand.
- **The audit log** is the firmware's format v2: a signing key per file,
  certified by the device log key, and every line signed.
- **PPA and EPA** are the two builds of the firmware. A module is one or the
  other from registration; an EPA has no drives and takes no uploads.

### Where things are kept

Redis, and one hash per module named by its prefix. Everything a module has is
a field of that hash:

| Field | Holds |
|---|---|
| `meta` | Owner's e-mail, variant, state (active, pending, blocked…), dates |
| `dev` | The device: its configuration, device keys, policy, counters |
| `boot` | The current power-up: session key, nonces, tokens in use |
| `k:<kid>` | One key record, with the private half or the secret |
| `log` | The last requests, for the panel |
| `audit:<id>` | Audit log files |

Two hashes are global: `@settings` (registration mode, limits, options) and `@reserved`
(prefix patterns that cannot be registered: brand names, offensive words,
premium names, and the playground's own names).

Redis writes its data to a Docker volume on the server: an append-only file
and a snapshot every minute when enough changed. There is no other copy.

### Attestation

Every module, PPA and EPA, signs its attestation (`genuine` and the attestation
JWT) with **one key shared by the whole playground**, in the role of a secure
element's device key.

- **The key** is `PG_ATT_KEY` in the server's `.env`. It never goes into Redis.
- **Its certificate** (`PG_ATT_CERT`) is issued by the **Encedo EPA Custody
  CA**, in the profile of a device certificate: subject `C=UK, O=Encedo Ltd,
  CN=#<serial>`, and in the SAN the otherName with the key's SKID and the
  dNSName `*.playground.ence.do`.
- **What attest says.** attest.encedo.com knows the certificate, so it
  recognises the playground's profile, but not which module signed: they all
  share one SKID.
- **The certificate is returned as `crt` by every module.** On EPA this is an
  exception to the firmware, where the module returns the CSR of its
  attestation key and the certificate stays with the operator.
- **Making it.** `server/tools/make-att-csr.mjs <domain>`, run where the
  `.env` lives, prints the key line for the `.env` and the CSR for the CA.
- **Without the two values** (locally, for instance), each module signs with a
  key of its own and answers without a certificate.

### Signing in

There are no passwords to the panel.

- **Sign-in link.** Someone types an e-mail address and gets a one-time link,
  valid for 15 minutes.
- **Encedo OIDC.** Someone signs in with their own HEM at test.oidc.encedo.com.
- **One address, one role.** An address in `ADMIN_EMAILS` is an administrator
  and signs in at `admin.`. Anyone else is an owner and signs in at `account.`,
  where they see only the modules registered with their address. The role
  travels in a signed session cookie, and every route checks it.

A module's own passwords are not on the server at all. As on hardware, the
module keeps only the public keys the passwords derive.

### Around it

- **The Manager** (`manager/`) and **hem-sdk-js** (`sdk/`) are git submodules,
  each changed in its own repository.
- **Playground modules in the Manager.** The Manager knows a playground module
  by its firmware version (`…-sim`). It keeps the playground's name and
  certificate, and offers no firmware and no domain registration for it.
- **Deploying.** `deploy/deploy.sh` streams the build context to the server,
  which builds the image itself (it is amd64), then restarts the container.
- **The server is shared.** It is attest.encedo.com, which also runs the
  production attestation service and pki.encedo.com. The playground's nginx
  site and its acme-dns container live beside them and touch nothing of theirs.

## Limits

**It is not a HEM.**

- Its attestation proves "a playground module", not a device. The certificate
  chains to the Encedo Root CA through the EPA Custody CA, but every module
  shares it, and its key is not in a secure element.
- hem-api-tester T-2, T-13.6 and T-16 cannot pass. T-2 and T-16 need a domain
  registered at api.encedo.com. T-13.6 expects, on a PPA, a chain through the
  PPA Custody CA, and on an EPA a CSR instead of a certificate. This is agreed,
  not a bug.
- A playground module gets no name under ence.do. Nothing is registered with
  api.encedo.com for it.
- Check-in goes to the real api.encedo.com. Remote actions (lock, wipe) are
  reported, not carried out.
- There are no drives, no USB and no firmware installs. Uploads are accepted
  and "verified", and nothing is installed.
- The full list of differences is in the [README](../README.md#differences-from-a-real-module).

**It sits behind a proxy.**

- nginx rejects some malformed requests itself before the module sees them,
  e.g. `Transfer-Encoding` together with `Content-Length` (hem-api-tester T-15.13).
- A module answers within the server's rate limit: 3,000 requests a minute by
  default, set in the panel.

**It is a shared, best-effort service.**

- **One server, one Redis, no backup and no redundancy.** A module can go
  without warning.
- **Lifetime.** A module lives until it is deleted, reset by its owner or an
  administrator, or idle for the number of days set in the panel (30 by
  default).
- **Limits per owner.** Each address may hold a limited number of modules
  (3 by default), and each module a limited number of keys (512 by default).
- **Administrators can do anything to any module.** They can block, reset or
  delete it. They cannot sign in as its owner, but whoever runs the server can
  read every key (see the warning at the top).

**Nothing in it is secret.** Every private key, secret and device key is
stored unencrypted on a server several people can reach. Use it with test
keys and test data only.
