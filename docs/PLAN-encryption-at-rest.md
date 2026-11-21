# Plan: module data encrypted at rest

Status: **built and tested locally (2026-11-21); not deployed**. The decisions
and the test results are near the end.

## Why

Every field of a module's Redis hash is plain JSON today: private key halves,
symmetric secrets, device keys, session keys, logs and the owner's e-mail.
Anyone who reads the Redis volume, its AOF/RDB files, a copy of them, or Redis
itself sees every key of every module (ARCHITECTURE.md, warning at the top).

Goal: what Redis holds and writes to disk is ciphertext. The backend decrypts
with a key it gets from an environment variable.

## Threat model

| Protects against | Does not protect against |
|---|---|
| A leaked Redis volume, AOF or RDB file, or a backup of them | root on the server: the key is in `.env`, like `PG_ATT_KEY` |
| Someone with Redis access only (`redis-cli`, a port opened by mistake) | Reading the app process's memory |
| A field copied into another module or under another name (AAD) | An administrator using the panel, which works as before |

The rule "nothing in the playground is secret" stays. Only the warning's
wording changes.

## Design

### Where

Everything goes into `server/lib/store.mjs`, and the rest of the code stays as
it is. Values are read and written in `get`, `getMany`, `set` and `fields`.
Encryption happens there, just before `JSON.stringify` → Redis on the way in,
and just after Redis → `JSON.parse` on the way out.

The code that goes around `Store` only uses field names: `HKEYS` in
`registry.mjs` and `index.mjs`. It also touches the `@reserved` and
`@passkeys` hashes. None of that needs a change.

### What is encrypted

- **Every field of every module hash** (`meta`, `dev`, `boot`, `k:*`, `log`,
  `audit:*`). There is no list of sensitive fields to keep up to date, so a new
  field cannot be missed.
- **Not encrypted:** hashes whose name starts with `@` (`@settings`,
  `@passkeys`, `@reserved`). They hold no secrets, and passkeys are public keys.
  The test in `Store` is `prefix.startsWith('@')`.
- **Field names stay plain.** `k:<kid>` reveals only the KID, which is a hash of
  the public key. Key counts, `HSCAN MATCH k:*` and `HKEYS` keep working.

### Format of a value

```
e1:<key-id>:<base64( iv[12] | ciphertext | tag[16] )>
```

- AES-256-GCM (`node:crypto`), a random 12-byte IV for every write.
- AAD = `<prefix>\0<field>`, so a value moved to another module or field does
  not decrypt.
- `key-id` = the first 8 hex characters of SHA-256(key). It tells which key
  encrypted the value during rotation.
- A value without `e1:` is legacy plain JSON. It is read as it is and comes
  back encrypted on its next write (lazy migration).

### Key

- `PG_DATA_KEY`: 32 random bytes in base64, made with `openssl rand -base64 32`.
  It sits in `.env` next to `PG_ATT_KEY`, and `.env.example` gets an empty
  entry with a comment.
- `PG_DATA_KEY_OLD` (optional) is the previous key, for reading only, during
  rotation.
- Loaded once at start-up in a new module, `server/lib/datakey.mjs`, in the
  same style as `sim/attkey.mjs`. A key that is not 32 bytes stops the start.

### Behaviour at start-up

| `PG_DATA_KEY` | Data in Redis | Result |
|---|---|---|
| set | anything | encrypts on write, reads both formats |
| not set | plain only | works as today (local development); one warning in the log |
| not set | some `e1:` | **refuses to start**, with a clear message |
| set, but a value has an unknown `key-id` | — | that request fails with 500, the log names the module and field, nothing is overwritten |

At start-up the `meta` of **every** module is checked, not just a sample. One
`HGET` per module is cheap, and this also catches a wrong key, not only a
missing one: the app refuses to start when a module is under a key id it does
not have.

### Migration and rotation tool

`server/tools/encrypt-at-rest.mjs`, run in the app container:

- `--dry-run` counts plain fields and fields under each `key-id`.
- With no flag, it re-encrypts every module field under the current key, from
  plain or from `PG_DATA_KEY_OLD`. Each module is done under `withLock`, so it
  can run while the app is live.
- A field is rewritten only if Redis still holds the value read
  (compare-and-set in Lua). The app is a separate process, so its in-process
  lock does not cover the tool.
- At the end it runs `BGREWRITEAOF` and `BGSAVE SCHEDULE`, so the AOF and
  `dump.rdb` stop holding plain values. Older copies (backups, snapshots of the volume) still hold plain
  values. That is a manual step and goes in the runbook.

## Changes, file by file

| File | Change |
|---|---|
| `server/lib/datakey.mjs` | new: loads the keys, `seal(prefix, field, json)` / `open(prefix, field, raw)` |
| `server/lib/store.mjs` | `get` / `getMany` / `set` / `fields` go through `seal` / `open` for prefixes without `@` |
| `server/index.mjs` | start-up check from the table above |
| `server/tools/encrypt-at-rest.mjs` | new: migration, rotation, dry-run |
| `deploy/deploy.sh` | runs the migration after `up -d` |
| `.env.example`, `compose*.yaml` | `PG_DATA_KEY` (compose takes it from `env_file`, so probably no change) |
| `docs/ARCHITECTURE.md` | "Where things are kept" + new wording of the warning |
| `README.md` | key generation, migration, rotation |
| `test/` | new test: after personalisation and making a key, `HGETALL` on the module has no `{` at the start of a value, and the module still works |

## Tests (before saying it works)

1. Locally with `PG_DATA_KEY`: the set from CLAUDE.md, `device.mjs` 35/35 and
   hem-api-tester with the same results as now (all PASS but T-13.6).
2. The new test that Redis holds only `e1:`.
3. Migration: a module made without a key → set the key → `--dry-run` shows
   plain fields → migration → `device.mjs` against that module passes.
4. Rotation: key A → key B with `PG_DATA_KEY_OLD=A` → migration → removing the
   old key does not break anything.
5. A start without a key while `e1:` data exists stops with a message.
6. AAD: copying a `k:*` value into another module by hand gives 500, not
   someone else's key.

## Deployment (the shared server, each step after the owner's go)

1. Generate the key on the server and add `PG_DATA_KEY` to
   `/opt/hem-playground/.env`. Put a copy in `~/hem-playground-data-key`
   (mode 600). The key never leaves the server.
2. Deploy (`deploy/deploy.sh`). It also runs the migration.
3. Check that `--dry-run` shows 0 plain fields.
4. Check whether backups or snapshots of the Redis volume exist outside the
   server and decide what to do with them.

## Decisions (2026-11-21)

- **`@passkeys` stays plain**, like the other `@` hashes.
- **The deploy migrates the data.** `deploy/deploy.sh` runs
  `encrypt-at-rest.mjs` in the app container after `up -d`. The migration is
  idempotent, so it is a no-op when there is nothing to do. Rotation works the
  same way: set the new key in `PG_DATA_KEY` and the old one in
  `PG_DATA_KEY_OLD`, deploy, then remove `PG_DATA_KEY_OLD`. After the first
  such deploy the server holds `e1:` data, so a start without the key is
  refused by the start-up check. No separate production flag is needed.
- **A copy of the key goes in the home directory on the server**
  (`~/hem-playground-data-key`, mode 600). It stays outside `/opt/hem-playground`
  and outside the Redis volume, and it never leaves the server (CLAUDE.md).
- **Performance:** accepted. Measure it once during the local tests.

## Local test results (2026-11-21)

Native Redis + Caddy + Node 24.22 on the macMini (no Docker there). Node 24.14
lacks `raw-public` key export and fails key creation, which has nothing to do
with this change. The image's `node:24-alpine` is newer.

| Check | Result |
|---|---|
| `test/at-rest.mjs` (cipher alone: format, IV, AAD, tamper, rotation, bad key) | 12 / 12 |
| `sdk/test/device.mjs` without a key (baseline) | 35 / 35 |
| migration of a plain module with `k:*` fields: dry-run, run, run again | 9 → 9 encrypted, then 0 to do |
| a key record before and after migration | identical |
| `sdk/test/device.mjs` on the encrypted module, key A | 35 / 35 |
| `test/at-rest.mjs redis://… test` (live Redis) | all 9 fields `e1:`, `@` hashes plain |
| rotation A → B with `PG_DATA_KEY_OLD`, then B alone | 9 re-encrypted; 35 / 35 |
| start without a key, data encrypted | refused, exit 1 |
| start with the wrong key | refused, exit 1 |
| `k:` value moved to another field by hand | does not decrypt |
| 512 decryptions of a key record | 1.9 ms |
| hem-api-tester | **not run**: needs Docker, and `../hem-api-tester` is on `main`, not `fw-1.3.x` (not switched, per CLAUDE.md) |
