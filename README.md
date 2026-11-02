# Bitwarden for COGNIX[WS]: Secrets Manager keys, vault logins, Site sign-ins

An extension (door L of ADR-0109, ADR-0388). Same contract as the
1Password source: the daemon resolves one binding at launch by asking this
process over loopback; the value rides the same 0600 file as every key and
is never stored, cached, logged or shown.

## Connect

1. Create a free Bitwarden account and start Secrets Manager Free
   (2 users, 3 projects, 3 machine accounts — bitwarden.com/go/start-secrets-free).
2. Create a **project**, put secrets in it (key + value).
3. **Machine accounts**: create one for COGNIX[WS], scope it to the
   project, **Generate access token**, copy it.
4. Paste the token on the extension's page in COGNIX[WS].

## Notes

- No SDK: the Secrets Manager API takes the machine account's access token
  directly as a Bearer on api.bitwarden.com; the Go standard library
  covers every call (7.8 MB binary, no dependencies).
- References read `bws://<project>/<secret-key>`; the caches hold names
  and ids only, refreshed at most once a minute; a value is fetched per
  resolve.
- `qa/package/` — the QA build (fixture resolver, `EXT_QA_MODE=1` only).

## Validated (2026-10-31)

Unit (reference parsing, classes → statuses, contract shape), the real
binary standalone in QA mode, and installed on a COGNIX[WS] instance with
the supervised process running. Live vendor validation pending the
owner's free account.

## Sign agents in to sites (0.2.0)

Fill **Vault address**, your **personal API key** (web vault → Settings →
Security → Keys) and your **master password** on the extension's page. The
extension then publishes your personal logins' names and sites (never a value),
and answers a login only to the daemon when an agent calls `sign_in`; the agent
never sees it. The vault's items are end-to-end encrypted, so the extension
decrypts them in memory the way a Bitwarden client does (PBKDF2 or Argon2id,
AES-CBC with HMAC), one resolve at a time. Organization items are not read yet.
The API key sign-in asks no new-device email code.

The manifest also declares Bitwarden's own browser extension (release, SHA-256),
which COGNIX[WS] installs in the browser profiles you turn Site sign-ins on for.

## Validated (2026-11-02)

Unit: decryption against a fake vault (personal, item-key, deleted,
organization and note items), the RFC 6238 vectors, wrong password and wrong
API key. Live on the QA VM against Vaultwarden (2026-11-02): the login published
with its site and no value, `sign_in` signed an agent in through the core, and
a refused login was reported as not signed in.
