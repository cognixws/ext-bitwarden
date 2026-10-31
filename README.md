# Bitwarden Secrets Manager secret source for COGNIX[WS]

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
