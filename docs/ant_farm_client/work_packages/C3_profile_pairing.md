# Work Package C3 — Local Profile Store and Server Pairing

## Objective

Expose the existing SQLite-backed Ant profiles through the standalone Client,
pair one local profile to one tenant `browser_profile`, and translate the
Server profile identity to the local Ant profile identity before any Farm
runtime command reaches the Agent. No second profile database or
`farm_profiles.json` is permitted.

## Ownership boundaries

- Ant remains authoritative for the local profile, browser process,
  `UserDataDir`, fingerprint, proxy credentials, and Chrome arguments.
- auto-scraper remains authoritative for the tenant `browser_profile`, node
  enrollment, one-time pairing grants, and Farm affinity.
- The Server stores only the node binding, opaque local profile ID and
  incarnation, safe display name, readiness projection, provider, and an
  independently generated opaque `farm_storage_key`.
- `farm_storage_key` is never the local Ant profile ID.

## Protocol

1. An authenticated tenant administrator issues a high-entropy, one-time,
   expiring pairing code bound to one tenant profile and one enrolled node.
2. The Client reads the code from a no-echo terminal or bounded stdin. Codes
   are never accepted in argv, config, diagnostics, or logs.
3. The Client submits the local profile safe projection plus its enrolled
   device public key, a fresh request ID and an Ed25519 signature over a
   canonical domain-separated payload.
4. The Server verifies the enrolled key and signature, atomically consumes the
   pairing grant/request ID, and records the affinity. Replays and rebinding
   attempts fail closed.
5. Server runtime dispatch resolves the affinity to `ant_profile_id` and sends
   that ID plus the paired incarnation. The Agent recomputes the incarnation
   from the current SQLite profile before starting a runtime.

## Durable ABA fence

The pairing incarnation is SHA-256 over a versioned, length-framed tuple of
the canonical local profile ID and its immutable random SQLite
`incarnation_id` value. Migration 15 backfills existing rows and an insert
trigger covers canonical direct-import paths.
Deleting and recreating a profile with the same ID therefore cannot inherit a
pairing. Runtime-process incarnation remains a separate, shorter-lived fence.

## Client surface

- `profiles list` prints a safe JSON projection only.
- `profiles create` creates through the existing Ant `browser.Manager` and
  SQLite DAO.
- `profiles open <id>` uses the existing `BrowserRuntimeService.Start` path.
- `pair <id>` reads a pairing code from no-echo terminal or bounded stdin.
- `unpair <id>` uses the enrolled identity and a fresh signed request ID.

## Acceptance

- list/create/open operate against the configured Ant SQLite database; no
  parallel profile store is created.
- wire, logs, diagnostics, and Server rows contain none of: cookies, raw
  fingerprint arguments, proxy password/config, `UserDataDir`, Chrome args,
  device private key, or pairing code.
- valid pairing selects the intended tenant profile and node.
- wrong/expired/used code, wrong node/key/signature, malformed projection,
  duplicate request ID, cross-tenant selection and concurrent consume fail.
- a deleted/recreated same-ID local profile is rejected by the Agent until it
  is explicitly paired again.
- unpair disables the affinity and prevents new runtime placement without
  deleting either the local or tenant profile.

## Verification

- Go unit/race tests for projection, SQLite CRUD/open, signing, strict HTTP,
  CLI secret handling, translation and ABA rejection.
- Python API/primitive/schema/auth tests including concurrency and replay.
- Cross-repository test proving tenant profile → affinity translation → local
  Ant profile runtime.
- `go test ./backend/...`, `go test -race ./backend/...`, `go vet ./backend/...`
  and the Server Farm/auth/schema suites.

## Completion evidence

- Canonical SQLite list/create/open and direct-import incarnation migration:
  PASS.
- Signed pair/unpair, strict safe projection, replay/expiry/response-loss and
  atomic tenant/Control writes: PASS.
- Same-ID delete/recreate and stale command rejection before runtime probing:
  PASS.
- Recursive nested runtime identity translation and contradiction rejection:
  PASS.
- Cross-repository TLS WSS real Chrome flow with external Server profile `41`
  mapped to a distinct local Ant profile: PASS.
- macOS arm64 full Go suite, focused race, vet, Server 129-pass suite and real
  Chrome tests: PASS. Native installed-artifact repeats remain owned by C8.
