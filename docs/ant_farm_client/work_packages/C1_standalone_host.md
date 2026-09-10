# Work Package C1 — Standalone Farm Client Host

## ID

`C1-WP1`

## Goal

Create a Wails-free `ant-farm-client` process that loads existing local Ant
profiles, composes the existing Farm services, connects with authenticated WSS,
reconnects, and shuts down cleanly.

## Existing implementation

- `NewBrowserRuntimeServiceForHost`
- `NewFarmRuntimeServiceForHost`
- `NewFarmRuntimeControlAdapter`
- `NewFarmControlWSSClient`
- existing `FarmRuntimeOwnershipStore`
- existing SQLite `ProfileDAO` and `browser.Manager.InitData()` load path

## Files allowed

- `backend/cmd/ant-farm-client/**`
- new `backend/farm_client_*.go`
- C1 tests in matching new files
- C0 documents when recording evidence

## Files frozen

All files listed under Frozen Farm core in `file_ownership.md`, except a
review-approved minimal public facade if the existing profile store cannot be
consumed without exposing internals. No protocol or lifecycle semantics may
change.

### Approved minimal extension

SOL architecture review found that the standalone factory otherwise discards
the canonical SQLite-backed Manager and cannot inject the existing fingerprint
launch callback. C1 may make an additive-only change to
`backend/browser_runtime_service_public.go`:

- accept an already initialized `*browser.Manager`, mutually exclusive with
  the legacy `Config/Profiles` inputs;
- accept and forward the existing `FingerprintLaunchArgs` callback;
- continue constructing connector managers and calling the existing
  `NewBrowserRuntimeService` lifecycle unchanged.

No other Frozen Core file is approved for modification.

## Contract

1. Require explicit, absolute application and state roots.
2. Load and strictly validate client config before constructing services.
3. Load local profiles through the existing SQLite-first Ant store path.
4. Reject empty/duplicate profile IDs and invalid node identity.
5. Compose exactly one BrowserRuntimeService and one FarmRuntimeService.
6. Use the existing adapter and WSS client with AutoReconnect enabled.
7. Keep private keys in memory only; C1 accepts a test/development identity
   source pending C2 secure enrollment, and must not log it.
8. Enforce one instance per state root.
9. On SIGINT/SIGTERM: stop admission, close WSS/CDP, invoke existing ownership-
   aware shutdown, flush logs, and exit within a bounded timeout.
10. Expose version, GOOS, and GOARCH without exposing secrets or local profile
    details.
11. Inject a local attestation-state provider built from the captured effective
    launch spec, current runtime snapshot, and safe local proxy revisions.
12. Keep the canonical read-only SQLite Manager with ProfileDAO, ProxyDAO and
    CoreDAO; do not replace it with a profiles-only Manager snapshot.

## Happy path

`start -> load profiles -> compose -> authenticate -> heartbeat -> command -> clean shutdown`

## Negative cases

- malformed/missing config
- missing or relative roots
- invalid WSS URL/TLS policy
- invalid NodeUID/private key
- duplicate/empty profile ID
- corrupt/unreadable profile database
- second process for the same state root

## Race cases

- signal during connect/reconnect
- signal while a command is in flight
- concurrent second-instance startup
- WSS disconnect during shutdown
- profile process exits while ownership is persisted

## Required tests

- unit tests for every negative case above
- process-level second-instance and SIGTERM tests
- real client process against the existing Control WSS fixture
- authenticated heartbeat and command dispatch evidence
- `go test -race` for the affected packages

## Regression tests

- full `go test ./backend/...`
- full `go test -race ./backend/...`
- `go vet ./backend/...`
- targeted Runtime, WSS, CDP, handoff, telemetry, and proxy tests

## Acceptance evidence

Binary starts without Wails, authenticates to the fixture, reports heartbeat,
executes an allowlisted runtime command, and terminates cleanly with no leaked
owned processes or secrets in logs.
