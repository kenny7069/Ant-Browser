# C0 Baseline Evidence

## Revisions

- Ant-Browser branch: `farm-client-dev`
- Ant-Browser SHA: `e83fc37ad5271034aba35f4d6b5a8b7ee3d394c1`
- auto-scraper branch: `feature/browser-farm-p1`
- auto-scraper SHA: `2ca94b58c7d2ca95849c5f75495950b301f6bd49`
- Host: macOS arm64
- Go: `go1.27.1 darwin/arm64`

Both repositories contained pre-existing untracked user files at inspection
time. They were not modified or included in the baseline.

## Ant commands

| Command | Result |
|---|---|
| `go vet ./backend/...` | PASS |
| `go test ./backend/... -count=1` | PASS |
| `go test -race ./backend/... -count=1` | PASS |
| two local-process timing tests, isolated with `-count=5` | PASS, 10/10 executions |

The first un-cached full run timed out once in each of two one-second
local-process tests. Both passed five consecutive isolated repetitions and the
subsequent un-cached full suite, so this is classified as a pre-existing timing
flake, not a new regression. C1 must not modify Frozen Core to mask it.

## Environment-required evidence

The following existing tests were discovered and intentionally skipped because
their explicit opt-in fixtures were not supplied:

- P1.12/P1.14 cross-repo real Chrome
- P1.13 real Xray proxy Chrome
- P1.18 real Chrome handoff
- P1.17 cross-repo resource RTT
- P1.12 and P1.18 local real Chrome
- Windows two-account DACL acceptance

These remain required at their installed-artifact/release Gates.

## Server commands

The pinned Farm suite passed for browser provider/identity, node enrollment,
control schema/WSS, tenant and controller lease, attestation, runtime control,
CDP gateway, resource RTT, queue integration, live monitor, auth, tenancy,
profile mirror, and dashboard/page contracts. Key results included:

- P1.6 enrollment: 23 tests, one environment skip
- P1.7 Control WSS: 22 tests, one environment skip
- P1.12 runtime control: 13 tests
- P1.13 proxy/runtime control: 5 tests
- P1.14 authority/CDP: 5 tests
- auth gate: 81 tests
- tenancy routing: 42 tests
- shared profile mirror: 25 tests

`test_shared_profile_queue.py` initially exposed a pre-existing source-contract
drift: its assertions still required per-cycle renewal/release after production
had moved ownership into persistent `_LiveMonitorRuntimeSession`. No production
code changed. The assertion now verifies periodic session renewal, renewal on
`touch()`, release on `close()`, and cycle acquisition through the persistent
session. The corrected 38-contract test and the dedicated runtime-session test
both pass.

Live database preflight reported a schema/migration mismatch in the available
external database (32/34 checks), and real queue/live/CDP E2E lacked their
explicit fixtures. They are classified as environment evidence, not source
regressions; no migration or external DB mutation was performed.

## C1 delta verification

After implementing the standalone host, the baseline was rerun sequentially:

| Command | Result |
|---|---|
| `go test ./backend/... -count=1` | PASS |
| `go test -race ./backend/... -count=1` | PASS |
| `go vet ./backend/...` | PASS |
| Windows amd64 build of backend and `ant-farm-client` | PASS |
| opt-in WSS → real Chrome → attestation test | PASS, normal and race |

The real test loaded both the profile and Chrome core exclusively from the
SQLite fixture. A separate test proved that an SQLite-only proxy binding is
resolved through the retained ProxyDAO and exposes only opaque revisions.
