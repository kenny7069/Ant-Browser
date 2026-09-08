# Ant Farm Client Test Matrix

| Gate | Scope | Required evidence | Current state |
|---|---|---|---|
| C0 | Ant baseline | `go test ./backend/...`, race, vet | PASS on macOS arm64; see `baseline.md` |
| C0 | Server baseline | Listed Farm pytest suite | PASS; environment-only E2E exclusions recorded |
| C0 | Windows secure runtime | Windows 2022 two-account DACL workflow | Environment-required |
| C0 | Real Chrome/proxy/cross-repo | Explicit opt-in tests and fixtures | Environment-required |
| C1 | Config and roots | invalid config, missing AppRoot, duplicate profile, invalid NodeUID, log escape | PASS |
| C1 | SQLite composition | read-only store; canonical Profile/Proxy/Core DAOs; SQLite-only proxy/core | PASS |
| C1 | Process lifecycle | second instance, SIGTERM, graceful shutdown | PASS |
| C1 | Control integration | authenticated WSS heartbeat/inventory and WSS→ensure→real Chrome→attest | PASS on macOS arm64 |
| C1 | Attestation | actual args, generation/PID/debug port/readiness, direct-mode fail closed, evidence cleanup | PASS |
| C1 | Core regression | full test, full race, vet, Windows cross-build | PASS |
| C2 | Enrollment/security | one-time/expiry/replay/key storage/diagnostics | Not started |
| C3 | Profile pairing | CRUD/readiness/pair/unpair/same-ID ABA | Not started |
| C4-C7 | Lifecycle/package/update | platform services, signed update, rollback | Not started |
| C8-C10 | Installed E2E/release | Windows, Linux, macOS, social, soak, chaos | Not started |

No skipped real-browser, cross-repository, Windows, installed-artifact, soak, or
chaos test may be counted as release acceptance.

## C1 commands (macOS arm64)

| Command | Result |
|---|---|
| `go test ./backend/... -count=1` | PASS |
| `go test -race ./backend/... -count=1` | PASS |
| `go vet ./backend/...` | PASS |
| `GOOS=windows GOARCH=amd64 go build ./backend ./backend/cmd/ant-farm-client` | PASS |
| `C1_REAL_CHROME=1 C1_REAL_CHROME_CORE=/Applications go test ./backend -run '^TestFarmClientHostRealChromeEnsureAttest$' -count=1 -v` | PASS |
| same real-Chrome command with `-race` | PASS |
