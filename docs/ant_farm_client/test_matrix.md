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
| C2 | Enrollment/security | one-time/expiry/replay/key storage/diagnostics | PASS on macOS arm64; target-OS native rerun required at C8 |
| C3 | Profile pairing | CRUD/readiness/pair/unpair/same-ID ABA | PASS on macOS arm64; target-OS installed rerun required at C8 |
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

## C2 commands (macOS arm64)

| Command | Result |
|---|---|
| `go test ./backend/... -count=1` | PASS (one known timing-sensitive baseline test passed on isolated rerun and full rerun) |
| `go test -race ./backend/... -count=1` | PASS |
| `go vet ./backend/...` | PASS |
| `ANT_FARM_CLIENT_NATIVE_STORE_E2E=1 go test ./backend -run '^TestFarmClientDarwinKeychainNativeOptIn$' -count=1` | PASS |
| `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./backend ./backend/cmd/ant-farm-client` | PASS |
| equivalent Linux amd64 and Darwin amd64/no-cgo builds | PASS |
| explicit Windows/Linux identity-store test compilation | PASS |
| Server enrollment + P1.6 + auth + WSS + schema suites | 77 PASS, 2 existing environment skips |
| `python3 輔助程式/test_security_hardening.py` | 36 PASS |
| C1 real Chrome authenticated ensure/attest regression | PASS normal and race |

Windows DPAPI, Linux Secret Service, different-user permissions and full
installed-artifact execution remain mandatory C8 target-host tests; their
opt-in test programs are present and are not counted as executed on macOS.

## C3 commands (macOS arm64)

| Command | Result |
|---|---|
| `go test ./backend/...` | PASS |
| focused C3 `go test -race` plus `go vet ./backend/...` | PASS |
| C1 real Chrome authenticated ensure/attest with pairing incarnation | PASS |
| `P112_CROSS_REPO_REAL_CHROME=1 P112_SERVER_REPO=/Users/bot/Desktop/dev-auto-scraper P112_REAL_CHROME_CORE=/Applications go test ./backend -run '^TestFarmRuntimeP112CrossRepoRealChrome$' -count=1 -v` | PASS; Server ID `41` mapped to a distinct Ant local ID |
| Server Farm/enrollment/auth/schema/runtime-control suites | 129 PASS, 1 existing skip |
| Python compile and `git diff --check` in both repositories | PASS |
