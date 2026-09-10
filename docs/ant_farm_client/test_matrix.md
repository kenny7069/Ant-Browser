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
| C4 | Background lifecycle | per-user autostart, production controller fence, graceful ownership-aware shutdown | PASS in unit/integration/cross-build; native installed login/reboot repeats at C8 |
| C5 | Dedicated packaging | isolated Windows setup/zip, Linux deb/tar, macOS app/zip, runtime/version/release gates | PASS; Windows native install and macOS production signing remain C8/C10 |
| C6 | Fleet management | inventory, enrollment, named actions, pairing, telemetry, closed command surface | PASS |
| C7 | Signed update | signed update, drain/restart/reconcile, pinned execution and rollback | PASS; independent SOL-MID review found no remaining P0/P1/P2/P3 |
| C8 | Installed artifact process boundary | artifact hash/path/native target, real Chrome/CDP, strict stop, persistence, native autostart, uninstall | IN PROGRESS; all five native basic matrices PASS at `0841cd5` |
| C8 | Installed signed update/rollback | real Ed25519 manifest, native A/B payloads, authoritative reconcile, continuous probation and rollback | PASS locally on Apple Silicon; five-target workflow execution pending |
| C8-C10 | Remaining installed E2E/release | reboot/login, proxy/CDP/Playwright, external Server, all native targets, social/soak/chaos | Not started / not inferred |

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

## C4 commands (macOS arm64)

| Command | Result |
|---|---|
| `go test ./backend/... -count=1` | PASS |
| focused autostart/WSS/SIGTERM `go test -race` and `go vet ./backend/...` | PASS |
| Windows amd64, Linux amd64/arm64 and macOS amd64/arm64 Client builds | PASS |
| Server Control WSS + Queue + Farm/auth/schema suites | 177 PASS, 2 existing skips |
| C1 real Chrome Host regression | PASS |
| C3 cross-repository TLS WSS/real Chrome profile-translation regression | PASS |

## C5 commands (macOS arm64 + Linux containers)

| Command / evidence | Result |
|---|---|
| `go test ./backend/... -count=1` | PASS |
| `go test -race ./backend/... -count=1` | PASS |
| `go vet ./backend/...` | PASS |
| `bash -n publish/farm-client/{linux,macos}/package.sh` and Ruby YAML parse of three workflows | PASS |
| `tools/runtime/verify-runtime.sh` for darwin-arm64, linux-amd64 and linux-arm64 | PASS |
| native macOS arm64 `package.sh --arch arm64 --version 1.5.0` | PASS; versioned `.app`/`.zip`, plist and three Mach-O architectures verified |
| Ubuntu target containers package and inspect Linux amd64/arm64 tar + deb | PASS; packaged binaries executed and reported exact version/GOARCH |
| Darwin amd64 and Windows amd64 Client cross-builds with release version injection | PASS |
| packaging policy/schema tests | PASS; isolated paths, dedicated tags/names, strict secure-reference examples, no global process cleanup |

Windows NSIS execution requires the existing `windows-2022` workflow and is
not counted as an installed-artifact pass here. macOS artifacts are explicitly
not Developer ID signed or notarized and cannot be externally released; those
acceptance gates remain C8 and C10 respectively.

## C6 commands (Server)

| Command / evidence | Result |
|---|---|
| `python3 輔助程式/test_farm_admin_c6.py` | PASS, 19 tests |
| `python3 輔助程式/test_control_wss_p1_7.py` | PASS, 25 tests; 1 existing environment skip |
| `python3 輔助程式/test_cdp_gateway_p1_14.py` | PASS, 9 tests |
| auth, Control schema, enrollment and Node enrollment suites | PASS, 140 checks/tests; 1 existing environment skip |
| resource RTT, pairing, runtime control/authority and attestation suites | PASS |
| live-monitor Farm provider and Queue browser-Farm integration | PASS |
| Python compile, HTML parse, inline `node --check`, `git diff --check` | PASS |
| desktop inventory and enrollment-modal visual inspection | PASS |
| independent SOL P1/P2 review after cancellation/race hardening | PASS |

The available live MySQL instance was not migrated as part of this gate.
Installed-environment migration and multi-process deployment checks remain C8
evidence and are not inferred from mocked transaction/schema tests.

## C7 commands (macOS arm64 + target builds)

| Command / evidence | Result |
|---|---|
| `go test ./backend/... -count=1` | PASS |
| `go test -race ./backend/... -count=1` | PASS |
| `go vet ./backend/...` | PASS |
| Windows amd64, Linux amd64/arm64 and Darwin amd64/arm64 Client builds | PASS |
| launcher, probation, WSS-loss preservation, activation crash/replay and pinned payload tests | PASS |
| Server `test_control_wss_p1_7.py` | PASS, 38 passed; 1 existing environment skip |
| Server `test_farm_admin_c6.py` | PASS, 19 tests |
| fresh independent SOL-MID gate review | C7 PASS; no remaining P0/P1/P2/P3 |

The native publish workflows execute the backend tests on each target runner;
fresh installed upgrade/rollback, real login persistence, two-account ACL and
true MySQL deployment races remain C8 evidence rather than inferred C7 PASS.

## C8 commands (installed artifact)

| Command / evidence | Result |
|---|---|
| package macOS arm64 1.5.1, install the produced ZIP outside the working tree, bind SHA/version/native target, then run `TestFarmClientInstalledArtifactRealChrome` | PASS; artifact SHA-256 `0865350ef3f6809987f8bf54db0fa93101b3777959c01bbb394c0fa16ea55e0e` |
| installed 1.5.1 arm64 Client → authenticated WSS → real Chrome ensure/attest → page-target CDP `40+2` → ordinary stop → installed CLI Profile persistence | PASS on local Apple Silicon |
| `TestFarmClientInstalledArtifactAutostartNative` against the installed app | PASS; real LaunchAgent install/active/remove, no registration left behind |
| Linux workflow run [34342453176](https://github.com/kenny7069/Ant-Browser/actions/runs/34342453176) at `0841cd5` | PASS; Ubuntu 22.04/24.04 amd64 and Ubuntu 24.04 arm64 installed Debian artifacts, real Chrome/CDP, strict stop, Profile persistence, systemd-user and uninstall |
| macOS workflow run [34342453223](https://github.com/kenny7069/Ant-Browser/actions/runs/34342453223) at `0841cd5` | PASS; Intel and Apple Silicon installed ZIP artifacts, real Chrome/CDP, strict stop, Profile persistence and LaunchAgent removal |
| Windows workflow run [34342453165](https://github.com/kenny7069/Ant-Browser/actions/runs/34342453165) at `0841cd5` | PASS; NSIS install/uninstall, protected update ACL, process tree, real Chrome/CDP, strict stop and Scheduled Task removal |
| installed A 1.5.1 → signed B 1.5.2 → reconcile/probation commit → authorized A downgrade with withheld completion → automatic stable-B rollback | PASS locally on Apple Silicon at `fd31252`; native workflow matrix wired, results pending |
| fresh login/reboot, proxy, Playwright/CDP gateway beyond the direct probe, external Server enrollment/reconcile, native identity stores and Linux display modes | REQUIRED; not yet implemented/executed as installed evidence |

The C8 test rejects development versions, mismatched artifact hashes, a target
different from the native Go runtime, executables outside the declared install
root, and installed/release executables inside the source working tree. Source tests, target
cross-builds and package-layout inspection remain insufficient for C8 PASS.
