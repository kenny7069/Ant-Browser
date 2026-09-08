# Known Risks

| Risk | Gate / mitigation |
|---|---|
| Standalone SQLite/Manager/fingerprint/attestation composition gap | Resolved in C1 with a narrow loader, approved additive factory seam and local launch evidence |
| Server profile ID and local Ant Profile ID are not mapped | C3: explicit pairing record and fail-closed adapter |
| Full profile objects contain sensitive local details | C1/C3: strict safe-field projection; never send raw objects |
| Profile incarnation is in-memory only | Preserve existing ABA fencing; durable restore uses creation/process identity |
| `LoadConfig` repairs malformed config | C1 bootstrap must define strict validation semantics before service construction |
| Existing one-second process tests can be timing-sensitive | Track as baseline flake; do not relax Frozen Core tests |
| One server test had a stale per-cycle lease source assertion | Corrected to verify persistent session heartbeat/touch/close ownership; behavior test passes |
| Real Chrome/cross-repo tests require opt-in fixtures | Run at C1 integration and installed-artifact Gates; skipped is not PASS |
| Available live server database is behind expected schema | Treat as environment; run controlled migrations only in an authorized test environment |
| Windows DACL cannot be proven on macOS | Preserve Windows 2022 acceptance workflow and extend it for Client state later |
| macOS/Linux/Windows state roots differ | C1 must separate install root from mutable state root explicitly |
| Shared Desktop and Client processes may touch one profile store | Define locking/read consistency before C3 write operations |
| BrowserRuntimeService shutdown has no context/deadline parameter | C1 bounds transport teardown and records this limitation; a total hard deadline needs a separately reviewed lifecycle change |
| Existing state-root ownership/permission hardening is platform-specific | Verify owner/mode/DACL in C5 installed-artifact tests; C1 creates new Unix roots with mode 0700 |
| Connector stacks can be accidentally mixed | Enforce `xray` combined stack versus standalone `mihomo` at every operation |
| Updater/uninstaller may kill foreign processes | Ownership-scoped drain/stop only; never global process-name kill |
| Enrollment limiter is process-local | Safe for the current single-process server; C6 multi-worker/replica deployment must use a shared gateway/limiter before scale-out |
| Windows DPAPI and Linux Secret Service cannot execute on macOS | Native opt-in tests and cross-builds are present; execute them again in C8 installed-artifact workflows on each target OS |
