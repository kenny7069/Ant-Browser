# Known Risks

| Risk | Gate / mitigation |
|---|---|
| Standalone SQLite/Manager/fingerprint/attestation composition gap | Resolved in C1 with a narrow loader, approved additive factory seam and local launch evidence |
| Server profile ID and local Ant Profile ID are not mapped | Resolved in C3 with explicit affinity plus strict recursive boundary translation |
| Full profile objects contain sensitive local details | C1/C3: strict safe-field projection; never send raw objects |
| Profile incarnation was in-memory only | Resolved in C3 with immutable SQLite `incarnation_id`, backfill, direct-insert trigger and pairing hash |
| `LoadConfig` repairs malformed config | C1 bootstrap must define strict validation semantics before service construction |
| Existing one-second process tests can be timing-sensitive | Track as baseline flake; do not relax Frozen Core tests |
| One server test had a stale per-cycle lease source assertion | Corrected to verify persistent session heartbeat/touch/close ownership; behavior test passes |
| Real Chrome/cross-repo tests require opt-in fixtures | Run at C1 integration and installed-artifact Gates; skipped is not PASS |
| Available live server database is behind expected schema | Treat as environment; run controlled migrations only in an authorized test environment |
| Windows DACL cannot be proven on macOS | Preserve Windows 2022 acceptance workflow and extend it for Client state later |
| macOS/Linux/Windows state roots differ | C1 must separate install root from mutable state root explicitly |
| Shared Desktop and Client processes may touch one profile store | C3 uses canonical SQLite transactions and busy timeout; live Manager caches still require operator avoidance of simultaneous same-profile edits until a cross-process refresh/coordination seam is added |
| BrowserRuntimeService shutdown has no context/deadline parameter | C1 bounds transport teardown and records this limitation; a total hard deadline needs a separately reviewed lifecycle change |
| Existing state-root ownership/permission hardening is platform-specific | C5 packages preserve per-user roots and C1 creates new Unix roots with mode 0700; verify owner/mode/two-account DACL in C8 installed-artifact tests |
| Connector stacks can be accidentally mixed | Enforce `xray` combined stack versus standalone `mihomo` at every operation |
| Updater/uninstaller may kill foreign processes | Ownership-scoped drain/stop only; never global process-name kill |
| Enrollment limiter is process-local | Safe for the current single-process server; C6 multi-worker/replica deployment must use a shared gateway/limiter before scale-out |
| Windows DPAPI and Linux Secret Service cannot execute on macOS | Native opt-in tests and cross-builds are present; execute them again in C8 installed-artifact workflows on each target OS |
| Pairing replay rows are retained indefinitely | Request IDs are 128-bit, signed and rate-limited; add bounded audited retention before fleet-scale C6 rollout |
| Production Control WSS lacked controller lease identity in auth acknowledgement | Resolved in C4: startup acquires the shared factory lease first and WSS fails closed when its exact ID/generation is unavailable |
| Native autostart behavior cannot be executed on all target OSes from macOS | C4 has platform descriptor tests and five target builds; C8 must prove real login/reboot/start/stop/remove on Windows, Linux and both macOS architectures |
| Windows NSIS cannot execute on the macOS development host | C5 adds a dedicated Windows 2022 build/layout/policy workflow; fresh install, upgrade and uninstall are mandatory C8 evidence |
| macOS C5 packages are not Developer ID signed or notarized | The macOS tag workflow refuses unsigned publication; C10 must add hardened-runtime signing, notarization, stapling and Gatekeeper acceptance before external release |
| Platform release jobs can produce partial non-macOS assets before C10 | Do not treat a `farm-client-v*` tag as a production release until the C10 unified release gate validates every required artifact and compatibility hash |
| Fleet live telemetry can disappear when a Control session drops | C6 falls back to durable inventory and labels freshness; C8 must verify reconnect and stale-state behavior against an installed fleet |
| Fleet update status is present before the signed updater exists | C6 reports the durable `unknown` state and update channel; C7 owns signed manifests, state transitions and rollback |
| Admin transitions can race commands or accepted CDP tunnels | Resolved in C6 with a per-Node transition/command lane, authentication fence, identity-safe tunnel registry and cancellation/capacity behavior tests |
| C6 schema migrations were verified without mutating the available live database | Run additive migration and rollback checks in the authorized installed C8 environment before production rollout |
| macOS has no supported fd-exec primitive for the per-user successor payload | C7 pins every path component, hashes the open fd and rechecks identity immediately before spawn; same-login-user arbitrary code execution is explicitly outside scope. If that threat enters scope, use a privileged broker rather than claim pathname checks close it |
| Windows updater DACL/reparse and Linux fd-exec cannot execute on the macOS development host | Native release workflows run backend security tests; repeat two-account and replacement-race cases using installed artifacts in C8 |
| C7 authoritative reconciliation was verified with transactional SQL fakes, not a mutable production MySQL instance | Execute update handoff against an authorized migrated MySQL environment and concurrent lease/runtime writers in C8 |
| A same-login-user code execution attacker can also read Client config, alter per-user autostart and interfere with headed Chrome | Explicitly outside the C7 per-user updater boundary; Administrator/root, kernel and filesystem-filter compromise are also excluded |
