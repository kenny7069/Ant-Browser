# Ant Farm Client Implementation Status

| Gate | Status | Notes |
|---|---|---|
| C0 Baseline / Branch | PASS | Pinned pair, ownership, risks, matrix, and regressions reviewed |
| C1 Standalone Host | PASS | Wails-free host, strict config, lock, canonical SQLite manager, WSS, real Chrome attestation and shutdown verified |
| C2 Enrollment | PASS | One-time HTTPS API, response-loss confirmation, secure per-OS identity, CLI bootstrap and secret-free diagnostics verified |
| C3 Profile Pairing | PASS | Canonical SQLite CRUD/open, signed one-time pairing, durable ABA fence and Server↔Ant ID translation verified |
| C4 Background Lifecycle | PASS | Per-user Windows/macOS/Linux autostart, controller-fenced production WSS auth and ownership-aware SIGTERM verified |
| C5 Packaging | PASS | Dedicated Windows/Linux/macOS artifacts, isolated workflows, pinned runtimes and unsigned-macOS release gate verified |
| C6 Fleet Management | PASS | Admin-only inventory/actions, enrollment, pairing, telemetry fallback and closed command surface verified |
| C7 Updater | PASS | Signed manifest, immutable launcher, transactional reconcile, probation and rollback verified by independent SOL-MID review |
| C8 Installed E2E | NOT STARTED | |
| C9 Social/Soak/Chaos | NOT STARTED | |
| C10 Final Release | NOT STARTED | Fresh independent acceptance required |

## Confirmed C0 findings

- `e83fc37` is the required Farm baseline and contains the post-`f19a195`
  handoff, ownership persistence, and Windows DACL hardening.
- Whole-branch merge from `master` is prohibited.
- The core composition factories already exist and remain Frozen Core.
- Standalone profile loading needs a minimal facade over the existing store.
- `farm_storage_key` is not a local Ant Profile ID and no pairing adapter exists
  in the current pair of repositories.

## C1 completion evidence

- Added the Wails-free `backend/cmd/ant-farm-client` composition root.
- Retained one read-only SQLite-backed Manager with Profile, Proxy, Core,
  Bookmark, Group and Extension DAOs.
- Added a local launch recorder/attestation provider whose locale, timezone,
  WebRTC and proxy evidence comes from actual launch/runtime state.
- Added only the architecture-approved additive factory seam in
  `backend/browser_runtime_service_public.go`; no lifecycle semantics changed.
- Authenticated WSS → ensure → real Chrome ready → attest passed on macOS arm64,
  including a race-enabled execution.
- Full backend tests, full race tests, vet, and Windows amd64 cross-build passed.

## C2 completion evidence

- Added admin/CSRF code issuance and unauthenticated HTTPS enrollment routes
  over the existing transactional P1.6 primitive; exact-tuple confirmation is
  read-only and bounded to 120 seconds after consume.
- Trusted-proxy TLS/source parsing, 8 KiB request bounds and source/node rate
  limits execute before unauthenticated JSON parsing.
- Added Ed25519 first-run generation and stable pending-key retry, Windows
  DPAPI, macOS Keychain, Linux Secret Service with a pinned owner-only fallback,
  and per-user/per-reference cross-process first-save locking.
- Added `-enroll` stdin/password input, explicit loopback HTTP opt-in, secure
  Host key-reference loading, allowlisted diagnostics and panic redaction.
- Independent SOL security review found and verified fixes for five P1 issues;
  the final review returned PASS with no remaining P0/P1.
- Full Go tests/race/vet, macOS native Keychain, real Chrome acceptance,
  Windows/Linux/macOS builds, Server enrollment/P1.6/auth/WSS/schema suites and
  security hardening passed. Target-OS native execution repeats in C8.

## C3 completion evidence

- Added safe CLI operations over the canonical Ant SQLite Manager: list,
  create, open, pair and unpair. Pairing secrets are read from no-echo terminal
  or bounded stdin and no `farm_profiles.json` exists.
- Added immutable SQLite `incarnation_id` migration/backfill/direct-insert
  trigger and a domain-separated pairing incarnation, so a deleted/recreated
  same-ID profile fails closed before any runtime observation or launch.
- Added signed, one-time, node-bound Server pairing grants with exact replay,
  expiry, response-loss confirmation and one cross-database transaction for
  tenant profile plus Control affinity updates.
- Server affinity stores only the local ID/incarnation and safe projection;
  `farm_storage_key` remains an independently generated opaque locator.
- Added strict recursive Server↔Ant profile identity translation for ensure,
  attestation, status and stop identities, with contradiction rejection.
- Cross-repository TLS WSS acceptance proved Server profile `41` translated to
  a distinct local Ant profile for real Chrome launch, attestation and status.
- Full Go tests, focused race, vet, Server Farm/auth/schema suites and real
  Chrome acceptance passed on macOS arm64.

## C4 completion evidence

- Added `autostart install|remove|status` with safe output and strict absolute
  executable/config validation.
- Windows uses a least-privilege, interactive-token Scheduled Task at logon;
  macOS uses a user LaunchAgent; Linux prefers `systemd --user` and falls back
  to XDG desktop-session autostart. No machine service or global process-name
  termination is used.
- Registration files are owner-only and atomically published; symlinked
  destination directories and partial registration failures fail closed.
- Server startup now acquires its existing controller lease before Control WSS
  and publishes that exact ID/generation in node authentication. Missing or
  invalid lease identity rejects the connection and returns the node offline.
- Full Go/race/vet, Windows/Linux/macOS builds, 177 Server farm/control/Queue
  tests, real Chrome Host and cross-repository real Chrome tests passed.
- Native login/reboot and installed-artifact repetitions remain mandatory C8
  evidence and are not inferred from cross-builds.

## C5 completion evidence

- Added isolated `publish/farm-client/{windows,linux,macos}` packaging and
  `farm-client-v*` workflows. They cannot match the Desktop `v*` release and
  never write into the Desktop staging/output trees.
- Linux produces versioned amd64/arm64 `.deb` and `.tar.gz` packages with the
  verified xray + sing-box runtime pair. Both architectures were assembled in
  target-architecture Ubuntu containers and their packaged Client binaries
  executed with the injected `1.5.0` version.
- macOS produces versioned Intel/Apple Silicon `.app` and `.zip` artifacts.
  The Apple Silicon package was assembled and inspected natively; its Client,
  xray and sing-box binaries are arm64 and its plist/version are valid.
- macOS output has no Developer ID/notarization acceptance. Tag-triggered
  publication fails closed until C10 adds hardened-runtime signing,
  notarization, stapling and Gatekeeper verification.
- Windows produces a separate setup and zip under Program Files/Local AppData
  semantics. Its installer stops only the exact installed Client executable,
  contains no global xray/sing-box process-name cleanup, preserves per-user
  state, and has a Windows 2022 native build/validation workflow.
- Full Go tests, full race tests, vet, package-policy tests, workflow YAML,
  shell syntax, runtime hashes and five target Client builds passed. Native
  Windows installer execution and installed upgrade/uninstall remain C8.

## C6 completion evidence

- Added an admin-only Fleet page and named APIs for Nodes, Enrollment,
  Versions, Pairing, Updates and Diagnostics. The inventory combines durable
  Control-plane state with live WSS telemetry and degrades to durable data when
  a session is offline.
- Added transactional rename, drain, resume, disable, enable, revoke, update
  channel and unpair operations. Admin unpair restores the tenant profile to
  the local provider, clears only its opaque Farm locator, disables affinity
  and revokes an unused grant in one MySQL transaction.
- Drain is serialized against new runtime commands while preserving liveness.
  Resume, disable and revoke fence authentication/commands and close the exact
  Control session plus tracked CDP tunnels before the durable state write;
  persistent Chrome runtimes are not killed.
- The Server and Agent retain the same finite Control command allowlist. No
  generic command, shell, PowerShell, Bash or upload-and-run API/UI was added.
- Enrollment responses are non-cacheable, secrets are cleared on dialog close,
  expiry, page hide and backgrounding, and unknown Node subresources return
  stable 404 responses.
- Fleet, Control WSS, CDP gateway, auth, schema, enrollment, pairing, runtime,
  attestation, telemetry, live-monitor and Queue regressions passed. Desktop
  and modal layouts were visually inspected; HTML and inline JavaScript checks
  passed. Independent SOL review returned PASS with no remaining P1/P2.

## C7 implementation evidence

- Added strict Ed25519 update envelopes for all five targets, offline signing,
  non-executable staging and a private content-addressed payload store.
- Added an immutable lifetime launcher with atomic active/previous/pending
  activation, drain fencing, continuous probation health and rollback.
- Successor health now requires a digest-bound inventory completion produced
  only after Server transactional comparison with controller/runtime leases,
  Node, all live runtime rows and profile affinity.
- Normal service stop, update rollback and launcher-loss shutdown have distinct
  semantics; rollback/parent loss preserve owned Chrome and connector state.
- Updated payloads are pinned against symlink/reparse/hardlink and pathname
  replacement according to the platform-specific boundary in architecture.
- Full Go normal/race/vet, five target builds and focused Server suites pass.
  Fresh independent SOL-MID review returned C7 PASS with no remaining
  P0/P1/P2/P3 findings after fail-closed terminal-authority and current-time
  pending-envelope expiry regressions were added.
