# Ant Farm Client Implementation Status

| Gate | Status | Notes |
|---|---|---|
| C0 Baseline / Branch | PASS | Pinned pair, ownership, risks, matrix, and regressions reviewed |
| C1 Standalone Host | PASS | Wails-free host, strict config, lock, canonical SQLite manager, WSS, real Chrome attestation and shutdown verified |
| C2 Enrollment | READY | Existing primitives/API gap documented; C1 development-key input must be replaced |
| C3 Profile Pairing | NOT STARTED | Explicit local/server mapping required |
| C4 Background Lifecycle | NOT STARTED | |
| C5 Packaging | NOT STARTED | |
| C6 Fleet Management | NOT STARTED | |
| C7 Updater | NOT STARTED | |
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
