# Work Package C8 — Installed Artifact E2E

## Objective

Prove the standalone Client through the native installed executable produced
by a release artifact. Source composition, cross-build and archive inspection
are regressions only and cannot satisfy this gate.

## Evidence contract

Every installed run binds all of the following before Client execution:

- release artifact absolute path and SHA-256;
- non-development package version;
- native GOOS/GOARCH reported by the installed executable;
- install root and executable path outside the source working tree;
- the release artifact's actual installer or extraction result.

Missing or contradictory evidence fails the test. The opt-in tests skip in an
ordinary source run and a skip is never a PASS.

## Implemented runner slice

`TestFarmClientInstalledArtifactRealChrome` launches the installed immutable
launcher, crosses the launcher/Agent process boundary, authenticates to a
bounded Control fixture, starts real Chrome, applies launch attestation and
executes `40+2` over a loopback page-target CDP WebSocket. It then stops the
Client normally and uses the same installed binary to read the canonical
Profile store, proving persistence rather than an in-memory result.

`TestFarmClientInstalledArtifactAutostartNative` uses the installed binary to
exercise the real per-user registration backend. It refuses to overwrite a
pre-existing registration, waits for an active native registration, removes
it and proves no installed/active state remains.

The manual publish workflows now consume the artifact they just produced:

- Windows executes the NSIS setup, runs installed tests under Program Files,
  executes the uninstaller and requires the installed executable to disappear.
- Linux installs the Debian package under `/opt/ant-farm-client`, runs installed
  tests and removes the package. The matrix covers Ubuntu 22.04/24.04 amd64 and
  native arm64, and requires `systemd-user` rather than accepting XDG fallback.
- macOS extracts the ZIP outside the checkout and runs the installed tests on
  native Intel and Apple Silicon runners with a real LaunchAgent.

## Current native evidence

Local Apple Silicon execution passed against unsigned version 1.5.1 artifact
SHA-256 `0865350ef3f6809987f8bf54db0fa93101b3777959c01bbb394c0fa16ea55e0e`:

- installed artifact identity/path/native target;
- authenticated WSS → real Chrome ensure → attestation → direct CDP evaluation;
- Profile persistence through a fresh installed CLI process;
- LaunchAgent install → active → remove.

The LaunchAgent was removed after the run. The installed test application was
moved to Trash and is recoverable.

## Remaining acceptance

C8 is not PASS until native evidence also covers fresh login/reboot and
reconnect/reconcile, installed signed update and rollback, proxy and full
Playwright/CDP gateway paths beyond the direct probe, enrollment against an authorized Server, Windows,
both required Ubuntu amd64 versions, Linux arm64 if advertised, and Intel plus
Apple Silicon macOS. Developer ID signing/notarization remains C10 and cannot
be inferred from this unsigned C8 slice.
