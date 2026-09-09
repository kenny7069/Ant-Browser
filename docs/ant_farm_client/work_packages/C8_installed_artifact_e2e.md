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
executes `40+2` over a loopback page-target CDP WebSocket. It waits for a fresh
resource heartbeat, then stops Chrome through the strict controller-, process-,
profile-incarnation- and telemetry-fenced `stop_runtime` command. The same
installed binary reads the canonical Profile store afterward, proving
persistence rather than an in-memory result.

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

Commit `0841cd5ed8d9bfd34b2bd2f5d8f7b2d878aa8030` passed the complete native
basic workflow matrix:

- Linux run [34342453176](https://github.com/kenny7069/Ant-Browser/actions/runs/34342453176): Ubuntu 22.04 amd64, Ubuntu 24.04 amd64 and native
  Ubuntu 24.04 arm64 all passed Debian install, real Chrome/CDP, Profile
  persistence, systemd-user registration/removal, package removal and layout
  checks. The arm64 runner uses a root-owned setuid Chromium sandbox and never
  falls back to `--no-sandbox`.
- macOS run [34342453223](https://github.com/kenny7069/Ant-Browser/actions/runs/34342453223): Intel and Apple Silicon both passed installed ZIP,
  real Chrome/CDP, strict runtime stop, Profile persistence and LaunchAgent
  registration/removal.
- Windows run [34342453165](https://github.com/kenny7069/Ant-Browser/actions/runs/34342453165): the NSIS install under Program Files, protected
  update ACL tests, process-tree RSS/termination, real Chrome/CDP, strict
  runtime stop, Scheduled Task registration/removal and NSIS uninstall all
  passed.

The native runs also exposed and closed product defects in Windows explicit
DACL handling, staged-artifact ACL publication, Windows task XML decoding,
Windows tree termination and Unix process-group cleanup. Source normal/race,
vet and Windows cross-compilation passed after those fixes.

## Remaining acceptance

C8 is not PASS until native evidence also covers fresh login/reboot and
reconnect/reconcile, installed signed update and rollback, proxy and full
Playwright/CDP gateway paths beyond the direct probe, enrollment against an
authorized external Server, native DPAPI/Keychain/Secret Service behavior,
Linux X11/Wayland plus headed/headless coverage, and the remaining two-account,
deployment-race and soak/chaos checks. Developer ID signing/notarization remains
C10 and cannot be inferred from this unsigned C8 slice.
