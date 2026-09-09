# Work Package C5 — Dedicated Cross-platform Packaging

## Objective

Reuse the existing Desktop pipeline primitives to package the Wails-free Farm
Client as a separate product without overwriting Desktop artifacts, state,
processes, tags or release jobs.

## Artifact contract

- Windows amd64: `AntFarmClient-Setup-<version>-x64.exe` and
  `AntFarmClient-<version>-windows-x64.zip`.
- Linux amd64/arm64: `ant-farm-client_<version>_<arch>.deb` and
  `AntFarmClient-<version>-linux-<arch>.tar.gz`.
- macOS Intel/Apple Silicon: versioned `.app` and `.zip` artifacts.
- Every package embeds the pinned target-specific xray and sing-box pair plus
  a strict example config that uses only a secure identity reference.
- The package version is injected into `backend.FarmClientVersion` at link
  time and is verified by executing the packaged Client where possible.

Each platform owns a local `dist` and `.staging` tree below
`publish/farm-client`. Desktop `publish/output`, `publish/staging`, product
names and `v*` tags remain untouched.

## Lifecycle and data contract

- Install roots contain immutable program/runtime files only. Mutable identity,
  ownership, logs and profile state remain in the explicit current-user root.
- Packaging never registers a machine daemon. Per-user autostart is the C4 CLI
  operation performed after a valid absolute config is installed.
- Windows installs binaries below `Program Files` and preserves
  `%LOCALAPPDATA%\AntFarmClient` on uninstall. Shutdown targets the exact
  installed Client path; global `taskkill`, xray, or sing-box name matching is
  prohibited.
- Linux `.deb` has no maintainer scripts and installs no system service.
- macOS uses a background/agent app bundle and installs no LaunchDaemon.

## Release safety

The macOS C5 bundle is intentionally not Developer ID signed or notarized.
Tag builds fail before artifact upload. Production release remains blocked
until C10 performs hardened-runtime nested signing, notarization, stapling,
`codesign --verify`, and Gatekeeper assessment.

The Windows and Linux workflows use the dedicated `farm-client-v*` namespace.
C10 must still provide one unified all-platform release decision so partial
assets are never mistaken for full production acceptance.

## Verification

- Full backend tests, full race tests and vet.
- Strict config parsing plus package ownership/path policy tests.
- Shell syntax and workflow YAML parsing.
- Runtime manifest hash verification.
- Native macOS arm64 package build, plist/architecture/archive inspection and
  packaged version execution.
- Linux amd64 and arm64 tar/deb generation and packaged binary execution in
  target-architecture Ubuntu containers.
- Darwin amd64 and Windows amd64 versioned cross-builds.

Native Windows setup execution, multi-user DACL, install/upgrade/uninstall,
login/reboot and all installed-artifact paths are explicitly deferred to C8;
macOS signing/notarization acceptance is C10.
