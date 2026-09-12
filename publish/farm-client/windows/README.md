# Ant Farm Client (Windows)

Signed payload updates and the offline manifest format are documented in
`../UPDATE-MANIFEST.md`.

Builds require the Suite release verification anchor so the binary can verify
canonical setup artifacts without accepting key, manifest, or install-root
overrides at runtime:

```powershell
.\publish-windows.ps1 -Arch amd64 -Version 1.5.0 `
  -ReleaseKeyID suite-release-2026 `
  -ReleasePublicKey BASE64_ED25519_PUBLIC_KEY
```

The setup and zip install the standalone Wails-free client plus pinned `xray`
and `sing-box` runtimes under `C:\Program Files\Ant Farm Client`. Mutable
identity, ownership and profile state stays under the current user's
`%LOCALAPPDATA%\AntFarmClient` tree and is preserved by uninstall.

The Program Files executable is the immutable autostart launcher. Signed
Client payloads run from an owner-only, content-addressed directory under the
mutable state root; self-update never writes Program Files.

Copy `config.example.yaml` into that state tree and replace every placeholder.
`application_root` and `ant_config_path` must point to the existing Ant
installation and its canonical config, not the Farm Client install directory.
Autostart is an explicit per-user CLI operation; the installer does not create
a machine service.
