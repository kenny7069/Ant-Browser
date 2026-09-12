# Ant Browser Suite Windows packaging scaffold

This first slice packages one preassembled, signed Windows x64 payload into an
immutable version directory under `%ProgramFiles%\Ant Browser Suite\versions`.
Mutable state remains under `%LocalAppData%\AntSuite` and upgrades never copy
files into or delete that tree.

The payload root must contain `Ant Browser.exe`, `ant-farm-client.exe`, pinned
`runtime/xray.exe` and `runtime/sing-box.exe`, the signed Suite release manifest
and detached envelope, `LICENSES.json`, and every notice referenced by that
license manifest. Every executable and the finished installer must have a valid
Windows Authenticode signature. The signed release manifest must cover every
binary, `LICENSES.json`, and every notice with its exact byte size and SHA-256
digest.

Run from a Windows release worker with `makensis.exe` and `signtool.exe` on
`PATH`:

```powershell
.\publish-windows.ps1 -PayloadRoot C:\signed-payload -Version 1.2.3 `
  -SigningCertificateSHA1 0123456789ABCDEF0123456789ABCDEF01234567 `
  -ReleaseKeyID suite-release-2026 -ReleasePublicKey BASE64_ED25519_PUBLIC_KEY
```

The installer does not start the Agent. Setup must first create the canonical
owner-only `%LocalAppData%\AntSuite\config\client.yaml`, finish the durable
preparation checkpoint, and run:

```powershell
ant-farm-client.exe suite finalize-handoff `
  -request-uid 00000000-0000-4000-8000-000000000000 `
  -suite-root "C:\Program Files\Ant Browser Suite\versions\1.2.3" `
  -gui "C:\Program Files\Ant Browser Suite\versions\1.2.3\Ant Browser.exe"
```

Only after that command succeeds may service/autostart activation proceed.
`suite launch-gui` loads the durable intent and supplies the absolute
`--farm-client-config` argument. This slice does not claim service activation,
enrollment, Control connectivity, or a native installed browser smoke test.
