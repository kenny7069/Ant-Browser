# Ant Browser Suite Windows packaging scaffold

This first slice packages one preassembled, signed Windows x64 payload into an
immutable version directory under `%ProgramFiles%\Ant Browser Suite\versions`.
Mutable state remains under `%LocalAppData%\AntSuite`, but the elevated machine
installer never creates, populates, or deletes that tree. The actual unelevated
Agent user must run setup so owner-only roots cannot accidentally belong to the
installer's elevation account.

The payload root must contain `AntBrowser.exe`, `ant-farm-client.exe`, pinned
`runtime/xray.exe`, `runtime/sing-box.exe`, and
`runtime/chrome/chrome.exe`, the signed Suite release manifest and detached
envelope, `LICENSES.json`, and every notice referenced by that license
manifest. Every executable and the finished installer must have a valid Windows
Authenticode signature. The signed release manifest must cover every binary,
`LICENSES.json`, and every notice with its exact byte size and SHA-256 digest.
Every signed third-party dependency must match exactly one payload
`LICENSES.json` artifact by name, version, and legal notice path, and every
artifact must match one dependency. The repository `LICENSES.json` is the
version-agnostic allowlist for dependency name, license expression, and notice
path plus the exact first-party product license; release payloads add the exact
third-party versions bound by their signed manifest. The product license notice
must also be an exact signed `legal` entry.

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
  -gui "C:\Program Files\Ant Browser Suite\versions\1.2.3\AntBrowser.exe"
```

The handoff is necessary ownership evidence, but `INTENT_DURABLE` does not mean
the Suite is `READY` and does not authorize service activation by itself. A
later workflow must finish the canonical setup stages. GUI launching and
desktop shortcuts remain deferred until T08 provides a strict GUI mode that
consumes the verified handoff. T07 owns safe activation, repair rotation,
rollback, and a signed uninstaller, so this scaffold deliberately does not
register or emit an uninstaller. This slice does not claim service activation,
enrollment, Control connectivity, or a native installed browser smoke test.
