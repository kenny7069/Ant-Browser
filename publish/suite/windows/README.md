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

`ant-farm-client.exe` must be built with the same release key ID and Ed25519
public key supplied below. Publishing verifies the detached envelope twice:
once with these external release-worker values and once with the trust anchor
embedded in the binary. A missing, mismatched, or development binary therefore
stops packaging.

Run from a Windows release worker with `makensis.exe` and `signtool.exe` on
`PATH`:

```powershell
.\publish-windows.ps1 -PayloadRoot C:\signed-payload -Version 1.2.3 `
  -SigningCertificateSHA1 0123456789ABCDEF0123456789ABCDEF01234567 `
  -ReleaseKeyID suite-release-2026 -ReleasePublicKey BASE64_ED25519_PUBLIC_KEY
```

The manifest schema accepts SemVer build metadata. This Windows scaffold keeps
its existing filesystem version policy and accepts release SemVer without a
`+build` suffix; numeric prerelease identifiers with leading zeroes are rejected
by both paths.

The installer does not start the Agent. From the installed immutable version
directory, the unelevated target user runs canonical setup. The only setup
options are `--server`, optional `--node-name`, and optional `--json`; the
release root, manifest, envelope, key ID, and public key are bound by the
running executable and cannot be overridden:

```powershell
& "C:\Program Files\Ant Browser Suite\versions\1.2.3\ant-farm-client.exe" setup `
  --server https://farm.example.com --node-name "Packing Node"
```

Setup resumes from the last durable canonical stage, prompts once for the
one-time enrollment code only when `IDENTITY_READY` has no durable
acknowledgment, and finishes at `ENROLLED`. The next action is
`service_activation`; setup does not expose a service-start command.
The durable handoff created during finalization is ownership evidence, but
`ENROLLED` does not authorize service activation by itself. GUI launching and
desktop shortcuts remain deferred until T08 provides a strict GUI mode that
consumes the verified handoff. T07 owns safe activation, repair rotation,
canonical Program Files resolution and DACL validation, immediate pre-spawn
release revalidation, rollback, and a signed uninstaller, so this scaffold
deliberately does not register or emit an uninstaller. This package does not
claim service activation, Control connectivity, or a native installed browser
smoke test.
