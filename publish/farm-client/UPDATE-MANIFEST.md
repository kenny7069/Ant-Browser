# Farm Client Signed Update Manifest

Farm Client update payloads are raw Wails-free Client binaries. Installers,
Desktop artifacts, xray, sing-box, mutable state, profiles and ownership files
are not self-update payloads.

The unsigned JSON payload has exactly these fields:

```json
{
  "version": "1.5.1",
  "protocol_version": "bf-p1.6",
  "minimum_protocol_version": "bf-p1.6",
  "channel": "stable",
  "published_at": "2026-09-09T00:00:00Z",
  "expires_at": "2026-09-16T00:00:00Z",
  "allow_downgrade": false,
  "artifacts": {
    "windows-amd64": {"url": "https://updates.example/windows.exe", "sha256": "...", "size": 1},
    "linux-amd64": {"url": "https://updates.example/linux-amd64.bin", "sha256": "...", "size": 1},
    "linux-arm64": {"url": "https://updates.example/linux-arm64.bin", "sha256": "...", "size": 1},
    "darwin-amd64": {"url": "https://updates.example/darwin-amd64.bin", "sha256": "...", "size": 1},
    "darwin-arm64": {"url": "https://updates.example/darwin-arm64.bin", "sha256": "...", "size": 1}
  }
}
```

All five targets are mandatory. URLs use HTTPS, SHA-256 is lowercase hex, and
the signed manifest has a bounded validity window. Downgrade requires both the
signed manifest and the local Client policy to opt in.

Sign offline with an owner-only base64 Ed25519 private-key file:

```text
go run ./tools/farm-client-update-manifest \
  -manifest /absolute/manifest.json \
  -private-key-file /absolute/private-key.base64 \
  -output /absolute/stable.json
```

The output envelope contains the exact manifest bytes as base64 plus a detached
Ed25519 signature. Publish only the envelope and artifacts. Never deploy the
private key to the Farm Server, Client package or CI artifact.

The updater rejects redirects, unknown or duplicate JSON fields, expired or
future manifests, incomplete target sets, protocol/channel mismatch, digest or
size mismatch, and real PE/ELF/Mach-O architecture mismatch. A downloaded file
remains non-executable in the private state root until verification completes.

The system-installed executable is an immutable launcher. It never overwrites
Program Files, `/opt`, or `Contents/MacOS`; verified payloads are copied into an
owner-only, content-addressed directory below `state_root`. Autostart always
targets the launcher, which re-verifies the original signed envelope and
artifact before every activation or startup.

One atomically replaced activation record contains active, previous and pending
slots. A pending child must keep an authenticated WSS health lease alive for the
configured probation window after the Server explicitly acknowledges the same
inventory snapshot. Failure clears the pending slot and reconnects the prior
payload. The updater never enumerates or kills Chrome, xray, sing-box or any
process by name.
