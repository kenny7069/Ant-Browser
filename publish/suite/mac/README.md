# Ant Browser Suite macOS packaging

`publish-mac.sh` turns one signed macOS payload into a component `.pkg` that
installs the immutable version directory

```
/Library/Application Support/Ant Browser Suite/versions/<version>
```

owned by root. It is the macOS counterpart of the Windows Program Files
package: the Agent user can never write the installed tree, so a verified
binary cannot be swapped between validation and spawn.

## Payload layout

| Entry | Path |
|---|---|
| GUI | `AntBrowser.app/Contents/MacOS/AntBrowser` |
| Agent / setup | `ant-farm-client` |
| Proxy runtimes | `runtime/xray`, `runtime/sing-box` |
| Chromium | `runtime/chrome/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing` |
| Legal | `LICENSES.json` and every notice it names |

The signed release manifest covers every file byte-for-byte and every bundle
symlink by the digest of its exact target (role `symlink`, macOS only).
macOS manifests may use inner spaces, parentheses and leading underscores in
path segments and paths up to 512 bytes; Windows and Linux rules are
unchanged.

## Code signing policy

`ant-farm-client` enforces the policy compiled into it:

- release: `-X ant-chrome/backend.suiteDarwinCodeSigningTeamID=<TEAMID>`;
  every code object must satisfy
  `anchor apple generic and certificate leaf[subject.OU] = "<TEAMID>"`;
- test: `-X ant-chrome/backend.suiteDarwinAllowAdhocCodeSigning=1` accepts
  valid ad-hoc signatures;
- neither: every macOS install is refused.

Code objects are the outermost `.app` bundles (verified `--deep --strict`) and
loose Mach-O binaries.

## Release build

1. Sign every code object with the Developer ID Application identity and the
   hardened runtime; re-sign bundled Chromium with the same identity.
2. Build `release-manifest.json` and sign the detached envelope
   (`tools/suite-release manifest` / `sign`) on the release worker.
3. Run:

```bash
publish/suite/mac/publish-mac.sh --payload /abs/payload --version 1.2.3 --arch arm64 --release-key-id suite-release-2026 --release-public-key BASE64 --team-id ABCDE12345 --installer-identity "Developer ID Installer: Example (ABCDE12345)" --output /abs/out
```

4. Notarize and staple the `.pkg` (`xcrun notarytool submit --wait`,
   `xcrun stapler staple`), then `spctl --assess --type install`.

The script refuses uncovered or group/other-writable payload paths, pins
every bundle as non-relocatable and not version-checked, and has no install
scripts.

## After install (target user, not root)

```bash
"/Library/Application Support/Ant Browser Suite/versions/1.2.3/ant-farm-client" setup --server https://farm.example.com
```

```bash
"/Library/Application Support/Ant Browser Suite/versions/1.2.3/ant-farm-client" suite service activate
```

Activation writes a per-user LaunchAgent
(`~/Library/LaunchAgents/com.antbrowser.suite.agent.<hash>.plist`), disabled
first via launchd's disabled database, audited byte-for-byte, then enabled and
started. It only loads in a GUI (Aqua) login session and restarts only after a
crash.

## Local test package

`build-test-payload.sh` assembles an ad-hoc signed payload with a throwaway
release key, a placeholder GUI and placeholder notices. Its output is for
native testing on a developer Mac only and must never be distributed.
