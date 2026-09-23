#!/usr/bin/env bash
# Package one signed macOS Suite payload into an installer .pkg.
#
# The payload root must already contain release-manifest.json and its
# detached release-manifest.envelope.json (signed by the release worker).
# This script never signs the manifest; it proves the payload matches it,
# proves every code object satisfies the signing policy, and builds a
# component package that installs the immutable version directory under
#   /Library/Application Support/Ant Browser Suite/versions/<version>
# owned by root.  It has no pre/postinstall scripts and does not start or
# register the Agent: the target user runs `ant-farm-client setup` and then
# `ant-farm-client suite service activate` from the installed version root.
#
# Usage:
#   publish-mac.sh --payload ABS --version V --arch arm64|amd64 \
#     --release-key-id ID --release-public-key BASE64 \
#     (--team-id TEAMID [--installer-identity "Developer ID Installer: ..."] | --adhoc-test) \
#     --output ABS
set -euo pipefail

fail() { echo "publish-mac: $*" >&2; exit 1; }

PAYLOAD="" VERSION="" ARCH="" KEY_ID="" PUBLIC_KEY="" TEAM_ID="" INSTALLER_IDENTITY="" ADHOC=0 OUTPUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --payload) PAYLOAD="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --arch) ARCH="$2"; shift 2 ;;
    --release-key-id) KEY_ID="$2"; shift 2 ;;
    --release-public-key) PUBLIC_KEY="$2"; shift 2 ;;
    --team-id) TEAM_ID="$2"; shift 2 ;;
    --installer-identity) INSTALLER_IDENTITY="$2"; shift 2 ;;
    --adhoc-test) ADHOC=1; shift ;;
    --output) OUTPUT="$2"; shift 2 ;;
    *) fail "unknown argument $1" ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || fail "run on macOS"
for tool in pkgbuild codesign plutil python3 shasum; do command -v "$tool" >/dev/null || fail "$tool is required"; done
[[ "$PAYLOAD" == /* && -d "$PAYLOAD" && "$OUTPUT" == /* ]] || fail "--payload and --output must be absolute"
[[ "$ARCH" == "arm64" || "$ARCH" == "amd64" ]] || fail "--arch must be arm64 or amd64"
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] || fail "--version must be release SemVer without build metadata"
[[ -n "$KEY_ID" && -n "$PUBLIC_KEY" ]] || fail "release key id and public key are required"
if [[ -n "$TEAM_ID" ]]; then
  [[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ && "$ADHOC" == 0 ]] || fail "--team-id must be a 10-character team and cannot be combined with --adhoc-test"
  REQUIREMENT="anchor apple generic and certificate leaf[subject.OU] = \"$TEAM_ID\""
elif [[ "$ADHOC" == 1 ]]; then
  [[ -z "$INSTALLER_IDENTITY" ]] || fail "--adhoc-test packages are never installer-signed"
  REQUIREMENT=""
  echo "publish-mac: WARNING ad-hoc test package; not for distribution" >&2
else
  fail "choose --team-id (release) or --adhoc-test"
fi

MANIFEST="$PAYLOAD/release-manifest.json"
ENVELOPE="$PAYLOAD/release-manifest.envelope.json"
CLIENT="$PAYLOAD/ant-farm-client"
[[ -f "$MANIFEST" && -f "$ENVELOPE" && -x "$CLIENT" ]] || fail "payload lacks manifest, envelope or ant-farm-client"

# 1. The detached envelope must verify with the external key and with the
#    trust anchor embedded in the shipped client.
"$CLIENT" suite verify-release --manifest "$MANIFEST" --envelope "$ENVELOPE" \
  --key-id "$KEY_ID" --public-key "$PUBLIC_KEY" >/dev/null || fail "Ed25519 release envelope verification failed"
"$CLIENT" suite verify-release-embedded --manifest "$MANIFEST" --envelope "$ENVELOPE" >/dev/null \
  || fail "embedded client trust anchor does not verify this release"

# 2. Exact coverage: every file and bundle symlink is signed, nothing else ships.
python3 - "$PAYLOAD" "$VERSION" "$ARCH" <<'PY' || fail "payload does not match the signed manifest"
import hashlib, json, os, stat, sys
root, version, arch = sys.argv[1:4]
manifest = json.load(open(os.path.join(root, "release-manifest.json")))
if manifest["version"] != version or manifest["target"] != {"os": "darwin", "arch": arch}:
    sys.exit("manifest identity mismatch")
required = {"AntBrowser.app/Contents/MacOS/AntBrowser", "ant-farm-client", "runtime/xray", "runtime/sing-box",
            "runtime/chrome/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing", "LICENSES.json"}
entries = {e["path"]: e for e in manifest["entries"]}
missing = required - {p for p, e in entries.items() if e["role"] != "symlink"}
if missing:
    sys.exit("manifest omits %s" % sorted(missing))
seen = set()
for directory, dirs, files in os.walk(root):
    for name in dirs + files:
        full = os.path.join(directory, name)
        rel = os.path.relpath(full, root)
        info = os.lstat(full)
        if info.st_mode & 0o022:
            sys.exit("group/other writable payload path: %s" % rel)
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            continue
        if rel in ("release-manifest.json", "release-manifest.envelope.json"):
            continue
        entry = entries.get(rel)
        if entry is None:
            sys.exit("unexpected or uncovered payload path: %s" % rel)
        seen.add(rel)
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(full)
            if entry["role"] != "symlink" or hashlib.sha256(target.encode()).hexdigest() != entry["sha256"]:
                sys.exit("symlink mismatch: %s" % rel)
            continue
        data = open(full, "rb").read()
        if entry["role"] == "symlink" or len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            sys.exit("sha256 or size mismatch: %s" % rel)
if seen != set(entries):
    sys.exit("manifest entries missing from payload: %s" % sorted(set(entries) - seen)[:5])
PY

# 3. Signing policy for every code object (outermost .app or loose binary).
python3 - "$MANIFEST" <<'PY' > "$OUTPUT.codeobjects.tmp" || fail "cannot list code objects"
import json, sys
seen = []
for entry in json.load(open(sys.argv[1]))["entries"]:
    if entry["role"] != "binary":
        continue
    parts = entry["path"].split("/")
    obj = entry["path"]
    for index, part in enumerate(parts):
        if part.endswith(".app"):
            obj = "/".join(parts[:index + 1]); break
    if obj not in seen:
        seen.append(obj); print(obj)
PY
while IFS= read -r object; do
  if [[ -n "$REQUIREMENT" ]]; then
    codesign --verify --deep --strict "-R=$REQUIREMENT" -- "$PAYLOAD/$object" || fail "code signature policy failed: $object"
  else
    codesign --verify --deep --strict -- "$PAYLOAD/$object" || fail "code signature invalid: $object"
  fi
done < "$OUTPUT.codeobjects.tmp"
rm -f "$OUTPUT.codeobjects.tmp"

# 4. Component package: root-owned, bundles pinned (never relocated).
mkdir -p "$OUTPUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ditto "$PAYLOAD" "$WORK/root"
pkgbuild --analyze --root "$WORK/root" "$WORK/components.plist" >/dev/null
# Installer must never move a bundle into another copy that happens to share
# its identifier (e.g. an existing Chrome for Testing) or skip it by version.
python3 - "$WORK/components.plist" <<'PY' || fail "cannot pin package bundles"
import plistlib, sys
path = sys.argv[1]
components = plistlib.load(open(path, "rb"))
def pin(bundles):
    count = 0
    for bundle in bundles:
        bundle["BundleIsRelocatable"] = False
        bundle["BundleIsVersionChecked"] = False
        bundle["BundleOverwriteAction"] = "upgrade"
        count += 1 + pin(bundle.get("ChildBundles", []))
    return count
if pin(components) == 0:
    sys.exit("no bundles found")
plistlib.dump(components, open(path, "wb"))
PY
PKG="$OUTPUT/Ant-Browser-Suite-$VERSION-darwin-$ARCH.pkg"
SIGN_ARGS=()
[[ -n "$INSTALLER_IDENTITY" ]] && SIGN_ARGS=(--sign "$INSTALLER_IDENTITY" --timestamp)
pkgbuild --root "$WORK/root" --component-plist "$WORK/components.plist" \
  --install-location "/Library/Application Support/Ant Browser Suite/versions/$VERSION" \
  --identifier "com.antbrowser.suite.v$VERSION" --version "$VERSION" --ownership recommended \
  ${SIGN_ARGS[@]+"${SIGN_ARGS[@]}"} "$PKG" >/dev/null || fail "pkgbuild failed"
[[ -n "$INSTALLER_IDENTITY" ]] && { pkgutil --check-signature "$PKG" >/dev/null || fail "installer signature invalid"; }
shasum -a 256 "$PKG"
echo "publish-mac: built $PKG"
echo "publish-mac: notarization (xcrun notarytool submit --wait) and stapling are release-worker steps"
