#!/usr/bin/env bash
# TEST ONLY: assemble an ad-hoc signed macOS Suite payload for native install
# testing on a developer Mac.  It generates a throwaway release key, embeds it
# (and the ad-hoc signing opt-in) into ant-farm-client, uses a placeholder GUI
# bundle, and writes placeholder license notices.  Never distribute its output.
#
# Usage:
#   build-test-payload.sh --work ABS --version V --chromium-app ABS/Google\ Chrome\ for\ Testing.app
# Then:
#   publish-mac.sh --payload WORK/payload ... --adhoc-test (values printed below)
set -euo pipefail

fail() { echo "build-test-payload: $*" >&2; exit 1; }
WORK="" VERSION="" CHROMIUM_APP=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --chromium-app) CHROMIUM_APP="$2"; shift 2 ;;
    *) fail "unknown argument $1" ;;
  esac
done
[[ "$WORK" == /* && "$CHROMIUM_APP" == /* && -d "$CHROMIUM_APP" && -n "$VERSION" ]] || fail "--work, --version and --chromium-app are required"
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
case "$(uname -m)" in arm64) ARCH=arm64 ;; x86_64) ARCH=amd64 ;; *) fail "unsupported host" ;; esac
[[ ! -e "$WORK/payload" ]] || fail "$WORK/payload already exists"
mkdir -p "$WORK/tools" "$WORK/payload/runtime/chrome" "$WORK/payload/licenses" "$WORK/gui"

( cd "$REPO" && go build -o "$WORK/tools/suite-release" ./tools/suite-release )
KEY_ID="suite-test-$(date +%Y%m%d%H%M%S)"
KEY_JSON="$("$WORK/tools/suite-release" keygen -private-key-file "$WORK/tools/release.key" -key-id "$KEY_ID")"
PUBLIC_KEY="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["public_key"])' "$KEY_JSON")"

( cd "$REPO/backend" && go build -trimpath -o "$WORK/payload/ant-farm-client" -ldflags "-s -w \
  -X ant-chrome/backend.FarmClientVersion=$VERSION \
  -X main.suiteReleaseKeyID=$KEY_ID -X main.suiteReleasePublicKeyBase64=$PUBLIC_KEY \
  -X ant-chrome/backend.suiteDarwinAllowAdhocCodeSigning=1" ./cmd/ant-farm-client )

# Placeholder GUI bundle (the real Wails GUI needs the frontend build).
cat > "$WORK/gui/main.go" <<'GO'
package main

import "fmt"

func main() { fmt.Println("Ant Browser Suite TEST placeholder GUI") }
GO
( cd "$WORK/gui" && GO111MODULE=off go build -o "$WORK/payload/AntBrowser.app/Contents/MacOS/AntBrowser" main.go )
cat > "$WORK/payload/AntBrowser.app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>AntBrowser</string>
<key>CFBundleIdentifier</key><string>com.antbrowser.suite.gui.test</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string>
<key>LSUIElement</key><true/>
</dict></plist>
PLIST

cp "$REPO/bin/darwin-$ARCH/xray" "$WORK/payload/runtime/xray"
cp "$REPO/bin/darwin-$ARCH/sing-box" "$WORK/payload/runtime/sing-box"
chmod 0755 "$WORK/payload/runtime/xray" "$WORK/payload/runtime/sing-box"
ditto "$CHROMIUM_APP" "$WORK/payload/runtime/chrome/Google Chrome for Testing.app"
CHROMIUM_VERSION="$(plutil -extract CFBundleShortVersionString raw "$CHROMIUM_APP/Contents/Info.plist")"
XRAY_VERSION="$("$WORK/payload/runtime/xray" version | awk 'NR==1{print $2}')"
SINGBOX_VERSION="$("$WORK/payload/runtime/sing-box" version | awk 'NR==1{print $3}')"

for name in Ant-Browser-Suite Xray-core sing-box Chromium; do
  printf 'TEST PLACEHOLDER notice for %s. Replace with the exact upstream license text before any release.\n' "$name" \
    > "$WORK/payload/licenses/$name-LICENSE.txt"
done
python3 - "$WORK/payload/LICENSES.json" "$XRAY_VERSION" "$SINGBOX_VERSION" "$CHROMIUM_VERSION" <<'PY'
import json, sys
path, xray, singbox, chromium = sys.argv[1:5]
json.dump({
    "schema_version": 1,
    "product_license": {"name": "Ant-Browser-Suite", "license_expression": "LicenseRef-Ant-Browser-Suite",
                        "notice_file": "licenses/Ant-Browser-Suite-LICENSE.txt"},
    "artifacts": [
        {"name": "Xray-core", "version": xray, "license_expression": "MPL-2.0", "notice_file": "licenses/Xray-core-LICENSE.txt"},
        {"name": "sing-box", "version": singbox, "license_expression": "GPL-3.0-or-later", "notice_file": "licenses/sing-box-LICENSE.txt"},
        {"name": "Chromium", "version": chromium, "license_expression": "BSD-3-Clause", "notice_file": "licenses/Chromium-LICENSE.txt"},
    ],
}, open(path, "w"), indent=2)
PY

chmod -R go-w "$WORK/payload"
codesign --force --sign - "$WORK/payload/ant-farm-client" "$WORK/payload/runtime/xray" "$WORK/payload/runtime/sing-box"
codesign --force --deep --sign - "$WORK/payload/AntBrowser.app"
codesign --force --deep --sign - "$WORK/payload/runtime/chrome/Google Chrome for Testing.app"

ANT_COMMIT="$(git -C "$REPO" rev-parse HEAD)"
"$WORK/tools/suite-release" manifest -payload "$WORK/payload" -version "$VERSION" -os darwin -arch "$ARCH" \
  -commits "$ANT_COMMIT,$ANT_COMMIT,$ANT_COMMIT" \
  -core "chromium=$CHROMIUM_VERSION,xray=$XRAY_VERSION,sing-box=$SINGBOX_VERSION" \
  -config-schema 3 -capabilities "setup-plan,signed-release" -output "$WORK/payload/release-manifest.json"
"$WORK/tools/suite-release" sign -manifest "$WORK/payload/release-manifest.json" \
  -private-key-file "$WORK/tools/release.key" -key-id "$KEY_ID" -output "$WORK/payload/release-manifest.envelope.json"
chmod go-w "$WORK/payload/release-manifest.json" "$WORK/payload/release-manifest.envelope.json"

echo "payload:            $WORK/payload"
echo "release key id:     $KEY_ID"
echo "release public key: $PUBLIC_KEY"
echo "arch:               $ARCH"
