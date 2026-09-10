#!/usr/bin/env bash
set -euo pipefail

# Build the standalone, Wails-free Ant Farm Client for macOS.  The generated
# app and zip are isolated below this directory; no shared desktop build or
# publish output is removed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/dist"
STAGING_ROOT="$SCRIPT_DIR/.staging"

ARCH=""
VERSION=""
BINARY_OVERRIDE=""
SKIP_BUILD=0
SKIP_RUNTIME_VERIFY=0
KEEP_STAGING=0

usage() {
  cat <<'EOF'
Usage:
  publish/farm-client/macos/package.sh --arch <amd64|arm64> [options]

Build a standalone unsigned Ant Farm Client.app containing the Wails-free
CLI host and pinned proxy runtimes. It is an LSUIElement/background bundle;
it does not install a LaunchDaemon or any other machine service.

Options:
  --arch <amd64|arm64>   Target macOS architecture (required; native host)
  --version <version>    Package version (default: FarmClientVersion in Go)
  --binary <path>        Prebuilt client binary (default: build/bin/ant-farm-client)
  --skip-build            Do not run go build
  --skip-runtime-verify   Do not verify pinned xray/sing-box hashes
  --keep-staging          Keep this target's staging directory for inspection
  -h, --help              Show this help

Outputs:
  publish/farm-client/macos/dist/AntFarmClient-<version>-macos-<arch>.app
  publish/farm-client/macos/dist/AntFarmClient-<version>-macos-<arch>.zip

Release gate:
  Artifacts are intentionally unsigned. Before distribution, perform the
  team's hardened-runtime codesign step and xcrun notarytool submission,
  then staple and verify the notarization ticket.
EOF
}

die() {
  echo "[ERROR] $*" >&2
  exit 1
}

need_value() {
  [[ $# -ge 2 && -n "${2:-}" ]] || die "$1 requires a value"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch)
      need_value "$@"
      ARCH="$2"
      shift 2
      ;;
    --version)
      need_value "$@"
      VERSION="$2"
      shift 2
      ;;
    --binary)
      need_value "$@"
      BINARY_OVERRIDE="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --skip-runtime-verify)
      SKIP_RUNTIME_VERIFY=1
      shift
      ;;
    --keep-staging)
      KEEP_STAGING=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1 (use --help for usage)"
      ;;
  esac
done

[[ -n "$ARCH" ]] || { usage >&2; die "--arch is required"; }
[[ "$ARCH" == "amd64" || "$ARCH" == "arm64" ]] || die "unsupported --arch '$ARCH' (expected amd64 or arm64)"
[[ "$(uname -s)" == "Darwin" ]] || die "this script must run on a macOS host"

host_arch_raw="$(uname -m)"
case "$host_arch_raw" in
  x86_64) HOST_ARCH="amd64" ;;
  arm64) HOST_ARCH="arm64" ;;
  *) die "unsupported host architecture: $host_arch_raw" ;;
esac
[[ "$HOST_ARCH" == "$ARCH" ]] || die "host arch is $HOST_ARCH but target is $ARCH; use the native macOS runner"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_cmd ditto
if [[ "$SKIP_BUILD" -ne 1 ]]; then
  require_cmd go
fi

if [[ -z "$VERSION" ]]; then
  VERSION="$(sed -n 's/^var FarmClientVersion = "\([^"]*\)"$/\1/p' "$ROOT_DIR/backend/farm_client_config.go")"
fi
[[ -n "$VERSION" ]] || die "could not determine FarmClientVersion; pass --version"
[[ "$VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z.+~:-]*$ ]] || die "invalid version '$VERSION'"

TARGET="darwin-$ARCH"
RUNTIME_DIR="$ROOT_DIR/bin/$TARGET"
XRAY_SRC="$RUNTIME_DIR/xray"
SINGBOX_SRC="$RUNTIME_DIR/sing-box"
CONFIG_SRC="$SCRIPT_DIR/config.example.yaml"
README_SRC="$SCRIPT_DIR/README.md"
SIGNING_GATE_SRC="$SCRIPT_DIR/SIGNING-NOTARIZATION.md"
STAGE_DIR="$STAGING_ROOT/$TARGET-$VERSION"
APP_STAGE="$STAGE_DIR/Ant Farm Client.app"
APP_EXPORT="$OUTPUT_DIR/AntFarmClient-${VERSION}-macos-${ARCH}.app"
ZIP_NAME="AntFarmClient-${VERSION}-macos-${ARCH}.zip"
UPDATE_NAME="AntFarmClient-${VERSION}-darwin-${ARCH}.update.bin"

[[ -f "$XRAY_SRC" && -f "$SINGBOX_SRC" ]] || die "missing runtime binaries for $TARGET under $RUNTIME_DIR"
[[ -f "$CONFIG_SRC" ]] || die "missing config example: $CONFIG_SRC"
[[ -f "$README_SRC" ]] || die "missing package README: $README_SRC"
[[ -f "$SIGNING_GATE_SRC" ]] || die "missing signing gate: $SIGNING_GATE_SRC"

if [[ "$SKIP_RUNTIME_VERIFY" -eq 1 ]]; then
  echo "[WARN] runtime verification skipped"
else
  bash "$ROOT_DIR/tools/runtime/verify-runtime.sh" "$TARGET"
fi

mkdir -p "$STAGING_ROOT" "$OUTPUT_DIR"
rm -rf "$STAGE_DIR"

cleanup() {
  if [[ "$KEEP_STAGING" -ne 1 ]]; then
    rm -rf "$STAGE_DIR"
  else
    echo "[INFO] keeping staging: $STAGE_DIR"
  fi
}
trap cleanup EXIT

if [[ "$SKIP_BUILD" -eq 1 ]]; then
  if [[ -n "$BINARY_OVERRIDE" ]]; then
    CLIENT_BINARY="$BINARY_OVERRIDE"
  else
    CLIENT_BINARY="$ROOT_DIR/build/bin/ant-farm-client"
  fi
  [[ -f "$CLIENT_BINARY" ]] || die "prebuilt binary not found: $CLIENT_BINARY (pass --binary to select another path)"
else
  CLIENT_BINARY="$STAGE_DIR/ant-farm-client"
  echo "[1/4] Building Wails-free Farm Client ($TARGET)..."
  (
    cd "$ROOT_DIR"
    # The macOS identity store is backed by Security.framework and is guarded
    # by the `darwin && cgo` build tag.  A CGO-disabled package silently links
    # the fail-closed fallback, making first-run enrollment impossible.
    GOOS=darwin GOARCH="$ARCH" CGO_ENABLED=1 go build -trimpath \
      -ldflags "-s -w -X ant-chrome/backend.FarmClientVersion=$VERSION" \
      -o "$CLIENT_BINARY" ./backend/cmd/ant-farm-client
  )
fi

[[ -x "$CLIENT_BINARY" || -f "$CLIENT_BINARY" ]] || die "client binary was not produced: $CLIENT_BINARY"
rm -f "$OUTPUT_DIR/$UPDATE_NAME"
cp "$CLIENT_BINARY" "$OUTPUT_DIR/$UPDATE_NAME"
chmod 0755 "$OUTPUT_DIR/$UPDATE_NAME"

echo "[2/4] Assembling unsigned app bundle..."
APP_CONTENTS="$APP_STAGE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_RESOURCES="$APP_CONTENTS/Resources"
mkdir -p "$APP_MACOS" "$APP_RESOURCES/bin"
cp "$CLIENT_BINARY" "$APP_MACOS/ant-farm-client"
cp "$XRAY_SRC" "$APP_RESOURCES/bin/xray"
cp "$SINGBOX_SRC" "$APP_RESOURCES/bin/sing-box"
cp "$CONFIG_SRC" "$APP_RESOURCES/config.example.yaml"
cp "$README_SRC" "$APP_RESOURCES/README.md"
cp "$SIGNING_GATE_SRC" "$APP_RESOURCES/SIGNING-NOTARIZATION.md"
chmod 0755 "$APP_MACOS/ant-farm-client" "$APP_RESOURCES/bin/xray" "$APP_RESOURCES/bin/sing-box"
cat > "$APP_CONTENTS/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>Ant Farm Client</string>
  <key>CFBundleExecutable</key>
  <string>ant-farm-client</string>
  <key>CFBundleIdentifier</key>
  <string>com.antfarm.client</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>Ant Farm Client</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$VERSION</string>
  <key>CFBundleVersion</key>
  <string>$VERSION</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
  <key>LSUIElement</key>
  <true/>
  <key>LSBackgroundOnly</key>
  <true/>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
EOF

rm -rf "$APP_EXPORT"
ditto "$APP_STAGE" "$APP_EXPORT"
rm -f "$OUTPUT_DIR/$ZIP_NAME"
ditto -c -k --sequesterRsrc --keepParent "$APP_EXPORT" "$OUTPUT_DIR/$ZIP_NAME"

echo "[3/4] Verifying app metadata and unsigned gate..."
if command -v plutil >/dev/null 2>&1; then
  plutil -lint "$APP_EXPORT/Contents/Info.plist" >/dev/null
fi
[[ -f "$APP_EXPORT/Contents/Resources/SIGNING-NOTARIZATION.md" ]] || die "signing gate missing from app bundle"

echo "[4/4] Package complete (UNSIGNED)"
echo "  - $APP_EXPORT"
echo "  - $OUTPUT_DIR/$ZIP_NAME"
echo "  - signing/notarization gate: $APP_EXPORT/Contents/Resources/SIGNING-NOTARIZATION.md"
echo "  Run the team's codesign + xcrun notarytool + stapler flow before distribution."
