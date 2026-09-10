#!/usr/bin/env bash
set -euo pipefail

# Build the standalone, Wails-free Ant Farm Client for Linux.  All generated
# files stay below this directory so this script cannot clean the desktop
# application's publish output or staging directories.

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
ALLOW_CROSS=0

usage() {
  cat <<'EOF'
Usage:
  publish/farm-client/linux/package.sh --arch <amd64|arm64> [options]

Build a standalone Wails-free Ant Farm Client and produce a tarball and a
Debian package.  The package has no maintainer scripts and never registers a
machine daemon; autostart remains an explicit per-user CLI operation.

Options:
  --arch <amd64|arm64>   Target Linux architecture (required)
  --version <version>    Package version (default: FarmClientVersion in Go)
  --binary <path>        Prebuilt client binary (default: build/bin/ant-farm-client)
  --skip-build            Do not run go build
  --skip-runtime-verify   Do not verify pinned xray/sing-box hashes
  --keep-staging          Keep this target's staging directory for inspection
  --allow-cross           Allow a target architecture different from the host
  -h, --help              Show this help

Outputs:
  publish/farm-client/linux/dist/AntFarmClient-<version>-linux-<arch>.tar.gz
  publish/farm-client/linux/dist/ant-farm-client_<version>_<arch>.deb
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
    --allow-cross)
      ALLOW_CROSS=1
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

[[ "$(uname -s)" == "Linux" ]] || die "this script must run on a Linux host"
host_arch_raw="$(uname -m)"
case "$host_arch_raw" in
  x86_64) HOST_ARCH="amd64" ;;
  aarch64|arm64) HOST_ARCH="arm64" ;;
  *) die "unsupported host architecture: $host_arch_raw" ;;
esac
if [[ "$ALLOW_CROSS" -ne 1 && "$HOST_ARCH" != "$ARCH" ]]; then
  die "host arch is $HOST_ARCH but target arch is $ARCH; use a native host or --allow-cross"
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_cmd tar
require_cmd dpkg-deb
if [[ "$SKIP_BUILD" -ne 1 ]]; then
  require_cmd go
fi

if [[ -z "$VERSION" ]]; then
  VERSION="$(sed -n 's/^var FarmClientVersion = "\([^"]*\)"$/\1/p' "$ROOT_DIR/backend/farm_client_config.go")"
fi
[[ -n "$VERSION" ]] || die "could not determine FarmClientVersion; pass --version"
[[ "$VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z.+~:-]*$ ]] || die "invalid version '$VERSION'"

TARGET="linux-$ARCH"
RUNTIME_DIR="$ROOT_DIR/bin/$TARGET"
XRAY_SRC="$RUNTIME_DIR/xray"
SINGBOX_SRC="$RUNTIME_DIR/sing-box"
CONFIG_SRC="$SCRIPT_DIR/config.example.yaml"
README_SRC="$SCRIPT_DIR/README.md"
STAGE_DIR="$STAGING_ROOT/$TARGET-$VERSION"
TAR_STAGE="$STAGE_DIR/tar"
DEB_ROOT="$STAGE_DIR/deb"
DEB_INSTALL_ROOT="$DEB_ROOT/opt/ant-farm-client"
TAR_NAME="AntFarmClient-${VERSION}-linux-${ARCH}.tar.gz"
DEB_NAME="ant-farm-client_${VERSION}_${ARCH}.deb"
UPDATE_NAME="AntFarmClient-${VERSION}-linux-${ARCH}.update.bin"

[[ -f "$XRAY_SRC" && -f "$SINGBOX_SRC" ]] || die "missing runtime binaries for $TARGET under $RUNTIME_DIR"
[[ -f "$CONFIG_SRC" ]] || die "missing config example: $CONFIG_SRC"
[[ -f "$README_SRC" ]] || die "missing package README: $README_SRC"

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

mkdir -p "$TAR_STAGE/bin" "$DEB_INSTALL_ROOT/bin" "$DEB_ROOT/DEBIAN"

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
    GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X ant-chrome/backend.FarmClientVersion=$VERSION" \
      -o "$CLIENT_BINARY" ./backend/cmd/ant-farm-client
  )
fi

[[ -x "$CLIENT_BINARY" || -f "$CLIENT_BINARY" ]] || die "client binary was not produced: $CLIENT_BINARY"
rm -f "$OUTPUT_DIR/$UPDATE_NAME"
cp "$CLIENT_BINARY" "$OUTPUT_DIR/$UPDATE_NAME"
chmod 0755 "$OUTPUT_DIR/$UPDATE_NAME"

echo "[2/4] Assembling tar staging..."
cp "$CLIENT_BINARY" "$TAR_STAGE/ant-farm-client"
cp "$XRAY_SRC" "$TAR_STAGE/bin/xray"
cp "$SINGBOX_SRC" "$TAR_STAGE/bin/sing-box"
cp "$CONFIG_SRC" "$TAR_STAGE/config.example.yaml"
cp "$README_SRC" "$TAR_STAGE/README.md"
chmod 0755 "$TAR_STAGE/ant-farm-client" "$TAR_STAGE/bin/xray" "$TAR_STAGE/bin/sing-box"

rm -f "$OUTPUT_DIR/$TAR_NAME"
tar -C "$TAR_STAGE" -czf "$OUTPUT_DIR/$TAR_NAME" .

echo "[3/4] Assembling Debian staging..."
cp "$CLIENT_BINARY" "$DEB_INSTALL_ROOT/ant-farm-client"
cp "$XRAY_SRC" "$DEB_INSTALL_ROOT/bin/xray"
cp "$SINGBOX_SRC" "$DEB_INSTALL_ROOT/bin/sing-box"
cp "$CONFIG_SRC" "$DEB_INSTALL_ROOT/config.example.yaml"
cp "$README_SRC" "$DEB_INSTALL_ROOT/README.md"
chmod 0755 "$DEB_INSTALL_ROOT/ant-farm-client" "$DEB_INSTALL_ROOT/bin/xray" "$DEB_INSTALL_ROOT/bin/sing-box"
cat > "$DEB_ROOT/DEBIAN/control" <<EOF
Package: ant-farm-client
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Ant Chrome Team <contact@antblack.dev>
Description: Standalone Ant Farm Client
 Wails-free outbound Farm Client host with pinned proxy runtimes.
 This package intentionally does not install or register a machine daemon.
EOF
rm -f "$OUTPUT_DIR/$DEB_NAME"
dpkg-deb --build --root-owner-group "$DEB_ROOT" "$OUTPUT_DIR/$DEB_NAME" >/dev/null

echo "[4/4] Package complete"
echo "  - $OUTPUT_DIR/$TAR_NAME"
echo "  - $OUTPUT_DIR/$DEB_NAME"
echo "  - $OUTPUT_DIR/$UPDATE_NAME (signed-manifest payload)"
echo "  - no machine daemon or post-install registration was created"
