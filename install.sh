#!/bin/bash

# Xray-Proxya one-click installer. The public CLI and its private runtime
# components are always downloaded from one verified GitHub Release tag.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'
REPO="AiLing2416/xray-proxya"

ASSUME_YES=false
ASSUME_NO=false

for arg in "$@"; do
    case "$arg" in
        -y|--yes) ASSUME_YES=true ;;
        -n|--no) ASSUME_NO=true ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -y, --yes      Automatically confirm overwrite if existing binary is found"
            echo "  -n, --no       Abort installation if existing binary is found"
            echo "  -h, --help     Show this help message"
            exit 0
            ;;
    esac
done

cleanup() {
    [ -n "${WORK_DIR:-}" ] && rm -rf "$WORK_DIR" || true
}
trap cleanup EXIT

fail() {
    echo -e "${RED}❌ $*${NC}" >&2
    exit 1
}

echo -e "${GREEN}🚀 Starting Xray-Proxya installation...${NC}"
command -v curl >/dev/null 2>&1 || fail "curl is required."
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required."

case "$(uname -m)" in
    x86_64) BIN_ARCH="amd64" ;;
    aarch64|arm64) BIN_ARCH="arm64" ;;
    *) fail "Unsupported architecture: $(uname -m)" ;;
esac

INSTALL_DIR="$HOME/.local/bin"
SHARE_BIN_DIR="$HOME/.local/share/xray-proxya/bin"
if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/root/.local/bin"
    SHARE_BIN_DIR="/root/.local/share/xray-proxya/bin"
fi
TARGET_BIN="$INSTALL_DIR/xray-proxya"

if [ -f "$TARGET_BIN" ]; then
    echo -e "${YELLOW}⚠️ Found existing installation at: $TARGET_BIN${NC}"
    if [ "$ASSUME_YES" = true ]; then
        echo "ℹ️ Auto-confirming overwrite (-y/--yes specified)."
    elif [ "$ASSUME_NO" = true ]; then
        echo "Installation cancelled (-n/--no specified)."; exit 0
    elif [ -c /dev/tty ] && [ -r /dev/tty ]; then
        read -r -p "Overwrite / update it? [Y/n]: " CHOICE < /dev/tty || CHOICE=""
        case "$CHOICE" in
            [Nn]*) echo "Installation cancelled."; exit 0 ;;
        esac
    elif [ -t 0 ]; then
        read -r -p "Overwrite / update it? [Y/n]: " CHOICE || CHOICE=""
        case "$CHOICE" in
            [Nn]*) echo "Installation cancelled."; exit 0 ;;
        esac
    else
        echo "ℹ️ Non-interactive shell detected; updating."
    fi
fi

# Resolve latest once, then use that immutable tag for every asset. Two
# independent releases/latest URLs could otherwise briefly select different
# versions while a release is being published.
RELEASE_URL=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") || fail "Cannot resolve latest release."
RELEASE_TAG=${RELEASE_URL##*/}
case "$RELEASE_TAG" in
    v*) ;;
    *) fail "Unexpected latest release URL: $RELEASE_URL" ;;
esac

MAIN_ASSET="xray-proxya-linux-$BIN_ARCH"
PATHD_ASSET="pathd-linux-$BIN_ARCH"
BASE_URL="https://github.com/$REPO/releases/download/$RELEASE_TAG"
WORK_DIR=$(mktemp -d)

echo -e "⬇️ Downloading ${YELLOW}$RELEASE_TAG${NC} for $BIN_ARCH..."
for asset in "$MAIN_ASSET" "$PATHD_ASSET" SHA256SUMS; do
    curl -fL --retry 3 --retry-delay 1 "$BASE_URL/$asset" -o "$WORK_DIR/$asset" || fail "Download failed: $asset"
done

verify_asset() {
    local asset="$1" expected actual
    expected=$(awk -v asset="$asset" '$2 == asset { print $1; exit }' "$WORK_DIR/SHA256SUMS")
    [[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || fail "SHA256SUMS has no valid digest for $asset"
    actual=$(sha256sum "$WORK_DIR/$asset" | awk '{print $1}')
    [ "$actual" = "$expected" ] || fail "Integrity check failed for $asset"
}
verify_asset "$MAIN_ASSET"
verify_asset "$PATHD_ASSET"

mkdir -p "$INSTALL_DIR" "$SHARE_BIN_DIR"

# Preserve the old private Xray-core location migration, but only after both
# new release artifacts were verified.
OLD_CORE="$INSTALL_DIR/xray"
if [ -f "$OLD_CORE" ]; then
    echo "📦 Moving legacy Xray core into private storage..."
    mv "$OLD_CORE" "$SHARE_BIN_DIR/xray"
fi

install -m 0755 "$WORK_DIR/$MAIN_ASSET" "$INSTALL_DIR/.xray-proxya.new"
mv -f "$INSTALL_DIR/.xray-proxya.new" "$INSTALL_DIR/xray-proxya"
install -m 0755 "$WORK_DIR/$PATHD_ASSET" "$SHARE_BIN_DIR/.pathd.new"
mv -f "$SHARE_BIN_DIR/.pathd.new" "$SHARE_BIN_DIR/pathd"
echo -e "${GREEN}✅ xray-proxya installed to: $INSTALL_DIR/xray-proxya${NC}"
echo -e "${GREEN}✅ private pathd installed to: $SHARE_BIN_DIR/pathd${NC}"

SHELL_NAME=$(basename "${SHELL:-/bin/bash}")
RC_FILE="$HOME/.bashrc"
if [ "$SHELL_NAME" = "zsh" ]; then
    RC_FILE="$HOME/.zshrc"
elif [ "$SHELL_NAME" = "fish" ]; then
    RC_FILE="$HOME/.config/fish/config.fish"
elif [ "$(id -u)" -eq 0 ]; then
    RC_FILE="/root/.bashrc"
fi

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "export PATH=\$PATH:$INSTALL_DIR" >> "$RC_FILE"
    echo -e "${GREEN}✅ Added $INSTALL_DIR to PATH in $RC_FILE${NC}"
fi
export PATH="$PATH:$INSTALL_DIR"

echo -e "\n${GREEN}✨ Installation successful.${NC}"
echo "Run 'xray-proxya init' to get started. Existing services keep their current binary until restarted."

# Ask whether to configure shell completion and refresh environment profile.
# This prompt is explicitly interactive and deliberately unaffected by any -y/-n flags passed to the installer.
COMPLETION_CHOICE=""
if [ -c /dev/tty ] && [ -r /dev/tty ]; then
    echo
    read -r -p "Configure shell completion and refresh environment profile? [Y/n]: " COMPLETION_CHOICE < /dev/tty || COMPLETION_CHOICE=""
elif [ -t 0 ]; then
    echo
    read -r -p "Configure shell completion and refresh environment profile? [Y/n]: " COMPLETION_CHOICE || COMPLETION_CHOICE=""
else
    echo "ℹ️ Non-interactive shell detected; skipped completion configuration prompt."
    COMPLETION_CHOICE="n"
fi

case "$COMPLETION_CHOICE" in
    [Nn]*)
        echo "Skipped shell completion configuration."
        ;;
    *)
        if [ -x "$TARGET_BIN" ]; then
            "$TARGET_BIN" doctor completion install || true
            [ -f "$RC_FILE" ] && . "$RC_FILE" 2>/dev/null || true
            echo -e "${GREEN}🔄 Shell profile updated. To activate completion and refresh your current session, run:${NC}"
            echo -e "   ${YELLOW}source $RC_FILE${NC}  (or open a new terminal)"
        fi
        ;;
esac
