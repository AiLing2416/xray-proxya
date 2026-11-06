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
INSTALL_XRAY=""
XRAY_PINNED_VERSION="v26.10.31"
XRAY_VERSION="${XRAY_VERSION:-$XRAY_PINNED_VERSION}"

for arg in "$@"; do
    case "$arg" in
        -y|--yes) ASSUME_YES=true ;;
        -n|--no) ASSUME_NO=true ;;
        --with-xray|--xray) INSTALL_XRAY=true ;;
        --without-xray|--no-xray) INSTALL_XRAY=false ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -y, --yes          Automatically confirm overwrite if existing binary is found"
            echo "  -n, --no           Abort installation if existing binary is found"
            echo "      --with-xray    Install/update Xray-core without prompting"
            echo "      --without-xray Skip Xray-core installation/update without prompting"
            echo "  -h, --help         Show this help message"
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
    x86_64)
        BIN_ARCH="amd64"
        XRAY_ARCH="64"
        ;;
    aarch64|arm64)
        BIN_ARCH="arm64"
        XRAY_ARCH="arm64-v8a"
        ;;
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
for asset in "$MAIN_ASSET" SHA256SUMS; do
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

mkdir -p "$INSTALL_DIR" "$SHARE_BIN_DIR"

# Preserve the old private Xray-core location migration, but only after
# the new release artifact was verified.
OLD_CORE="$INSTALL_DIR/xray"
if [ -f "$OLD_CORE" ]; then
    echo "📦 Moving legacy Xray core into private storage..."
    mv "$OLD_CORE" "$SHARE_BIN_DIR/xray"
fi

install -m 0755 "$WORK_DIR/$MAIN_ASSET" "$INSTALL_DIR/.xray-proxya.new"
mv -f "$INSTALL_DIR/.xray-proxya.new" "$INSTALL_DIR/xray-proxya"

# Multi-call symlink for pathd (saves ~4.5MB redundant Go runtime binary)
rm -f "$SHARE_BIN_DIR/pathd"
if ln -sf "$INSTALL_DIR/xray-proxya" "$SHARE_BIN_DIR/pathd" 2>/dev/null; then
    echo -e "${GREEN}✅ pathd linked to: $INSTALL_DIR/xray-proxya (multi-call)${NC}"
else
    # Fallback for environments lacking symlink support: download standalone binary if available
    if curl -fsSL "$BASE_URL/$PATHD_ASSET" -o "$WORK_DIR/$PATHD_ASSET" 2>/dev/null && grep -q "$PATHD_ASSET" "$WORK_DIR/SHA256SUMS"; then
        verify_asset "$PATHD_ASSET"
        install -m 0755 "$WORK_DIR/$PATHD_ASSET" "$SHARE_BIN_DIR/pathd"
        echo -e "${GREEN}✅ pathd installed to: $SHARE_BIN_DIR/pathd${NC}"
    else
        cp -f "$INSTALL_DIR/xray-proxya" "$SHARE_BIN_DIR/pathd"
        echo -e "${GREEN}✅ pathd copied from: $INSTALL_DIR/xray-proxya${NC}"
    fi
fi
echo -e "${GREEN}✅ xray-proxya installed to: $INSTALL_DIR/xray-proxya${NC}"

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

# Optional Xray-core installation or update
XRAY_BIN="$SHARE_BIN_DIR/xray"
XRAY_PROMPT="Install Xray-core ($XRAY_VERSION)? [Y/n]: "
if [ -f "$XRAY_BIN" ]; then
    CURRENT_XRAY_VER=$("$XRAY_BIN" version 2>/dev/null | head -n1 | awk '{print $2}') || CURRENT_XRAY_VER=""
    if [ -n "$CURRENT_XRAY_VER" ]; then
        XRAY_PROMPT="Update Xray-core ($CURRENT_XRAY_VER -> $XRAY_VERSION)? [Y/n]: "
    else
        XRAY_PROMPT="Update existing Xray-core to $XRAY_VERSION? [Y/n]: "
    fi
fi

XRAY_CHOICE=""
if [ -n "$INSTALL_XRAY" ]; then
    if [ "$INSTALL_XRAY" = true ]; then
        XRAY_CHOICE="y"
    else
        XRAY_CHOICE="n"
    fi
elif [ -c /dev/tty ] && [ -r /dev/tty ]; then
    echo
    read -r -p "$XRAY_PROMPT" XRAY_CHOICE < /dev/tty || XRAY_CHOICE=""
elif [ -t 0 ]; then
    echo
    read -r -p "$XRAY_PROMPT" XRAY_CHOICE || XRAY_CHOICE=""
else
    if [ "$ASSUME_YES" = true ]; then
        XRAY_CHOICE="y"
    else
        echo "ℹ️ Non-interactive shell detected; skipped Xray-core installation prompt."
        XRAY_CHOICE="n"
    fi
fi

case "$XRAY_CHOICE" in
    [Nn]*)
        echo "Skipped Xray-core installation."
        ;;
    *)
        echo -e "⬇️ Downloading Xray-core ${YELLOW}$XRAY_VERSION${NC} for $BIN_ARCH..."
        XRAY_ZIP="Xray-linux-$XRAY_ARCH.zip"
        XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/$XRAY_ZIP"
        curl -fL --retry 3 --retry-delay 1 "$XRAY_URL" -o "$WORK_DIR/$XRAY_ZIP" || fail "Failed to download $XRAY_URL"
        curl -fL --retry 3 --retry-delay 1 "$XRAY_URL.dgst" -o "$WORK_DIR/$XRAY_ZIP.dgst" || fail "Failed to download $XRAY_URL.dgst"

        EXPECTED_XRAY_HASH=""
        if grep -qi -E 'SHA2-256|SHA256' "$WORK_DIR/$XRAY_ZIP.dgst" 2>/dev/null; then
            for word in $(grep -i -E 'SHA2-256|SHA256' "$WORK_DIR/$XRAY_ZIP.dgst" | tr -d '\r' | tr '=()' '   '); do
                if [ ${#word} -eq 64 ] && [[ "$word" =~ ^[0-9a-fA-F]+$ ]]; then
                    EXPECTED_XRAY_HASH=$(echo "$word" | tr 'A-F' 'a-f')
                    break
                fi
            done
        fi
        if [ -z "$EXPECTED_XRAY_HASH" ]; then
            for word in $(tr -d '\r' < "$WORK_DIR/$XRAY_ZIP.dgst" 2>/dev/null | tr '=()' '   '); do
                if [ ${#word} -eq 64 ] && [[ "$word" =~ ^[0-9a-fA-F]+$ ]]; then
                    EXPECTED_XRAY_HASH=$(echo "$word" | tr 'A-F' 'a-f')
                    break
                fi
            done
        fi
        [[ "$EXPECTED_XRAY_HASH" =~ ^[[:xdigit:]]{64}$ ]] || fail "Cannot extract valid SHA256 digest for $XRAY_ZIP"

        ACTUAL_XRAY_HASH=$(sha256sum "$WORK_DIR/$XRAY_ZIP" | awk '{print $1}')
        [ "$ACTUAL_XRAY_HASH" = "$EXPECTED_XRAY_HASH" ] || fail "Integrity check failed for $XRAY_ZIP (expected $EXPECTED_XRAY_HASH, got $ACTUAL_XRAY_HASH)"

        echo "📦 Extracting Xray-core into $SHARE_BIN_DIR..."
        XRAY_TMP_DIR="$WORK_DIR/xray_extracted"
        mkdir -p "$XRAY_TMP_DIR"
        if command -v unzip >/dev/null 2>&1; then
            unzip -q -o "$WORK_DIR/$XRAY_ZIP" "xray" "geoip.dat" "geosite.dat" -d "$XRAY_TMP_DIR"
        elif command -v python3 >/dev/null 2>&1; then
            python3 -c "import zipfile, sys; z=zipfile.ZipFile(sys.argv[1]); [z.extract(m, sys.argv[2]) for m in z.namelist() if m in ['xray', 'geoip.dat', 'geosite.dat']]" "$WORK_DIR/$XRAY_ZIP" "$XRAY_TMP_DIR"
        else
            fail "Neither unzip nor python3 is available to extract Xray-core."
        fi
        chmod 0755 "$XRAY_TMP_DIR/xray"
        [ -f "$XRAY_TMP_DIR/geoip.dat" ] && chmod 0644 "$XRAY_TMP_DIR/geoip.dat" || true
        [ -f "$XRAY_TMP_DIR/geosite.dat" ] && chmod 0644 "$XRAY_TMP_DIR/geosite.dat" || true

        # Atomic replacement: rename(2) replaces the directory entry without opening the running binary for writing, preventing ETXTBSY (Text file busy).
        mv -f "$XRAY_TMP_DIR/xray" "$SHARE_BIN_DIR/xray"
        [ -f "$XRAY_TMP_DIR/geoip.dat" ] && mv -f "$XRAY_TMP_DIR/geoip.dat" "$SHARE_BIN_DIR/geoip.dat" || true
        [ -f "$XRAY_TMP_DIR/geosite.dat" ] && mv -f "$XRAY_TMP_DIR/geosite.dat" "$SHARE_BIN_DIR/geosite.dat" || true
        echo -e "${GREEN}✅ Xray-core ($XRAY_VERSION) installed to: $SHARE_BIN_DIR/xray${NC}"
        ;;
esac

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
