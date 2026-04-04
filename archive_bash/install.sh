#!/bin/sh

# ==================================================
# Xray-Proxya Installer (Universal)
# Supports: Debian/Ubuntu & Alpine (OpenRC)
# ==================================================

REPO_BASE="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main"
SRC_DIR="src"

# Default
TargetScript="main.sh"
InstallName="xray-proxya"

# Parse Arguments
for arg in "$@"; do
    case $arg in
        --help|-h)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --help, -h     Show this help message"
            exit 0
            ;;
    esac
done

REMOTE_SCRIPT_URL="$REPO_BASE/$SRC_DIR/$TargetScript"
REMOTE_MAINTAIN_URL="$REPO_BASE/$SRC_DIR/maintain.sh"
REMOTE_LIB_URL="$REPO_BASE/$SRC_DIR/lib.sh"
REMOTE_LOGIC_URL="$REPO_BASE/$SRC_DIR/logic.sh"

INSTALL_DIR="/usr/local/sbin"
INSTALL_PATH="$INSTALL_DIR/$InstallName"

MAINTAIN_DIR="/usr/local/bin"
MAINTAIN_FILENAME="xray-proxya-maintenance"
MAINTAIN_PATH="$MAINTAIN_DIR/$MAINTAIN_FILENAME"

LIB_DIR="/opt/xray-proxya"
LIB_PATH="$LIB_DIR/lib.sh"
LOGIC_PATH="$LIB_DIR/logic.sh"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# 1. Root Check
if [ "$(id -u)" -ne 0 ]; then
    printf "${RED}Error: This script must be run as root.${NC}\n"
    exit 1
fi

echo "⚙️  Checking environment..."

# 2. Dependency Check
if [ -f /etc/alpine-release ]; then
    # Alpine Linux
    echo "📦 Detected Alpine Linux. Installing dependencies (bash, curl)..."
    apk add --no-cache bash curl >/dev/null 2>&1
elif [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    apt-get update -qq >/dev/null
    apt-get install -y curl >/dev/null 2>&1
fi

# 3. Ensure Directories
[ ! -d "$INSTALL_DIR" ] && mkdir -p "$INSTALL_DIR"
[ ! -d "$MAINTAIN_DIR" ] && mkdir -p "$MAINTAIN_DIR"
[ ! -d "$LIB_DIR" ] && mkdir -p "$LIB_DIR"

# 4. Download Files
echo "⬇️  Downloading manager script ($TargetScript)..."
# Clean legacy lib file
[ -f "/opt/xray-proxya/main_lib.sh" ] && rm -f "/opt/xray-proxya/main_lib.sh" && echo "🧹 Removed legacy main_lib.sh"

if curl -sSfL -o "$INSTALL_PATH" "$REMOTE_SCRIPT_URL"; then
    echo "✅ Manager script downloaded."
else
    printf "${RED}❌ Download failed! URL: $REMOTE_SCRIPT_URL${NC}\n"
    exit 1
fi

echo "⬇️  Downloading maintenance script..."
if curl -sSfL -o "$MAINTAIN_PATH" "$REMOTE_MAINTAIN_URL"; then
    chmod 755 "$MAINTAIN_PATH"
else
    printf "${YELLOW}⚠️  Download maintenance script failed, skipping...${NC}\n"
fi

echo "⬇️  Downloading library..."
if curl -sSfL -o "$LIB_PATH" "$REMOTE_LIB_URL"; then
    chmod 644 "$LIB_PATH"
else
    printf "${RED}❌ Download library (lib.sh) failed!${NC}\n"
    exit 1
fi

echo "⬇️  Downloading core logic..."
if curl -sSfL -o "$LOGIC_PATH" "$REMOTE_LOGIC_URL"; then
    chmod 644 "$LOGIC_PATH"
else
    printf "${RED}❌ Download logic (logic.sh) failed!${NC}\n"
    exit 1
fi

# 5. Quick Integrity Check
for f in "$INSTALL_PATH" "$LIB_PATH" "$LOGIC_PATH"; do
    if [ ! -s "$f" ]; then
        printf "${RED}❌ Critical file $f is empty after download.${NC}\n"
        exit 1
    fi
done

# Optional maintenance script check
if [ -f "$MAINTAIN_PATH" ] && [ ! -s "$MAINTAIN_PATH" ]; then
    printf "${YELLOW}⚠️  Maintenance script is empty, ignoring...${NC}\n"
    rm -f "$MAINTAIN_PATH"
fi

# 6. Set Permissions
chmod 755 "$INSTALL_PATH"

# 6. Completion
printf "${GREEN}✅ Installation successful!${NC}\n"
echo "Run the script with:"
printf "   ${GREEN}$InstallName${NC}\n"
echo "Maintenance script: $MAINTAIN_PATH"
echo "Library path: $LIB_PATH"
