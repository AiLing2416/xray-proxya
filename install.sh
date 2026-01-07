#!/bin/sh

# ==================================================
# Xray-Proxya Installer (Universal)
# ==================================================

REMOTE_SCRIPT_URL="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/main.sh"
REMOTE_MAINTAIN_URL="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/maintain.sh"

INSTALL_DIR="/usr/local/sbin"
INSTALL_FILENAME="xray-proxya"
INSTALL_PATH="$INSTALL_DIR/$INSTALL_FILENAME"

MAINTAIN_DIR="/usr/local/bin"
MAINTAIN_FILENAME="xray-proxya-maintenance"
MAINTAIN_PATH="$MAINTAIN_DIR/$MAINTAIN_FILENAME"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$(id -u)" -ne 0 ]; then
    printf "${RED}Error: This script must be run as root.${NC}\n"
    exit 1
fi

echo "⚙️  Checking environment..."

if [ -f /etc/alpine-release ]; then
    # Alpine Linux
    echo "📦 Detected Alpine Linux. Installing dependencies (bash, curl)..."
    apk add --no-cache bash curl >/dev/null 2>&1
elif [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    apt-get update -qq >/dev/null
    apt-get install -y curl >/dev/null 2>&1
fi

[ ! -d "$INSTALL_DIR" ] && mkdir -p "$INSTALL_DIR"
[ ! -d "$MAINTAIN_DIR" ] && mkdir -p "$MAINTAIN_DIR"

echo "⬇️  Downloading manager script..."
curl -sSL -o "$INSTALL_PATH" "$REMOTE_SCRIPT_URL"
if [ $? -ne 0 ]; then
    printf "${RED}❌ Download main script failed!${NC}\n"
    exit 1
fi

echo "⬇️  Downloading maintenance script..."
curl -sSL -o "$MAINTAIN_PATH" "$REMOTE_MAINTAIN_URL"
if [ $? -ne 0 ]; then
    printf "${YELLOW}⚠️  Download maintenance script failed, skipping...${NC}\n"
else
    chmod 755 "$MAINTAIN_PATH"
fi

chmod 755 "$INSTALL_PATH"

printf "${GREEN}✅ Installation successful!${NC}\n"
echo "You can now run the script with:"
printf "   ${GREEN}xray-proxya${NC}   (as root)\n"
printf "   ${GREEN}sudo xray-proxya${NC} (if using sudo)\n"
echo "Maintenance script installed to: $MAINTAIN_PATH"

