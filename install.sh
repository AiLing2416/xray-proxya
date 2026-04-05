#!/bin/bash

# Xray-Proxya One-Click Installer
# Repository: https://github.com/AiLing2416/xray-proxya

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${GREEN}🚀 Starting Xray-Proxya Installation...${NC}"

# 1. Unlock Binaries (Release file locks by killing running processes)
echo -e "🔓 Releasing file locks..."
pkill -9 xray-proxya || true
pkill -9 xray || true

# 2. Detect Architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64) BIN_ARCH="amd64" ;;
    aarch64|arm64) BIN_ARCH="arm64" ;;
    *) echo -e "${RED}❌ Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

INSTALL_DIR="$HOME/.local/bin"
[ "$(id -u)" -eq 0 ] && INSTALL_DIR="/root/.local/bin"
mkdir -p "$INSTALL_DIR"

SHARE_BIN_DIR="$HOME/.local/share/xray-proxya/bin"
[ "$(id -u)" -eq 0 ] && SHARE_BIN_DIR="/root/.local/share/xray-proxya/bin"

# 3. Migration Logic: Detect and move legacy Xray core
OLD_CORE="$INSTALL_DIR/xray"
if [ -f "$OLD_CORE" ]; then
    echo -e "📦 Found legacy Xray core at $OLD_CORE. Moving to private bin..."
    mkdir -p "$SHARE_BIN_DIR"
    mv "$OLD_CORE" "$SHARE_BIN_DIR/xray"
fi

# 4. Download Latest xray-proxya
REPO="AiLing2416/xray-proxya"
URL="https://github.com/$REPO/releases/latest/download/xray-proxya-linux-$BIN_ARCH"

echo -e "⬇️  Downloading latest binary for ${YELLOW}$BIN_ARCH${NC}..."
curl -Ls "$URL" -o "$INSTALL_DIR/xray-proxya"

if [ ! -f "$INSTALL_DIR/xray-proxya" ] || [ ! -s "$INSTALL_DIR/xray-proxya" ]; then
    echo -e "${RED}❌ Download failed. Please check your network.${NC}"
    exit 1
fi

chmod +x "$INSTALL_DIR/xray-proxya"
echo -e "${GREEN}✅ xray-proxya installed to: $INSTALL_DIR/xray-proxya${NC}"

# 5. Path cleanup (ensure Xray core is not in PATH)
if [ -f "$INSTALL_DIR/xray" ]; then
    rm -f "$INSTALL_DIR/xray"
fi

# 6. Add to PATH if not present
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    SHELL_NAME=$(basename "$SHELL")
    RC_FILE="$HOME/.bashrc"
    [ "$SHELL_NAME" == "zsh" ] && RC_FILE="$HOME/.zshrc"
    [ "$(id -u)" -eq 0 ] && RC_FILE="/root/.bashrc"
    
    echo "export PATH=\$PATH:$INSTALL_DIR" >> "$RC_FILE"
    echo -e "${GREEN}✅ Added $INSTALL_DIR to PATH in $RC_FILE${NC}"
fi

echo -e "\n${GREEN}✨ Installation successful!${NC}"
echo -e "Xray Core is now isolated at: ${YELLOW}$SHARE_BIN_DIR/xray${NC}"
echo -e "Run '${GREEN}xray-proxya init${NC}' to get started."
