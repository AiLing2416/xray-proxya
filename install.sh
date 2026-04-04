#!/bin/bash

# Xray-Proxya One-Click Installer
# Repository: https://github.com/AiLing2416/xray-proxya

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${GREEN}🚀 Starting Xray-Proxya Installation...${NC}"

# 1. Detect Architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64) BIN_ARCH="amd64" ;;
    aarch64|arm64) BIN_ARCH="arm64" ;;
    *) echo -e "${RED}❌ Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

# 2. Download Binary from GitHub Releases
REPO="AiLing2416/xray-proxya"
URL="https://github.com/$REPO/releases/latest/download/xray-proxya-linux-$BIN_ARCH"

echo -e "⬇️  Downloading latest binary for ${YELLOW}$BIN_ARCH${NC}..."
curl -Ls "$URL" -o "$INSTALL_DIR/xray-proxya"

if [ ! -f "$INSTALL_DIR/xray-proxya" ] || [ ! -s "$INSTALL_DIR/xray-proxya" ]; then
    echo -e "${RED}❌ Download failed. Please check your network or the repository status.${NC}"
    exit 1
fi

chmod +x "$INSTALL_DIR/xray-proxya"
echo -e "${GREEN}✅ Binary installed to: $INSTALL_DIR/xray-proxya${NC}"

# 3. Add to PATH if not present
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    SHELL_NAME=$(basename "$SHELL")
    RC_FILE="$HOME/.bashrc"
    [ "$SHELL_NAME" == "zsh" ] && RC_FILE="$HOME/.zshrc"
    
    echo "export PATH=\$PATH:$INSTALL_DIR" >> "$RC_FILE"
    echo -e "${GREEN}✅ Added $INSTALL_DIR to PATH in $RC_FILE${NC}"
    echo -e "${YELLOW}👉 Please run 'source $RC_FILE' or restart your shell.${NC}"
fi

# 4. Success message
echo -e "\n${GREEN}✨ Xray-Proxya is ready!${NC}"
echo -e "Next steps:"
echo -e "  1. Run '${GREEN}xray-proxya init --role server${NC}' (as distribution server)"
echo -e "  2. Run '${GREEN}xray-proxya init --role gateway${NC}' (as transparent gateway)"
echo -e "  3. Run '${GREEN}xray-proxya completion install${NC}' for auto-completion."
