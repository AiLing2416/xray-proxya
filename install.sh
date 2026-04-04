#!/bin/bash

# Xray-Proxya One-Click Installer
# Repository: https://github.com/AiLing2416/xray-proxya
# Supports x86_64 and arm64

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}🚀 Starting Xray-Proxya Installation...${NC}"

# 1. Detect Architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64) BIN_ARCH="linux-amd64" ;;
    aarch64|arm64) BIN_ARCH="linux-arm64" ;;
    *) echo -e "${RED}❌ Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

# 2. Download Binary (Assuming GitHub Release structure)
# Note: For development, we copy from current build. 
# In production, replace this with: curl -Ls ...
if [ -f "./build/xray-proxya-$BIN_ARCH" ]; then
    cp "./build/xray-proxya-$BIN_ARCH" "$INSTALL_DIR/xray-proxya"
else
    # Fallback to current system build if specifically run in repo
    CGO_ENABLED=0 go build -o "$INSTALL_DIR/xray-proxya" ./cmd/xray-proxya/
fi

chmod +x "$INSTALL_DIR/xray-proxya"

# 3. Add to PATH if not present
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "export PATH=\$PATH:$INSTALL_DIR" >> "$HOME/.bashrc"
    echo -e "${GREEN}✅ Added $INSTALL_DIR to PATH. Please run 'source ~/.bashrc' or restart shell.${NC}"
fi

# 4. Success message
echo -e "${GREEN}✅ Xray-Proxya installed successfully!${NC}"
echo -e "Next steps:"
echo -e "  1. Run '${GREEN}xray-proxya init --role server${NC}' (for distribution server)"
echo -e "  2. Run '${GREEN}xray-proxya init --role gateway${NC}' (for transparent proxy)"
echo -e "  3. Run '${GREEN}xray-proxya help${NC}' to explore more commands."
