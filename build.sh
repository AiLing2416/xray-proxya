#!/bin/bash

# Xray-Proxya Local Build Helper

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🛠️ Starting Xray-Proxya local build...${NC}"

# 1. Environment Detection
if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go compiler not found. Please install Go 1.25 or later.${NC}"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo -e "📦 Detected Go version: $GO_VERSION"

# 2. Perform Build
echo -e "🚀 Building statically linked binary..."
mkdir -p build
CGO_ENABLED=0 go build -ldflags "-s -w" -o build/xray-proxya ./cmd/xray-proxya/

# 3. Verify
if [ -f "build/xray-proxya" ]; then
    echo -e "${GREEN}✅ Build successful: build/xray-proxya${NC}"
    build/xray-proxya version
else
    echo -e "${RED}❌ Build failed.${NC}"
    exit 1
fi
