#!/bin/bash

# Xray-Proxya Local Build Helper

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

TARGET="${1:-full}"

echo -e "${GREEN}🛠️ Starting Xray-Proxya local build (target: ${TARGET})...${NC}"

# 1. Environment Detection
if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go compiler not found. Please install Go 1.25 or later.${NC}"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo -e "📦 Detected Go version: $GO_VERSION"

mkdir -p build

case "$TARGET" in
    slim)
        echo -e "🚀 Building statically linked Slim binary (-trimpath -tags slim)..."
        CGO_ENABLED=0 go build -trimpath -tags slim -ldflags "-s -w" -o build/xray-proxya-slim ./cmd/xray-proxya/
        CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o build/pathd ./cmd/xray-proxya-pathd/
        echo -e "${GREEN}✅ Build successful: build/xray-proxya-slim and build/pathd${NC}"
        ls -lh build/xray-proxya-slim build/pathd
        echo ""
        build/xray-proxya-slim version
        ;;
    all)
        echo -e "🚀 Building statically linked Full binary (-trimpath)..."
        CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o build/xray-proxya ./cmd/xray-proxya/
        echo -e "🚀 Building statically linked Slim binary (-trimpath -tags slim)..."
        CGO_ENABLED=0 go build -trimpath -tags slim -ldflags "-s -w" -o build/xray-proxya-slim ./cmd/xray-proxya/
        CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o build/pathd ./cmd/xray-proxya-pathd/
        echo -e "${GREEN}✅ Build successful: build/xray-proxya, build/xray-proxya-slim, and build/pathd${NC}"
        ls -lh build/xray-proxya build/xray-proxya-slim build/pathd
        echo ""
        build/xray-proxya version
        echo ""
        build/xray-proxya-slim version
        ;;
    full|default|*)
        echo -e "🚀 Building statically linked binary (-trimpath)..."
        CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o build/xray-proxya ./cmd/xray-proxya/
        CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o build/pathd ./cmd/xray-proxya-pathd/
        echo -e "${GREEN}✅ Build successful: build/xray-proxya and build/pathd${NC}"
        ls -lh build/xray-proxya build/pathd
        echo ""
        build/xray-proxya version
        ;;
esac
