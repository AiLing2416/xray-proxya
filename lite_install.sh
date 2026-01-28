#!/bin/sh

# ==================================================
# Xray-Proxya Lite Installer (Universal)
# ==================================================

REMOTE_SCRIPT_URL="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/lite.sh"
REMOTE_MAINTAIN_URL="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/maintain.sh"
REMOTE_LIB_URL="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/lib.sh"

INSTALL_DIR="/usr/local/sbin"
INSTALL_FILENAME="xray-proxya"
INSTALL_PATH="$INSTALL_DIR/$INSTALL_FILENAME"

MAINTAIN_DIR="/usr/local/bin"
MAINTAIN_FILENAME="xray-proxya-maintenance"
MAINTAIN_PATH="$MAINTAIN_DIR/$MAINTAIN_FILENAME"

LIB_PATH="$LIB_DIR/lib.sh"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# 1. Root 权限检查
if [ "$(id -u)" -ne 0 ]; then
    printf "${RED}Error: This script must be run as root.${NC}\n"
    exit 1
fi

echo "⚙️  Checking environment..."

# 2. 依赖安装
if [ -f /etc/alpine-release ]; then
    # Alpine Linux
    echo "📦 Detected Alpine Linux. Installing dependencies (bash, curl)..."
    apk add --no-cache bash curl >/dev/null 2>&1
elif [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y curl >/dev/null 2>&1
fi

# 3. 确保目录存在
[ ! -d "$INSTALL_DIR" ] && mkdir -p "$INSTALL_DIR"
[ ! -d "$MAINTAIN_DIR" ] && mkdir -p "$MAINTAIN_DIR"
[ ! -d "$LIB_DIR" ] && mkdir -p "$LIB_DIR"

# 4. 清理与下载
echo "⬇️  Downloading manager script (Lite)..."
# 清理旧库文件 (兼容性迁移)
[ -f "/opt/xray-proxya/main_lib.sh" ] && rm -f "/opt/xray-proxya/main_lib.sh" && echo "🧹 Removed legacy main_lib.sh"
curl -sSfL -o "$INSTALL_PATH" "$REMOTE_SCRIPT_URL"
if [ $? -ne 0 ]; then
    printf "${RED}❌ Download lite script failed!${NC}\n"
    exit 1
fi

echo "⬇️  Downloading maintenance script..."
curl -sSfL -o "$MAINTAIN_PATH" "$REMOTE_MAINTAIN_URL"
if [ $? -ne 0 ]; then
    printf "${YELLOW}⚠️  Download maintenance script failed, skipping...${NC}\n"
else
    chmod 755 "$MAINTAIN_PATH"
fi

echo "⬇️  Downloading library..."
curl -sSfL -o "$LIB_PATH" "$REMOTE_LIB_URL"
if [ $? -ne 0 ]; then
    printf "${YELLOW}⚠️  Download library failed, automated updates might not work.${NC}\n"
else
    chmod 644 "$LIB_PATH"
fi

# 5. 设置权限
chmod 755 "$INSTALL_PATH"

# 6. 完成提示
printf "${GREEN}✅ Lite Installation successful!${NC}\n"
echo "You can now run the script with:"
printf "   ${GREEN}$INSTALL_FILENAME${NC}   (as root)\n"
echo "Maintenance script: $MAINTAIN_PATH"
echo "Library path: $LIB_PATH"
