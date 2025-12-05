#!/bin/sh

# ==================================================
# Xray-Proxya Installer (Universal)
# ==================================================

# 请修改此处为您实际的仓库链接
REMOTE_SCRIPT_URL="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/main.sh"

INSTALL_DIR="/usr/local/sbin"
INSTALL_FILENAME="xray-proxya"
INSTALL_PATH="$INSTALL_DIR/$INSTALL_FILENAME"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
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
    apt-get update -qq >/dev/null
    apt-get install -y curl >/dev/null 2>&1
fi

# 3. 确保目录存在
if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR"
fi

# 4. 清理与下载
rm -f "$INSTALL_PATH"

echo "⬇️  Downloading manager script..."
curl -sSL -o "$INSTALL_PATH" "$REMOTE_SCRIPT_URL"

if [ $? -ne 0 ]; then
    printf "${RED}❌ Download failed! Please check your network or URL.${NC}\n"
    exit 1
fi

# 5. 设置权限
chmod 755 "$INSTALL_PATH"

# 6. 完成提示 (使用 printf 修复显示问题)
printf "${GREEN}✅ Installation successful!${NC}\n"
echo "You can now run the script with:"
printf "   ${GREEN}xray-proxya${NC}   (as root)\n"
printf "   ${GREEN}sudo xray-proxya${NC} (if using sudo)\n"
