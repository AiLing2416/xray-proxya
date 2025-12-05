#!/bin/sh

# ==================================================
# Xray-Proxya Installer (Alpine & Debian Universal)
# ==================================================

REMOTE_SCRIPT_URL="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/test-main.sh"

INSTALL_DIR="/usr/local/sbin"
INSTALL_FILENAME="xray-proxya"
INSTALL_PATH="$INSTALL_DIR/$INSTALL_FILENAME"

# 颜色定义 (兼容 sh)
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# 1. Root 权限检查
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root."
    exit 1
fi

echo "⚙️  Checking environment..."

# 2. 依赖安装 (针对 Alpine 和 Debian)
if [ -f /etc/alpine-release ]; then
    # Alpine Linux: 安装 bash (主脚本需要) 和 curl
    echo "📦 Detected Alpine Linux. Installing dependencies (bash, curl)..."
    apk add --no-cache bash curl >/dev/null 2>&1
elif [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    apt-get update -qq >/dev/null
    apt-get install -y curl >/dev/null 2>&1
fi

# 3. 确保目录存在 (Alpine 极简版可能缺少 sbin)
if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR"
fi

# 4. 清理旧文件并下载
# 强制删除可能存在的同名文件，防止 curl 写入错误
rm -f "$INSTALL_PATH"

echo "⬇️  Downloading manager script..."
curl -sSL -o "$INSTALL_PATH" "$REMOTE_SCRIPT_URL"

if [ $? -ne 0 ]; then
    echo "${RED}❌ Download failed! Please check your network or URL.${NC}"
    exit 1
fi

# 5. 设置权限
# 755 允许 root/sudo 运行及补全
chmod 755 "$INSTALL_PATH"

echo "${GREEN}✅ Installation successful!${NC}"
echo "You can now run the script with:"
echo "   ${GREEN}xray-proxya${NC}   (as root)"
echo "   ${GREEN}sudo xray-proxya${NC} (if using sudo)"
