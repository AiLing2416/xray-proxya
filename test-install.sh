#!/bin/bash

# ==================================================
# Xray-Proxya Bootstrap
# ==================================================

REMOTE_SCRIPT_URL="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/test-main.sh"
INSTALL_PATH="/usr/sbin/xray-proxya"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}❌ 错误: 需要 root 权限${NC}"
  exit 1
fi

if [ -d "$INSTALL_PATH" ]; then
    systemctl stop xray-proxya 2>/dev/null
    rm -rf "$INSTALL_PATH"
elif [ -f "$INSTALL_PATH" ]; then
    rm -f "$INSTALL_PATH"
fi

rm -rf /usr/local/bin/xray-proxya
echo -e "⬇️  下载脚本..."
curl -sSL -o "$INSTALL_PATH" "$REMOTE_SCRIPT_URL"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 下载失败${NC}"
    exit 1
fi

chmod 755 "$INSTALL_PATH"

echo -e "${GREEN}✅ 安装成功${NC}"
echo -e "请运行: ${GREEN}xray-proxya${NC}"
