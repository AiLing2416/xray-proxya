#!/bin/bash

# ==================================================
# Xray-Proxya Bootstrap Installer
# ==================================================

# Github 链接 (请在部署前修改此处为你实际的仓库地址)
REMOTE_SCRIPT_URL="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/main.sh"

INSTALL_PATH="/usr/local/bin/xray-proxya"

# 颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}❌ 错误: 请以 root 权限运行安装脚本。${NC}"
  exit 1
fi

echo -e "⬇️  正在下载管理脚本..."
curl -L -o "$INSTALL_PATH" "$REMOTE_SCRIPT_URL"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 下载失败，请检查网络连接或 Github 链接。${NC}"
    exit 1
fi

# 设置仅 Root 可执行权限 (700)
chmod 700 "$INSTALL_PATH"

echo -e "${GREEN}✅ 安装成功！${NC}"
echo -e "现在，您可以在任意位置输入以下命令来管理服务："
echo -e ""
echo -e "   ${GREEN}xray-proxya${NC}"
echo -e ""
