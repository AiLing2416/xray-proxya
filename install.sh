#!/bin/bash

# ==================================================
# Xray-Proxya Bootstrap Installer
# ==================================================

# Github 链接 (请在部署前修改此处为你实际的仓库地址)
REMOTE_SCRIPT_URL="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/main.sh"

# 目标安装路径
INSTALL_PATH="/usr/local/bin/xray-proxya"

# 颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# 1. Root 检查
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}❌ 错误: 请以 root 权限运行安装脚本。${NC}"
  exit 1
fi

echo -e "🧹 正在准备环境..."

# 2. 清理旧版文件或目录冲突 (解决 Error 23)
if [ -d "$INSTALL_PATH" ]; then
    echo -e "⚠️  检测到旧版目录，正在清理..."
    systemctl stop xray-proxya 2>/dev/null
    rm -rf "$INSTALL_PATH"
elif [ -f "$INSTALL_PATH" ]; then
    rm -f "$INSTALL_PATH"
fi

echo -e "⬇️  正在下载管理脚本..."

# 3. 下载脚本
curl -sSL -o "$INSTALL_PATH" "$REMOTE_SCRIPT_URL"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 下载失败，请检查网络。${NC}"
    exit 1
fi

# 4. 赋予执行权限 (700)
chmod 700 "$INSTALL_PATH"

echo -e "${GREEN}✅ 安装成功！${NC}"
echo -e "使用方法：在任意位置输入 ${GREEN}xray-proxya${NC} 即可管理服务。"
echo -e ""
