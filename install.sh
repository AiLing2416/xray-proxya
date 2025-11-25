#!/bin/bash

# ==================================================
# Xray-Proxya Bootstrap Installer
# ==================================================

# Github 链接 (请在部署前修改此处为你实际的仓库地址)
REMOTE_SCRIPT_URL="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/main.sh"

# 目标安装路径 (脚本文件)
INSTALL_PATH="/usr/local/bin/xray-proxya"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# 1. 检查 Root 权限
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}❌ 错误: 请以 root 权限运行安装脚本。${NC}"
  exit 1
fi

echo -e "🧹 正在清理旧版本残留..."

# 2. 关键修复: 如果存在同名文件夹(旧版残留)或文件，强制删除
if [ -d "$INSTALL_PATH" ]; then
    echo -e "⚠️  检测到旧版目录冲突，正在移除: $INSTALL_PATH"
    # 停止旧服务以防止文件被占用
    systemctl stop xray-proxya 2>/dev/null
    rm -rf "$INSTALL_PATH"
elif [ -f "$INSTALL_PATH" ]; then
    rm -f "$INSTALL_PATH"
fi

echo -e "⬇️  正在下载管理脚本..."

# 3. 下载脚本
curl -sSL -o "$INSTALL_PATH" "$REMOTE_SCRIPT_URL"

# 检查 curl 是否执行成功
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 下载失败 (curl error $?)。请检查网络或 URL 是否正确。${NC}"
    exit 1
fi

# 4. 赋予执行权限 (700 = 仅 root 可读写执行)
chmod 700 "$INSTALL_PATH"

# 5. 完成提示
echo -e "${GREEN}✅ 安装成功！${NC}"
echo -e "现在，您可以在任意位置输入以下命令来管理服务："
echo -e ""
echo -e "   ${GREEN}xray-proxya${NC}"
echo -e ""
