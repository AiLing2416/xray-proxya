#!/bin/bash
# Xray-Proxya Client Installer (proxya)
# Installs client.sh as /usr/local/bin/proxya

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=== 安装 Xray-Proxya Client (proxya) ===${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请以 root 权限运行${NC}"
    exit 1
fi

DEST_DIR="/usr/local/bin"
DEST_FILE="$DEST_DIR/proxya"
SOURCE_SCRIPT="client.sh"

# 检查当前目录下是否有 client.sh
if [ ! -f "$SOURCE_SCRIPT" ]; then
    # 如果不存在，尝试从 GitHub 下载 (假设仓库结构)
    # 这里假设安装脚本通常与 client.sh 一起分发，或者从 git 仓库运行
    # 如果是独立运行，可能需要 curl 下载
    echo -e "${RED}错误: 未找到 $SOURCE_SCRIPT${NC}"
    echo "请确保 client.sh 与安装脚本在同一目录下"
    exit 1
fi

echo -e "${BLUE}正在安装 proxya 到 $DEST_FILE ...${NC}"

cp "$SOURCE_SCRIPT" "$DEST_FILE"
chmod +x "$DEST_FILE"

echo -e "${GREEN}✅ 安装成功!${NC}"
echo -e "您现在可以在终端直接输入 ${GREEN}proxya${NC} 来启动客户端管理菜单。"
echo ""
echo "首次运行建议执行: proxya -> 1. 安装 / 重置"
