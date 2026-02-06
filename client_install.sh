#!/bin/bash
# Xray-Proxya Client Installer (proxya)
# Installs client.sh as /usr/local/bin/proxya

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

REMOTE_SCRIPT_URL="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/client.sh"

echo -e "${BLUE}=== 安装 Xray-Proxya Client (proxya) ===${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请以 root 权限运行${NC}"
    exit 1
fi

DEST_DIR="/usr/local/bin"
DEST_FILE="$DEST_DIR/proxya"
SOURCE_SCRIPT="client.sh"

# 检查当前目录下是否有 client.sh
# 检查当前目录下是否有 client.sh
if [ ! -f "$SOURCE_SCRIPT" ]; then
    echo -e "${BLUE}本地未找到 $SOURCE_SCRIPT，尝试从远程下载...${NC}"
    curl -sSfL -o "$SOURCE_SCRIPT" "$REMOTE_SCRIPT_URL"
    if [ $? -ne 0 ]; then
        echo -e "${RED}错误: 下载失败${NC}"
        exit 1
    fi
fi

echo -e "${BLUE}正在安装 proxya 到 $DEST_FILE ...${NC}"

cp "$SOURCE_SCRIPT" "$DEST_FILE"
chmod +x "$DEST_FILE"

echo -e "${GREEN}✅ 安装成功!${NC}"
echo -e "您现在可以在终端直接输入 ${GREEN}proxya${NC} 来启动客户端管理菜单。"
echo ""
echo "首次运行建议执行: proxya -> 1. 安装 / 重置"
