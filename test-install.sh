#!/bin/bash

# ==================================================
# Xray-Proxya Bootstrap (Beta)
# ==================================================

REMOTE_SCRIPT_URL="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/test-main.sh"
INSTALL_PATH="/usr/local/sbin/xray-proxya" # 使用 sbin
OLD_PATH="/usr/local/bin/xray-proxya"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

[[ "$EUID" -ne 0 ]] && echo -e "${RED}❌ Root required${NC}" && exit 1

# 清理
[[ -f "$OLD_PATH" ]] && rm -f "$OLD_PATH"
if [[ -d "$INSTALL_PATH" ]] || [[ -f "$INSTALL_PATH" ]]; then
    systemctl stop xray-proxya 2>/dev/null
    rm -rf "$INSTALL_PATH"
fi

echo -e "⬇️  下载管理脚本..."
# 增加重试机制
if ! curl -sSL -o "$INSTALL_PATH" "$REMOTE_SCRIPT_URL"; then
    echo -e "${RED}❌ 下载失败${NC}"
    exit 1
fi

chmod 755 "$INSTALL_PATH" # 允许 sudo 补全发现

echo -e "${GREEN}✅ 安装成功 (BETA)${NC}"
echo -e "运行: ${GREEN}sudo xray-proxya${NC}"
