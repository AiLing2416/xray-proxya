#!/bin/bash

# ==================================================
# Xray-Proxya Manager Script v2.0
# Supports: VMess-WS | VLESS-XHTTP-ENC | Shadowsocks
# ==================================================

# --- 配置与全局变量 ---
CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
XRAY_BIN="/usr/local/bin/xray-proxya-core/xray"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
JSON_FILE="$XRAY_DIR/config.json"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 权限检查
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}❌ 错误: 此脚本必须以 root 用户运行。${NC}"
        exit 1
    fi
}

# 依赖安装
install_deps() {
    echo -e "${BLUE}📦 正在检查并安装依赖 (curl, jq, openssl)...${NC}"
    apt-get update -qq >/dev/null
    apt-get install -y curl jq unzip openssl >/dev/null 2>&1
}

# 辅助函数: 生成指定长度的随机字符串 (字母+数字)
generate_random() {
    local length=$1
    openssl rand -base64 $((length * 2)) | tr -dc 'a-zA-Z0-9' | head -c $length
}

# 状态检查
check_status() {
    if systemctl is-active --quiet xray-proxya; then
        echo -e "🟢 服务状态: ${GREEN}运行中${NC}"
        echo -e "⏱️  运行时间: $(systemctl status xray-proxya | grep Active | awk '{print $5, $6, $7, $8, $9}')"
    else
        echo -e "🔴 服务状态: ${RED}未运行${NC}"
    fi
    
    if [ -f "$CONF_FILE" ]; then
        source "$CONF_FILE"
        echo -e "🔌 当前端口: VMess [${YELLOW}$PORT_VMESS${NC}] | VLESS [${YELLOW}$PORT_VLESS${NC}] | SS [${YELLOW}$PORT_SS${NC}]"
    else
        echo -e "⚪ 配置状态: 未检测到配置文件"
    fi
}

# 获取 Xray 核心
download_core() {
    echo -e "${BLUE}⬇️  正在获取最新 Xray-core 版本信息...${NC}"
    LATEST_URL=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
    
    if [ -z "$LATEST_URL" ]; then
        echo -e "${RED}❌ 错误: 无法获取下载链接。${NC}"
        return 1
    fi

    echo -e "${BLUE}🚀 下载并安装 Xray...${NC}"
    systemctl stop xray-proxya 2>/dev/null
    mkdir -p "$XRAY_DIR"
    curl -L -o /tmp/xray.zip "$LATEST_URL"
    unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
    rm /tmp/xray.zip
    chmod +x "$XRAY_BIN"
    
    VER=$("$XRAY_BIN" version | head -n 1 | awk '{print $2}')
    echo -e "${GREEN}✅ Xray Core 安装完成 (版本: $VER)${NC}"
}

# 生成配置文件 (VMess + VLESS + Shadowsocks)
generate_config() {
    local vmess_p=$1
    local vless_p=$2
    local ss_p=$3
    local uuid=$4
    local vmess_path=$5
    local vless_path=$6
    local enc_key=$7
    local dec_key=$8
    local ss_pass=$9

    cat > "$JSON_FILE" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vmess-in",
      "port": $vmess_p,
      "protocol": "vmess",
      "settings": { "clients": [ { "id": "$uuid", "level": 0 } ] },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "$vmess_path" } }
    },
    {
      "tag": "vless-enc-in",
      "port": $vless_p,
      "protocol": "vless",
      "settings": { "clients": [ { "id": "$uuid", "level": 0 } ], "decryption": "$dec_key" },
      "streamSettings": { "network": "xhttp", "xhttpSettings": { "path": "$vless_path" } }
    },
    {
      "tag": "shadowsocks-in",
      "port": $ss_p,
      "protocol": "shadowsocks",
      "settings": {
        "method": "chacha20-poly1305",
        "password": "$ss_pass",
        "network": "tcp,udp"
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom" } ]
}
EOF
}

# 生成 Systemd 服务
create_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Xray-Proxya Service
After=network.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$XRAY_BIN run -c $JSON_FILE
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xray-proxya >/dev/null 2>&1
    systemctl restart xray-proxya
}

# 核心安装流程
install_xray() {
    echo -e "=================================================="
    echo -e "   开始安装 / 重装 Xray-Proxya"
    echo -e "=================================================="
    
    # 端口输入 (支持环境变量默认值)
    # vmessp, vlessp, ssocks
    read -p "请输入 VMess 端口 (默认: ${vmessp:-8081}): " port_vm
    read -p "请输入 VLESS 端口 (默认: ${vlessp:-8082}): " port_vl
    read -p "请输入 SS 端口    (默认: ${ssocks:-8083}): " port_ss
    
    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}

    # 占用检查
    for p in $PORT_VMESS $PORT_VLESS $PORT_SS; do
        if ss -lnt | grep -q ":$p "; then 
            echo -e "${RED}⚠️  端口 $p 已被占用，请更换。${NC}"
            return
        fi
    done

    install_deps
    download_core

    # 生成密钥与密码 (长度升级至 24)
    echo -e "${BLUE}🔑 生成高强度凭证...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    
    # 路径使用 hex (24字符 = 12 bytes)
    PATH_VM="/$(openssl rand -hex 12)"
    PATH_VL="/$(openssl rand -hex 12)"
    
    # SS 密码使用 base64 字符集 (24字符)
    PASS_SS=$(generate_random 24)
    
    # ML-KEM Key Gen (Fix for v25.10+)
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"decryption":' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"encryption":' | cut -d '"' -f 4)

    if [ -z "$DEC_KEY" ]; then
        echo -e "${RED}❌ ML-KEM 密钥生成失败。${NC}"
        return 1
    fi

    # 保存环境配置
    mkdir -p "$CONF_DIR"
    cat > "$CONF_FILE" <<EOF
PORT_VMESS=$PORT_VMESS
PORT_VLESS=$PORT_VLESS
PORT_SS=$PORT_SS
UUID=$UUID
PATH_VM=$PATH_VM
PATH_VL=$PATH_VL
PASS_SS=$PASS_SS
ENC_KEY=$ENC_KEY
DEC_KEY=$DEC_KEY
EOF

    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS"
    create_service

    echo -e "${GREEN}✅ 安装完成！服务已启动。${NC}"
    show_links
}

# 显示链接
show_links() {
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}❌ 未检测到安装配置。请先安装。${NC}"
        return
    fi
    source "$CONF_FILE"
    
    echo -e "${BLUE}🌍 正在获取外部 IP...${NC}"
    PUBLIC_IP=$(curl -s --max-time 3 https://ipconfig.me || curl -s --max-time 3 https://ifconfig.co || echo "YOUR_IP")

    # VMess Link
    VMESS_JSON=$(jq -n \
      --arg add "$PUBLIC_IP" --arg port "$PORT_VMESS" --arg id "$UUID" --arg path "$PATH_VM" \
      '{v:"2", ps:"VMess-ChaCha", add:$add, port:$port, id:$id, aid:"0", scy:"chacha20-poly1305", net:"ws", type:"none", host:"", path:$path, tls:""}')
    VMESS_LINK="vmess://$(echo -n "$VMESS_JSON" | base64 -w 0)"

    # VLESS Link
    VLESS_LINK="vless://$UUID@$PUBLIC_IP:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#VLESS-XHTTP-ENC"

    # Shadowsocks Link (SIP002 standard)
    # Format: ss://base64(method:password)@ip:port#NAME
    SS_AUTH=$(echo -n "chacha20-poly1305:$PASS_SS" | base64 -w 0)
    SS_LINK="ss://$SS_AUTH@$PUBLIC_IP:$PORT_SS#Shadowsocks-Xray"

    echo -e "\n=================================================="
    echo -e "🔑 用户 UUID: ${YELLOW}$UUID${NC}"
    echo -e "🔐 SS 密码:   ${YELLOW}$PASS_SS${NC}"
    echo -e "--------------------------------------------------"
    echo -e "1️⃣  VMess WS (ChaCha20-Poly1305)"
    echo -e "    端口: $PORT_VMESS | 路径: $PATH_VM"
    echo -e "    🔗 ${GREEN}$VMESS_LINK${NC}"
    echo -e "--------------------------------------------------"
    echo -e "2️⃣  VLESS XHTTP (抗量子 ENC - ML-KEM)"
    echo -e "    端口: $PORT_VLESS | 路径: $PATH_VL"
    echo -e "    🔗 ${GREEN}$VLESS_LINK${NC}"
    echo -e "--------------------------------------------------"
    echo -e "3️⃣  Shadowsocks (ChaCha20-Poly1305)"
    echo -e "    端口: $PORT_SS"
    echo -e "    🔗 ${GREEN}$SS_LINK${NC}"
    echo -e "=================================================="
}

# 修改端口
change_ports() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}❌ 未安装。${NC}"; return; fi
    source "$CONF_FILE"
    
    echo -e "当前端口 -> VMess: $PORT_VMESS, VLESS: $PORT_VLESS, SS: $PORT_SS"
    read -p "新 VMess 端口 (留空不改): " new_vm
    read -p "新 VLESS 端口 (留空不改): " new_vl
    read -p "新 SS    端口 (留空不改): " new_ss
    
    # 如果有输入则更新，否则保持原值
    [[ ! -z "$new_vm" ]] && sed -i "s/^PORT_VMESS=.*/PORT_VMESS=$new_vm/" "$CONF_FILE"
    [[ ! -z "$new_vl" ]] && sed -i "s/^PORT_VLESS=.*/PORT_VLESS=$new_vl/" "$CONF_FILE"
    [[ ! -z "$new_ss" ]] && sed -i "s/^PORT_SS=.*/PORT_SS=$new_ss/" "$CONF_FILE"
    
    source "$CONF_FILE"
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS"
    restart_service
}

# 重启服务
restart_service() {
    echo -e "${BLUE}🔄 正在重启服务...${NC}"
    systemctl restart xray-proxya
    sleep 1
    if systemctl is-active --quiet xray-proxya; then
        echo -e "${GREEN}✅ 服务重启成功。${NC}"
    else
        echo -e "${RED}❌ 服务启动失败，请检查端口占用或日志。${NC}"
        echo -e "查看日志命令: journalctl -u xray-proxya -e --no-pager"
    fi
}

# 卸载
uninstall_xray() {
    echo -e "${YELLOW}⚠️  警告: 这将完全删除 Xray-Proxya 服务和配置。${NC}"
    read -p "确定要继续吗? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi

    systemctl stop xray-proxya
    systemctl disable xray-proxya
    rm "$SERVICE_FILE"
    rm -rf "$XRAY_DIR"
    rm -rf "$CONF_DIR"
    systemctl daemon-reload
    
    echo -e "${GREEN}✅ 卸载完成。${NC}"
}

# --- 主菜单 ---
check_root

echo -e "${BLUE}Xray-Proxya 管理脚本 v2.0${NC}"
check_status
echo -e ""
echo -e "1. 安装 / 重置 Xray"
echo -e "2. 查看链接 (VMess/VLESS/SS)"
echo -e "3. 修改端口"
echo -e "4. 卸载 Xray"
echo -e "5. 重启服务 (排除故障)"
echo -e "0. 退出"
echo -e ""
read -p "请选择 [0-5]: " choice

case "$choice" in
    1) install_xray ;;
    2) show_links ;;
    3) change_ports ;;
    4) uninstall_xray ;;
    5) restart_service ;;
    0) exit 0 ;;
    *) echo -e "${RED}无效选项${NC}" ;;
esac
