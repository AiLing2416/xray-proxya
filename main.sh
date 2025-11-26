#!/bin/bash

# ==================================================
# Xray-Proxya Manager
# ==================================================

# --- 用户可配置变量 ---
VMESS_CIPHER="chacha20-poly1305"
SS_CIPHER="aes-256-gcm"
# -----------------------------------------------

CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
XRAY_BIN="/usr/local/bin/xray-proxya-core/xray"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
JSON_FILE="$XRAY_DIR/config.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}❌ 错误: 需要 root 权限${NC}"
        exit 1
    fi
}

install_deps() {
    echo -e "${BLUE}📦 安装依赖...${NC}"
    apt-get update -qq >/dev/null
    apt-get install -y curl jq unzip openssl >/dev/null 2>&1
}

generate_random() {
    local length=$1
    openssl rand -base64 $((length * 2)) | tr -dc 'a-zA-Z0-9' | head -c $length
}

check_status() {
    if systemctl is-active --quiet xray-proxya; then
        echo -e "🟢 服务状态: ${GREEN}运行中${NC}"
    else
        echo -e "🔴 服务状态: ${RED}未运行${NC}"
    fi
}

download_core() {
    echo -e "${BLUE}⬇️  获取 Xray-core...${NC}"
    LATEST_URL=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
    
    if [ -z "$LATEST_URL" ]; then
        echo -e "${RED}❌ 下载链接获取失败${NC}"
        return 1
    fi

    systemctl stop xray-proxya 2>/dev/null
    mkdir -p "$XRAY_DIR"
    curl -L -o /tmp/xray.zip "$LATEST_URL"
    unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
    rm /tmp/xray.zip
    chmod +x "$XRAY_BIN"
}

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
    local ss_method=${10} # 第10个参数

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
        "method": "$ss_method",
        "password": "$ss_pass",
        "network": "tcp,udp"
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom" } ]
}
EOF
}

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

install_xray() {
    echo -e "=== 安装向导 ==="
    echo -e "加密配置: VMess [${YELLOW}$VMESS_CIPHER${NC}] | SS [${YELLOW}$SS_CIPHER${NC}]"
    
    read -p "VMess 端口 (默认 ${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (默认 ${vlessp:-8082}): " port_vl
    read -p "SS    端口 (默认 ${ssocks:-8083}): " port_ss
    
    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}

    for p in $PORT_VMESS $PORT_VLESS $PORT_SS; do
        if ss -lnt | grep -q ":$p "; then 
            echo -e "${RED}⚠️  端口 $p 被占用${NC}"
            return
        fi
    done

    install_deps
    download_core

    echo -e "${BLUE}🔑 生成密钥...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(openssl rand -hex 12)"
    PATH_VL="/$(openssl rand -hex 12)"
    PASS_SS=$(generate_random 24)
    
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"decryption":' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"encryption":' | cut -d '"' -f 4)

    if [ -z "$DEC_KEY" ]; then
        echo -e "${RED}❌ 密钥生成失败${NC}"
        return 1
    fi

    # 保存配置到文件，包括当前使用的加密算法
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
CFG_VMESS_CIPHER=$VMESS_CIPHER
CFG_SS_CIPHER=$SS_CIPHER
EOF

    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER"
    create_service

    echo -e "${GREEN}✅ 安装完成${NC}"
    show_links
}

format_ip() {
    local ip=$1
    if [[ "$ip" =~ .*:.* ]]; then
        echo "[$ip]"
    else
        echo "$ip"
    fi
}

print_config_group() {
    local ip_addr=$1
    local label=$2
    
    if [ -z "$ip_addr" ]; then return; fi
    local fmt_ip=$(format_ip "$ip_addr")
    
    # 使用配置文件中保存的算法变量
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_cipher=${CFG_SS_CIPHER:-$SS_CIPHER}

    # VMess Link
    local vmess_json=$(jq -n \
      --arg add "$ip_addr" --arg port "$PORT_VMESS" --arg id "$UUID" --arg path "$PATH_VM" --arg scy "$vm_cipher" \
      '{v:"2", ps:("VMess-" + $scy), add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
    local vmess_link="vmess://$(echo -n "$vmess_json" | base64 -w 0)"

    # VLESS Link
    local vless_link="vless://$UUID@$fmt_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#VLESS-XHTTP-ENC"

    # Shadowsocks Link
    local ss_auth=$(echo -n "${ss_cipher}:$PASS_SS" | base64 -w 0)
    local ss_link="ss://$ss_auth@$fmt_ip:$PORT_SS#SS-Xray"

    echo -e "\n${BLUE}--- $label ($ip_addr) ---${NC}"
    echo -e "1️⃣  VMess ($vm_cipher):"
    echo -e "    ${GREEN}$vmess_link${NC}"
    echo -e "2️⃣  VLESS (XHTTP-ENC):"
    echo -e "    ${GREEN}$vless_link${NC}"
    echo -e "3️⃣  Shadowsocks ($ss_cipher):"
    echo -e "    ${GREEN}$ss_link${NC}"
}

show_links() {
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}❌ 未找到配置${NC}"
        return
    fi
    source "$CONF_FILE"
    
    echo -e "🔑 UUID: ${YELLOW}$UUID${NC}"
    echo -e "🔐 SS 密码: ${YELLOW}$PASS_SS${NC}"
    echo -e "📂 VMess 路径: $PATH_VM"
    echo -e "📂 VLESS 路径: $PATH_VL"

    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    local ipv6=$(curl -s -6 --max-time 2 https://ifconfig.co)

    if [ -n "$ipv4" ]; then print_config_group "$ipv4" "IPv4 配置"; fi
    if [ -n "$ipv6" ]; then print_config_group "$ipv6" "IPv6 配置"; fi
    
    if [ -z "$ipv4" ] && [ -z "$ipv6" ]; then
        echo -e "${RED}❌ 无法获取外部 IP，请检查网络${NC}"
    fi
}

change_ports() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    
    echo -e "当前: VMess=$PORT_VMESS, VLESS=$PORT_VLESS, SS=$PORT_SS"
    read -p "新 VMess (回车跳过): " new_vm
    read -p "新 VLESS (回车跳过): " new_vl
    read -p "新 SS    (回车跳过): " new_ss
    
    [[ ! -z "$new_vm" ]] && sed -i "s/^PORT_VMESS=.*/PORT_VMESS=$new_vm/" "$CONF_FILE"
    [[ ! -z "$new_vl" ]] && sed -i "s/^PORT_VLESS=.*/PORT_VLESS=$new_vl/" "$CONF_FILE"
    [[ ! -z "$new_ss" ]] && sed -i "s/^PORT_SS=.*/PORT_SS=$new_ss/" "$CONF_FILE"
    
    source "$CONF_FILE"
    # 使用保存的加密配置，防止修改端口时丢失加密设置
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_cipher=${CFG_SS_CIPHER:-$SS_CIPHER}
    
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$ss_cipher"
    systemctl restart xray-proxya
    echo -e "${GREEN}✅ 端口已更新并重启${NC}"
}

maintenance_menu() {
    while true; do
        echo -e "\n=== 服务维护 ==="
        echo "1. 启动服务 (Start)"
        echo "2. 停止服务 (Stop)"
        echo "3. 重启服务 (Restart)"
        echo "4. 开机自启 (Enable)"
        echo "5. 取消自启 (Disable)"
        echo "0. 返回上级"
        read -p "选择: " m_choice
        
        case "$m_choice" in
            1) systemctl start xray-proxya && echo -e "${GREEN}已启动${NC}" ;;
            2) systemctl stop xray-proxya && echo -e "${RED}已停止${NC}" ;;
            3) systemctl restart xray-proxya && echo -e "${GREEN}已重启${NC}" ;;
            4) systemctl enable xray-proxya && echo -e "${GREEN}已设置开机自启${NC}" ;;
            5) systemctl disable xray-proxya && echo -e "${YELLOW}已取消开机自启${NC}" ;;
            0) return ;;
            *) echo -e "${RED}无效选项${NC}" ;;
        esac
    done
}

uninstall_xray() {
    read -p "确认卸载? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi

    systemctl stop xray-proxya
    systemctl disable xray-proxya
    rm "$SERVICE_FILE"
    rm -rf "$XRAY_DIR"
    rm -rf "$CONF_DIR"
    systemctl daemon-reload
    echo -e "${GREEN}✅ 已卸载${NC}"
}

check_root
echo -e "${BLUE}Xray-Proxya 管理${NC}"
check_status
echo -e ""
echo "1. 安装 / 重置"
echo "2. 查看链接"
echo "3. 修改端口"
echo "4. 服务维护 (启动/停止/重启)"
echo "5. 卸载"
echo "0. 退出"
read -p "选择: " choice

case "$choice" in
    1) install_xray ;;
    2) show_links ;;
    3) change_ports ;;
    4) maintenance_menu ;;
    5) uninstall_xray ;;
    0) exit 0 ;;
    *) echo -e "${RED}无效${NC}" ;;
esac
