#!/bin/bash

# ==================================================
# Xray-Proxya Manager [STABLE FIX v4]
# Supports: Debian/Ubuntu & Alpine (OpenRC)
# Fixed: Key parsing logic for Alpine output format
# ==================================================

# --- 默认配置变量 ---
DEFAULT_PORT_VMESS=8081
DEFAULT_PORT_VLESS_KEM=8082
DEFAULT_PORT_REALITY=8443
DEFAULT_PORT_SS=8083

# 加密算法
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"

# Reality 配置
REALITY_DEST="www.microsoft.com:443"
REALITY_SNI="www.microsoft.com"

# -----------------

CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
CUSTOM_OUT_FILE="$CONF_DIR/custom_outbound.json"
XRAY_BIN="/usr/local/bin/xray-proxya-core/xray"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
JSON_FILE="$XRAY_DIR/config.json"

# 系统检测
IS_OPENRC=0
if [ -f /etc/alpine-release ]; then
    IS_OPENRC=1
fi

if [ $IS_OPENRC -eq 1 ]; then
    SERVICE_FILE="/etc/init.d/xray-proxya"
else
    SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 基础函数 ---

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}❌ 错误: 需要 root 权限${NC}"
        exit 1
    fi
}

install_deps() {
    echo -e "${BLUE}📦 安装/检查依赖...${NC}"
    if [ -f /etc/alpine-release ]; then
        apk update
        apk add curl jq openssl bash coreutils gcompat iproute2 grep libgcc libstdc++ sed awk >/dev/null 2>&1
    else
        apt-get update -qq >/dev/null
        apt-get install -y curl jq unzip openssl >/dev/null 2>&1
    fi
}

check_port_occupied() {
    local port=$1
    if command -v ss >/dev/null 2>&1; then
        if ss -lnt | grep -q ":$port "; then return 0; fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -lnt | grep -q ":$port "; then return 0; fi
    fi
    return 1
}

# --- 服务管理 ---

sys_enable() {
    [ $IS_OPENRC -eq 1 ] && rc-update add xray-proxya default >/dev/null 2>&1 || systemctl enable xray-proxya >/dev/null 2>&1
}
sys_disable() {
    [ $IS_OPENRC -eq 1 ] && rc-update del xray-proxya default >/dev/null 2>&1 || systemctl disable xray-proxya >/dev/null 2>&1
}
sys_start() {
    [ $IS_OPENRC -eq 1 ] && rc-service xray-proxya start || systemctl start xray-proxya
}
sys_stop() {
    [ $IS_OPENRC -eq 1 ] && rc-service xray-proxya stop || systemctl stop xray-proxya
}
sys_restart() {
    [ $IS_OPENRC -eq 1 ] && rc-service xray-proxya restart || systemctl restart xray-proxya
}
sys_reload_daemon() {
    [ $IS_OPENRC -eq 0 ] && systemctl daemon-reload
}
check_status() {
    if [ $IS_OPENRC -eq 1 ]; then
        if rc-service xray-proxya status 2>/dev/null | grep -q "started"; then
            echo -e "🟢 服务状态: ${GREEN}运行中 (OpenRC)${NC}"
        else
            echo -e "🔴 服务状态: ${RED}未运行${NC}"
        fi
    else
        if systemctl is-active --quiet xray-proxya; then
            echo -e "🟢 服务状态: ${GREEN}运行中 (Systemd)${NC}"
        else
            echo -e "🔴 服务状态: ${RED}未运行${NC}"
        fi
    fi
}

# --- 核心逻辑 ---

generate_random() {
    openssl rand -base64 $(( $1 * 2 )) | tr -dc 'a-zA-Z0-9' | head -c $1
}

download_core() {
    if [ -f "$XRAY_BIN" ]; then return; fi
    echo -e "${BLUE}⬇️  获取 Xray-core...${NC}"
    LATEST_URL=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
    if [ -z "$LATEST_URL" ]; then echo -e "${RED}❌ 下载失败${NC}"; return 1; fi
    sys_stop 2>/dev/null
    mkdir -p "$XRAY_DIR"
    curl -L -o /tmp/xray.zip "$LATEST_URL"
    unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
    rm /tmp/xray.zip
    chmod +x "$XRAY_BIN"
}

decode_base64() {
    local str="$1"
    echo "$str" | base64 -d 2>/dev/null || echo "$str" | base64 -d -i 2>/dev/null
}

parse_link_to_json() {
    local link="$1"
    if [[ "$link" == vmess://* ]]; then
        local b64="${link#vmess://}"
        local json_str=$(decode_base64 "$b64")
        if [ -z "$json_str" ]; then return 1; fi
        local add=$(echo "$json_str" | jq -r '.add')
        local port=$(echo "$json_str" | jq -r '.port')
        local id=$(echo "$json_str" | jq -r '.id')
        local net=$(echo "$json_str" | jq -r '.net')
        local path=$(echo "$json_str" | jq -r '.path')
        local host=$(echo "$json_str" | jq -r '.host')
        local tls=$(echo "$json_str" | jq -r '.tls')
        cat <<-EOF
{ "tag": "custom-out", "protocol": "vmess", "settings": { "vnext": [{ "address": "$add", "port": $port, "users": [{ "id": "$id" }] }] }, "streamSettings": { "network": "$net", "security": "$tls", "wsSettings": { "path": "$path", "headers": { "Host": "$host" } } } }
EOF
        return 0
    fi
    if [[ "$link" == vless://* ]]; then
        local tmp="${link#vless://}"
        local uuid="${tmp%%@*}"
        tmp="${tmp#*@}"
        local address_port="${tmp%%\?*}"
        local address="${address_port%:*}"
        local port="${address_port##*:}"
        local query="${link#*\?}"
        query="${query%%\#*}"
        local type=$(echo "$query" | grep -oP 'type=\K[^&]+')
        local security=$(echo "$query" | grep -oP 'security=\K[^&]+')
        local path=$(echo "$query" | grep -oP 'path=\K[^&]+' | sed 's/%2F/\//g')
        local sni=$(echo "$query" | grep -oP 'sni=\K[^&]+')
        [ -z "$type" ] && type="tcp"
        [ -z "$security" ] && security="none"
        cat <<-EOF
{ "tag": "custom-out", "protocol": "vless", "settings": { "vnext": [{ "address": "$address", "port": $port, "users": [{ "id": "$uuid" }] }] }, "streamSettings": { "network": "$type", "security": "$security", "tlsSettings": { "serverName": "$sni" }, "$type\Settings": { "path": "$path" } } }
EOF
        return 0
    fi
    return 1
}

add_custom_outbound() {
    echo -e "\n=== 添加自定义出站 (流量转发) ==="
    read -p "请粘贴分享链接 (VMess/VLESS): " link_str
    if [ -z "$link_str" ]; then echo -e "${RED}输入为空${NC}"; return; fi
    PARSED_JSON=$(parse_link_to_json "$link_str")
    if [ $? -ne 0 ] || [ -z "$PARSED_JSON" ]; then echo -e "${RED}❌ 解析失败${NC}"; return; fi
    echo "$PARSED_JSON" > "$CUSTOM_OUT_FILE"
    echo -e "${GREEN}✅ 解析成功${NC}"
    source "$CONF_FILE"
    if [ -z "$UUID_CUSTOM" ]; then
        UUID_CUSTOM=$("$XRAY_BIN" uuid)
        echo "UUID_CUSTOM=$UUID_CUSTOM" >> "$CONF_FILE"
    fi
    source "$CONF_FILE"
    generate_config
    sys_restart
    echo -e "${GREEN}服务已重启，转发规则已生效${NC}"
}

generate_config() {
    source "$CONF_FILE"
    
    local clients_direct="{ \"id\": \"$UUID\", \"email\": \"direct\", \"level\": 0 }"
    local clients_custom=""
    if [ ! -z "$UUID_CUSTOM" ] && [ -f "$CUSTOM_OUT_FILE" ]; then
        clients_custom=", { \"id\": \"$UUID_CUSTOM\", \"email\": \"custom\", \"level\": 0 }"
    fi
    local clients_all="[ $clients_direct $clients_custom ]"

    cat > "$JSON_FILE" <<-EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vmess-in", "port": $PORT_VMESS, "protocol": "vmess",
      "settings": { "clients": $clients_all },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "$PATH_VM" } }
    },
    {
      "tag": "vless-enc-in", "port": $PORT_VLESS, "protocol": "vless",
      "settings": { "clients": $clients_all, "decryption": "$DEC_KEY" },
      "streamSettings": { "network": "xhttp", "xhttpSettings": { "path": "$PATH_VL" } }
    },
    {
      "tag": "vless-reality-in", "port": $PORT_REALITY, "protocol": "vless",
      "settings": { "clients": $clients_all, "decryption": "none" },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$REALITY_DEST",
          "xver": 0,
          "serverNames": [ "$REALITY_SNI" ],
          "privateKey": "$REALITY_PK",
          "shortIds": [ "$REALITY_SID" ]
        },
        "xhttpSettings": { "path": "$PATH_REALITY" }
      }
    },
    {
      "tag": "shadowsocks-in", "port": $PORT_SS, "protocol": "shadowsocks",
      "settings": { "method": "$SS_CIPHER", "password": "$PASS_SS", "network": "tcp,udp" }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" }
EOF

    if [ -f "$CUSTOM_OUT_FILE" ]; then
        echo "," >> "$JSON_FILE"
        cat "$CUSTOM_OUT_FILE" >> "$JSON_FILE"
    fi

    cat >> "$JSON_FILE" <<-EOF
  ],
  "routing": {
    "rules": [
      { "type": "field", "user": ["direct"], "outboundTag": "direct" },
      { "type": "field", "user": ["custom"], "outboundTag": "custom-out" }
    ]
  }
}
EOF
}

create_service() {
    if [ $IS_OPENRC -eq 1 ]; then
        cat > "$SERVICE_FILE" <<-EOF
#!/sbin/openrc-run
name="xray-proxya"
description="Xray-Proxya Service"
command="$XRAY_BIN"
command_args="run -c $JSON_FILE"
command_background=true
pidfile="/run/xray-proxya.pid"
depend() {
    need net
    after firewall
}
EOF
        chmod +x "$SERVICE_FILE"
    else
        cat > "$SERVICE_FILE" <<-EOF
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
[Install]
WantedBy=multi-user.target
EOF
    fi
    sys_reload_daemon
    sys_enable
    sys_restart
}

install_xray() {
    echo -e "=== 安装向导 ==="
    
    read -p "VMess-WS 入站端口 (默认 $DEFAULT_PORT_VMESS): " port_vm
    read -p "VLess-XHTTP-KEM768 (抗量子) 端口 (默认 $DEFAULT_PORT_VLESS_KEM): " port_vl
    read -p "VLess-XHTTP-Reality (TLS抗量子) 端口 (默认 $DEFAULT_PORT_REALITY): " port_rea
    read -p "Shadowsocks-AES256 端口 (默认 $DEFAULT_PORT_SS): " port_ss
    
    PORT_VMESS=${port_vm:-$DEFAULT_PORT_VMESS}
    PORT_VLESS=${port_vl:-$DEFAULT_PORT_VLESS_KEM}
    PORT_REALITY=${port_rea:-$DEFAULT_PORT_REALITY}
    PORT_SS=${port_ss:-$DEFAULT_PORT_SS}

    for p in $PORT_VMESS $PORT_VLESS $PORT_REALITY $PORT_SS; do
        if check_port_occupied $p; then echo -e "${RED}⚠️ 端口 $p 被占用${NC}"; return; fi
    done

    install_deps
    download_core

    echo -e "${BLUE}🔑 生成配置与密钥...${NC}"
    
    if ! "$XRAY_BIN" version >/dev/null 2>&1; then
        echo -e "${RED}❌ Xray 无法运行!${NC} (可能缺少依赖)"
        echo -e "Debug: $($XRAY_BIN version 2>&1)"
        return 1
    fi

    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(generate_random 12)"
    PATH_VL="/$(generate_random 12)"
    PATH_REALITY="/$(generate_random 12)"
    PASS_SS=$(generate_random 24)
    
    # === 修复解析逻辑 ===
    
    # 1. Reality Key Parsing
    # Output: "PrivateKey: xxxx" (awk $2) or "Private Key: xxxx" (awk $3) or just use $NF (Last Field)
    RAW_REALITY_OUT=$("$XRAY_BIN" x25519 2>&1)
    REALITY_PK=$(echo "$RAW_REALITY_OUT" | grep "Private" | awk -F ": " '{print $NF}' | tr -d ' \r')
    REALITY_PUB=$(echo "$RAW_REALITY_OUT" | grep "Public" | awk -F ": " '{print $NF}' | tr -d ' \r')
    REALITY_SID=$(openssl rand -hex 4)
    
    # 2. ML-KEM Key Parsing
    # 使用 awk 定位 Block，然后提取 quotes 里的内容
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc 2>&1)
    # 逻辑: 找到 "Authentication: ML-KEM-768" 这行，设置 flag。在 flag=1 时，找到 "decryption" 行，打印并退出 awk。
    DEC_KEY=$(echo "$RAW_ENC_OUT" | awk '/Authentication: ML-KEM-768/{flag=1} flag && /"decryption":/{print $0; exit}' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | awk '/Authentication: ML-KEM-768/{flag=1} flag && /"encryption":/{print $0; exit}' | cut -d '"' -f 4)

    if [ -z "$DEC_KEY" ] || [ -z "$REALITY_PK" ]; then
        echo -e "${RED}❌ 密钥生成失败${NC}"
        echo -e "--- Reality Debug ---\n$RAW_REALITY_OUT"
        echo -e "--- ML-KEM Debug ---\n$RAW_ENC_OUT"
        return 1
    fi

    mkdir -p "$CONF_DIR"
    rm -f "$CUSTOM_OUT_FILE"
    
    cat > "$CONF_FILE" <<-EOF
PORT_VMESS=$PORT_VMESS
PORT_VLESS=$PORT_VLESS
PORT_REALITY=$PORT_REALITY
PORT_SS=$PORT_SS
UUID=$UUID
PATH_VM=$PATH_VM
PATH_VL=$PATH_VL
PATH_REALITY=$PATH_REALITY
PASS_SS=$PASS_SS
ENC_KEY=$ENC_KEY
DEC_KEY=$DEC_KEY
REALITY_PK=$REALITY_PK
REALITY_PUB=$REALITY_PUB
REALITY_SID=$REALITY_SID
REALITY_SNI=$REALITY_SNI
REALITY_DEST=$REALITY_DEST
EOF
    generate_config
    create_service
    echo -e "${GREEN}✅ 安装完成${NC}"
    show_links_menu
}

# --- 链接展示 ---

format_ip() { [[ "$1" =~ .*:.* ]] && echo "[$1]" || echo "$1"; }

print_link_group() {
    local ip=$1; local label=$2; local target_uuid=$3; local desc=$4
    if [ -z "$ip" ]; then return; fi
    local f_ip=$(format_ip "$ip")
    
    local ps_vm="VMess-WS-${VMESS_CIPHER}-$PORT_VMESS"
    [ "$desc" == "Custom" ] && ps_vm="转发-$ps_vm"
    local vm_j=$(jq -n --arg add "$ip" --arg port "$PORT_VMESS" --arg id "$target_uuid" --arg path "$PATH_VM" --arg scy "$VMESS_CIPHER" --arg ps "$ps_vm" \
      '{v:"2", ps:$ps, add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
    local vm_l="vmess://$(echo -n "$vm_j" | base64 -w 0)"
    
    local ps_vl="VLess-XHTTP-KEM768-$PORT_VLESS"
    [ "$desc" == "Custom" ] && ps_vl="转发-$ps_vl"
    local vl_l="vless://$target_uuid@$f_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#$ps_vl"
    
    local ps_rea="VLess-XHTTP-Reality-$PORT_REALITY"
    [ "$desc" == "Custom" ] && ps_rea="转发-$ps_rea"
    local rea_l="vless://$target_uuid@$f_ip:$PORT_REALITY?security=reality&encryption=none&pbk=$REALITY_PUB&fp=chrome&type=xhttp&serviceName=&path=$PATH_REALITY&sni=$REALITY_SNI&sid=$REALITY_SID&spx=%2F#$ps_rea"

    local ss_l=""
    if [ "$desc" == "Direct" ]; then
        local ps_ss="SS-TCPUDP-${SS_CIPHER}-$PORT_SS"
        local ss_auth=$(echo -n "${SS_CIPHER}:$PASS_SS" | base64 -w 0)
        ss_l="ss://$ss_auth@$f_ip:$PORT_SS#$ps_ss"
    fi

    echo -e "\n${BLUE}--- $label ($ip) ---${NC}"
    echo -e "1️⃣  VMess (${VMESS_CIPHER}):\n    ${GREEN}$vm_l${NC}"
    echo -e "2️⃣  VLESS (ML-KEM768):\n    ${GREEN}$vl_l${NC}"
    echo -e "3️⃣  VLESS (Reality-TLS):\n    ${GREEN}$rea_l${NC}"
    [ ! -z "$ss_l" ] && echo -e "4️⃣  Shadowsocks (${SS_CIPHER}):\n    ${GREEN}$ss_l${NC}"
}

show_links_logic() {
    local target_uuid=$1; local desc_tag=$2
    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    local ipv6=$(curl -s -6 --max-time 2 https://ifconfig.co)
    if [ -n "$ipv4" ]; then print_link_group "$ipv4" "IPv4" "$target_uuid" "$desc_tag"; fi
    if [ -n "$ipv6" ]; then print_link_group "$ipv6" "IPv6" "$target_uuid" "$desc_tag"; fi
    if [ -z "$ipv4" ] && [ -z "$ipv6" ]; then echo -e "${RED}❌ 无法获取 IP${NC}"; fi
}

show_links_menu() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}❌ 未配置${NC}"; return; fi
    source "$CONF_FILE"
    if [ ! -f "$CUSTOM_OUT_FILE" ]; then
        echo -e "\n=== 链接信息 (直接出站) ==="
        show_links_logic "$UUID" "Direct"
        return
    fi
    echo -e "\n=== 选择要查看的链接类型 ==="
    echo "1. 直接出站 (本机 IP)"
    echo "2. 自定义出站 (转发流量)"
    echo "q. 返回"
    read -p "选择: " sl_choice
    case "$sl_choice" in
        1) show_links_logic "$UUID" "Direct" ;;
        2) [ -z "$UUID_CUSTOM" ] && { echo -e "${RED}错误${NC}"; return; }; show_links_logic "$UUID_CUSTOM" "Custom" ;;
        q|Q) return ;;
        *) echo -e "${RED}无效${NC}" ;;
    esac
}

change_ports() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    echo -e "当前配置:"
    echo "1. VMess     : $PORT_VMESS"
    echo "2. VLESS(KEM): $PORT_VLESS"
    echo "3. Reality   : $PORT_REALITY"
    echo "4. SS        : $PORT_SS"
    
    read -p "新 VMess 端口 (回车跳过): " new_vm
    read -p "新 VLESS(KEM) 端口 (回车跳过): " new_vl
    read -p "新 Reality 端口 (回车跳过): " new_rea
    read -p "新 SS 端口 (回车跳过): " new_ss
    
    [[ ! -z "$new_vm" ]] && sed -i "s/^PORT_VMESS=.*/PORT_VMESS=$new_vm/" "$CONF_FILE"
    [[ ! -z "$new_vl" ]] && sed -i "s/^PORT_VLESS=.*/PORT_VLESS=$new_vl/" "$CONF_FILE"
    [[ ! -z "$new_rea" ]] && sed -i "s/^PORT_REALITY=.*/PORT_REALITY=$new_rea/" "$CONF_FILE"
    [[ ! -z "$new_ss" ]] && sed -i "s/^PORT_SS=.*/PORT_SS=$new_ss/" "$CONF_FILE"
    
    source "$CONF_FILE"
    generate_config
    sys_restart
    echo -e "${GREEN}✅ 已更新并重启${NC}"
}

maintenance_menu() {
    while true; do
        echo -e "\n=== 维护 ==="
        echo "1. 启动"
        echo "2. 停止"
        echo "3. 重启"
        echo "4. 开机自启"
        echo "5. 取消自启"
        echo "q. 返回"
        read -p "选择: " m_choice
        case "$m_choice" in
            1) sys_start && echo "✅" ;;
            2) sys_stop && echo "✅" ;;
            3) sys_restart && echo "✅" ;;
            4) sys_enable && echo "✅" ;;
            5) sys_disable && echo "✅" ;;
            q|Q) return ;;
            *) echo "❌" ;;
        esac
    done
}

uninstall_xray() {
    echo -e "${YELLOW}⚠️  警告: 将停止服务并删除配置。${NC}"
    read -p "确认卸载? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi
    sys_stop 2>/dev/null
    sys_disable 2>/dev/null
    rm "$SERVICE_FILE"
    rm -rf "$CONF_DIR"
    sys_reload_daemon
    echo -e "${GREEN}✅ 服务与配置已移除。${NC}"
    read -p "是否同时删除 Xray 核心文件 ($XRAY_DIR)? (y/N): " del_core
    if [[ "$del_core" == "y" ]]; then rm -rf "$XRAY_DIR"; echo -e "${GREEN}✅ 核心文件已移除。${NC}"; fi
}

check_root
while true; do
    echo -e "\n${BLUE}Xray-Proxya 管理 [TEST]${NC}"
    check_status
    echo "1. 安装 / 重置"
    echo "2. 查看链接"
    echo "3. 修改端口"
    echo "4. 维护菜单"
    echo "5. 卸载 Xray"
    echo "6. 添加/更新 自定义出站 (转发)"
    echo "q. 退出"
    echo "0. 卸载 (快捷)"
    read -p "选择: " choice
    case "$choice" in
        1) install_xray ;;
        2) show_links_menu ;;
        3) change_ports ;;
        4) maintenance_menu ;;
        5|0) uninstall_xray ;;
        6) add_custom_outbound ;;
        q|Q) exit 0 ;;
        *) echo -e "${RED}无效${NC}" ;;
    esac
done
