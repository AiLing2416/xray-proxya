#!/bin/bash

# ==================================================
# Xray-Proxya Manager [TEST BRANCH]
# ==================================================

# --- 用户配置区 ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"
# -----------------

CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
CUSTOM_OUT_FILE="$CONF_DIR/custom_outbound.json"
XRAY_BIN="/usr/local/bin/xray-proxya-core/xray"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
JSON_FILE="$XRAY_DIR/config.json"

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
        # Alpine Linux 适配
        echo -e "识别为 Alpine Linux，使用 apk 安装..."
        apk update
        # gcompat 是必须的，因为官方 Xray 编译依赖 glibc
        # iproute2 提供 ss 命令
        apk add curl jq openssl bash coreutils gcompat iproute2 >/dev/null 2>&1
    else
        # Debian / Ubuntu
        apt-get update -qq >/dev/null
        apt-get install -y curl jq unzip openssl >/dev/null 2>&1
    fi
}

generate_random() {
    openssl rand -base64 $(( $1 * 2 )) | tr -dc 'a-zA-Z0-9' | head -c $1
}

check_status() {
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xray-proxya; then
        echo -e "🟢 服务状态: ${GREEN}运行中${NC}"
    else
        # 尝试简单检测进程 (适配部分非标准环境)
        if pgrep -f "$XRAY_BIN" >/dev/null; then
            echo -e "🟢 服务状态: ${GREEN}运行中 (进程检测)${NC}"
        else
            echo -e "🔴 服务状态: ${RED}未运行${NC}"
        fi
    fi
}

download_core() {
    if [ -f "$XRAY_BIN" ]; then return; fi
    echo -e "${BLUE}⬇️  获取 Xray-core...${NC}"
    LATEST_URL=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
    if [ -z "$LATEST_URL" ]; then echo -e "${RED}❌ 下载失败${NC}"; return 1; fi

    systemctl stop xray-proxya 2>/dev/null
    mkdir -p "$XRAY_DIR"
    curl -L -o /tmp/xray.zip "$LATEST_URL"
    unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
    rm /tmp/xray.zip
    chmod +x "$XRAY_BIN"
}

# --- 链接解析与自定义出站 ---

# 解码辅助
decode_base64() {
    local str="$1"
    # 尝试标准解码，失败尝试 URL safe 解码
    echo "$str" | base64 -d 2>/dev/null || echo "$str" | base64 -d -i 2>/dev/null
}

parse_link_to_json() {
    local link="$1"
    
    # === VMess ===
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

        cat <<EOF
{
  "tag": "custom-out",
  "protocol": "vmess",
  "settings": {
    "vnext": [{ "address": "$add", "port": $port, "users": [{ "id": "$id" }] }]
  },
  "streamSettings": {
    "network": "$net",
    "security": "$tls",
    "wsSettings": { "path": "$path", "headers": { "Host": "$host" } }
  }
}
EOF
        return 0
    fi

    # === VLESS ===
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

        cat <<EOF
{
  "tag": "custom-out",
  "protocol": "vless",
  "settings": {
    "vnext": [{ "address": "$address", "port": $port, "users": [{ "id": "$uuid" }] }]
  },
  "streamSettings": {
    "network": "$type",
    "security": "$security",
    "tlsSettings": { "serverName": "$sni" },
    "$type\Settings": { "path": "$path" }
  }
}
EOF
        return 0
    fi

    # === Shadowsocks ===
    if [[ "$link" == ss://* ]]; then
        local raw="${link#ss://}"
        raw="${raw%%\#*}" # 去掉 #tag
        
        # 尝试解码整个字符串 (SIP002 格式: user:pass@host:port)
        local decoded=$(decode_base64 "$raw")
        local method=""
        local password=""
        local address=""
        local port=""
        
        if [[ "$decoded" == *:*@*:* ]]; then
            # 格式: method:pass@host:port
            local auth="${decoded%%@*}"
            local addr_full="${decoded#*@}"
            method="${auth%%:*}"
            password="${auth#*:}"
            address="${addr_full%%:*}"
            port="${addr_full##*:}"
        else
            # 尝试旧格式: base64(method:pass)@host:port
            if [[ "$raw" == *@* ]]; then
                local b64_auth="${raw%%@*}"
                local addr_full="${raw#*@}"
                local auth=$(decode_base64 "$b64_auth")
                method="${auth%%:*}"
                password="${auth#*:}"
                address="${addr_full%%:*}"
                port="${addr_full##*:}"
            fi
        fi

        if [ -z "$method" ] || [ -z "$address" ]; then return 1; fi

        cat <<EOF
{
  "tag": "custom-out",
  "protocol": "shadowsocks",
  "settings": {
    "servers": [{
      "address": "$address",
      "port": $port,
      "method": "$method",
      "password": "$password"
    }]
  }
}
EOF
        return 0
    fi
    
    return 1
}

add_custom_outbound() {
    echo -e "\n=== 添加自定义出站 (流量转发) ==="
    echo -e "${YELLOW}支持导入: VMess(ws), VLESS, Shadowsocks${NC}"
    echo -e "该配置将用于新的转发用户，原用户不受影响。\n"
    
    read -p "请粘贴分享链接: " link_str
    
    if [ -z "$link_str" ]; then echo -e "${RED}输入为空${NC}"; return; fi
    
    echo -e "${BLUE}正在解析...${NC}"
    PARSED_JSON=$(parse_link_to_json "$link_str")
    
    if [ $? -ne 0 ] || [ -z "$PARSED_JSON" ]; then
        echo -e "${RED}❌ 解析失败。${NC}"
        echo -e "可能是不支持的链接格式或编码错误。"
        return
    fi
    
    echo "$PARSED_JSON" > "$CUSTOM_OUT_FILE"
    echo -e "${GREEN}✅ 解析成功！${NC}"
    
    source "$CONF_FILE"
    if [ -z "$UUID_CUSTOM" ]; then
        UUID_CUSTOM=$("$XRAY_BIN" uuid)
        echo "UUID_CUSTOM=$UUID_CUSTOM" >> "$CONF_FILE"
        echo -e "已生成转发专用 UUID: $UUID_CUSTOM"
    fi
    
    source "$CONF_FILE"
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER"
    systemctl restart xray-proxya
    echo -e "${GREEN}服务已重启，转发规则已生效。${NC}"
}

# --- 核心配置生成 ---

generate_config() {
    local vmess_p=$1; local vless_p=$2; local ss_p=$3; local uuid_direct=$4
    local vmess_path=$5; local vless_path=$6; local enc_key=$7; local dec_key=$8
    local ss_pass=$9; local ss_method=${10}
    local uuid_custom=${UUID_CUSTOM:-""}
    
    local clients_vmess="{ \"id\": \"$uuid_direct\", \"email\": \"direct\", \"level\": 0 }"
    local clients_vless="{ \"id\": \"$uuid_direct\", \"email\": \"direct\", \"level\": 0 }"
    
    if [ ! -z "$uuid_custom" ] && [ -f "$CUSTOM_OUT_FILE" ]; then
        clients_vmess="$clients_vmess, { \"id\": \"$uuid_custom\", \"email\": \"custom\", \"level\": 0 }"
        clients_vless="$clients_vless, { \"id\": \"$uuid_custom\", \"email\": \"custom\", \"level\": 0 }"
    fi

    cat > "$JSON_FILE" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vmess-in",
      "port": $vmess_p,
      "protocol": "vmess",
      "settings": { "clients": [ $clients_vmess ] },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "$vmess_path" } }
    },
    {
      "tag": "vless-enc-in",
      "port": $vless_p,
      "protocol": "vless",
      "settings": { "clients": [ $clients_vless ], "decryption": "$dec_key" },
      "streamSettings": { "network": "xhttp", "xhttpSettings": { "path": "$vless_path" } }
    },
    {
      "tag": "shadowsocks-in",
      "port": $ss_p,
      "protocol": "shadowsocks",
      "settings": { "method": "$ss_method", "password": "$ss_pass", "network": "tcp,udp" }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" }
EOF

    if [ -f "$CUSTOM_OUT_FILE" ]; then
        echo "," >> "$JSON_FILE"
        cat "$CUSTOM_OUT_FILE" >> "$JSON_FILE"
    fi

    cat >> "$JSON_FILE" <<EOF
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

# --- 安装与管理 ---

install_xray() {
    echo -e "=== 安装向导 ==="
    read -p "VMess 端口 (默认 ${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (默认 ${vlessp:-8082}): " port_vl
    read -p "SS    端口 (默认 ${ssocks:-8083}): " port_ss
    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}

    for p in $PORT_VMESS $PORT_VLESS $PORT_SS; do
        if ss -lnt | grep -q ":$p "; then echo -e "${RED}⚠️ 端口 $p 被占用${NC}"; return; fi
    done

    install_deps
    download_core

    echo -e "${BLUE}🔑 生成配置...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(generate_random 12)"
    PATH_VL="/$(generate_random 12)"
    PASS_SS=$(generate_random 24)
    
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "ML-KEM" | grep '"decryption":' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "ML-KEM" | grep '"encryption":' | cut -d '"' -f 4)
    if [ -z "$DEC_KEY" ]; then echo -e "${RED}❌ 密钥生成失败${NC}"; return 1; fi

    mkdir -p "$CONF_DIR"
    rm -f "$CUSTOM_OUT_FILE"
    
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
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xray-proxya >/dev/null 2>&1
    systemctl restart xray-proxya
    echo -e "${GREEN}✅ 安装完成${NC}"
    show_links_menu
}

# --- 链接展示逻辑 ---

format_ip() { [[ "$1" =~ .*:.* ]] && echo "[$1]" || echo "$1"; }

print_link_group() {
    local ip=$1; local label=$2; local target_uuid=$3; local desc=$4
    if [ -z "$ip" ]; then return; fi
    local f_ip=$(format_ip "$ip")
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_cipher=${CFG_SS_CIPHER:-$SS_CIPHER}

    local vm_j=$(jq -n --arg add "$ip" --arg port "$PORT_VMESS" --arg id "$target_uuid" --arg path "$PATH_VM" --arg scy "$vm_cipher" --arg ps "$desc-VMess" \
      '{v:"2", ps:$ps, add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
    local vm_l="vmess://$(echo -n "$vm_j" | base64 -w 0)"
    
    local vl_l="vless://$target_uuid@$f_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#$desc-VLESS"
    
    local ss_l=""
    if [ "$desc" == "Direct" ]; then
        local ss_auth=$(echo -n "${ss_cipher}:$PASS_SS" | base64 -w 0)
        ss_l="ss://$ss_auth@$f_ip:$PORT_SS#$desc-SS"
    fi

    echo -e "\n${BLUE}--- $label ($ip) ---${NC}"
    echo -e "1️⃣  VMess ($vm_cipher): ${GREEN}$vm_l${NC}"
    echo -e "2️⃣  VLESS (XHTTP-ENC): ${GREEN}$vl_l${NC}"
    [ ! -z "$ss_l" ] && echo -e "3️⃣  Shadowsocks:       ${GREEN}$ss_l${NC}"
}

show_links_logic() {
    local target_uuid=$1
    local desc_tag=$2
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
        2) [ -z "$UUID_CUSTOM" ] && { echo -e "${RED}错误${NC}"; return; }
           show_links_logic "$UUID_CUSTOM" "Custom" ;;
        q|Q) return ;;
        *) echo -e "${RED}无效${NC}" ;;
    esac
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
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "${CFG_SS_CIPHER:-$SS_CIPHER}"
    systemctl restart xray-proxya
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
            1) systemctl start xray-proxya && echo "✅" ;;
            2) systemctl stop xray-proxya && echo "✅" ;;
            3) systemctl restart xray-proxya && echo "✅" ;;
            4) systemctl enable xray-proxya && echo "✅" ;;
            5) systemctl disable xray-proxya && echo "✅" ;;
            q|Q) return ;;
            *) echo "❌" ;;
        esac
    done
}

uninstall_xray() {
    echo -e "${YELLOW}⚠️  警告: 将停止服务并删除配置。${NC}"
    read -p "确认卸载? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi
    systemctl stop xray-proxya
    systemctl disable xray-proxya
    rm "$SERVICE_FILE"
    rm -rf "$CONF_DIR"
    systemctl daemon-reload
    echo -e "${GREEN}✅ 服务与配置已移除。${NC}"
    read -p "是否同时删除 Xray 核心文件 ($XRAY_DIR)? (y/N): " del_core
    if [[ "$del_core" == "y" ]]; then
        rm -rf "$XRAY_DIR"
        echo -e "${GREEN}✅ 核心文件已移除。${NC}"
    fi
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
