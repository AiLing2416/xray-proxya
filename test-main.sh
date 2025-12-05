#!/bin/bash

# ==================================================
# Xray-Proxya Manager [Test Build]
# ==================================================

# --- 用户变量 ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"

# --- 系统变量 ---
CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
CUSTOM_OUT_FILE="$CONF_DIR/custom_out.json"
XRAY_BIN="/usr/local/sbin/xray-proxya-core/xray" # 为了 sudo 补全，此处也假设安装在 sbin 或 bin，由 install.sh 决定
XRAY_DIR="/usr/local/sbin/xray-proxya-core"
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
    if ! command -v jq &> /dev/null; then
        echo -e "${BLUE}📦 安装依赖...${NC}"
        apt-get update -qq >/dev/null
        apt-get install -y curl jq unzip openssl >/dev/null 2>&1
    fi
}

generate_random() {
    local length=$1
    openssl rand -base64 $((length * 2)) | tr -dc 'a-zA-Z0-9' | head -c $length
}

# --- 核心逻辑 ---

download_core() {
    echo -e "${BLUE}⬇️  获取 Xray-core...${NC}"
    LATEST_URL=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
    
    if [ -z "$LATEST_URL" ]; then
        echo -e "${RED}❌ 下载失败${NC}"
        return 1
    fi

    systemctl stop xray-proxya 2>/dev/null
    mkdir -p "$XRAY_DIR"
    curl -L -o /tmp/xray.zip "$LATEST_URL"
    unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
    rm /tmp/xray.zip
    chmod +x "$XRAY_BIN"
}

# 解析出站链接并生成 JSON 片段
parse_outbound_link() {
    local link=$1
    local json_out=""

    if [[ "$link" == vmess://* ]]; then
        # VMess 解析
        local b64=$(echo "${link#vmess://}" | base64 -d 2>/dev/null)
        if [ $? -ne 0 ]; then echo "❌ Base64 解码失败"; return 1; fi
        
        # 提取字段
        local addr=$(echo "$b64" | jq -r '.add')
        local port=$(echo "$b64" | jq -r '.port')
        local id=$(echo "$b64" | jq -r '.id')
        local net=$(echo "$b64" | jq -r '.net')
        local path=$(echo "$b64" | jq -r '.path')
        local tls=$(echo "$b64" | jq -r '.tls')
        
        # 构建出站 JSON
        json_out=$(jq -n \
            --arg addr "$addr" --arg port "$port" --arg id "$id" --arg net "$net" --arg path "$path" --arg tls "$tls" \
            '{
                protocol: "vmess",
                settings: { vnext: [{ address: $addr, port: ($port|tonumber), users: [{ id: $id }] }] },
                streamSettings: { network: $net, security: $tls, wsSettings: { path: $path } }
            }')

    elif [[ "$link" == ss://* ]]; then
        # SS 解析 (SIP002)
        local body=${link#ss://}
        body=${body%%#*} # 去掉备注
        local decoded=$(echo "$body" | cut -d'@' -f1 | base64 -d 2>/dev/null)
        local addr_part=$(echo "$body" | cut -d'@' -f2)
        
        local method=$(echo "$decoded" | cut -d':' -f1)
        local pass=$(echo "$decoded" | cut -d':' -f2)
        local addr=$(echo "$addr_part" | cut -d':' -f1)
        local port=$(echo "$addr_part" | cut -d':' -f2)

        json_out=$(jq -n \
            --arg addr "$addr" --arg port "$port" --arg method "$method" --arg pass "$pass" \
            '{
                protocol: "shadowsocks",
                settings: { servers: [{ address: $addr, port: ($port|tonumber), method: $method, password: $pass }] }
            }')
    else
        echo "❌ 目前仅支持标准 VMess(base64) 和 SS(SIP002) 链接导入。"
        return 1
    fi

    # 添加 tag
    echo "$json_out" | jq '. + {tag: "custom_out"}' > "$CUSTOM_OUT_FILE"
    return 0
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
    local ss_method=${10}
    local uuid_custom=${11} # 第二个用户的 UUID (可选)

    # 基础入站 (Client 0: Direct)
    local vmess_clients="[ { \"id\": \"$uuid\", \"email\": \"direct\", \"level\": 0 }"
    local vless_clients="[ { \"id\": \"$uuid\", \"email\": \"direct\", \"level\": 0 }"

    # 如果有自定义出站用户，参加入站配置
    if [ -n "$uuid_custom" ]; then
        vmess_clients="$vmess_clients, { \"id\": \"$uuid_custom\", \"email\": \"custom\", \"level\": 0 }"
        vless_clients="$vless_clients, { \"id\": \"$uuid_custom\", \"email\": \"custom\", \"level\": 0 }"
    fi
    vmess_clients="$vmess_clients ]"
    vless_clients="$vless_clients ]"

    # 构建配置头
    cat > "$JSON_FILE" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vmess-in",
      "port": $vmess_p,
      "protocol": "vmess",
      "settings": { "clients": $vmess_clients },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "$vmess_path" } }
    },
    {
      "tag": "vless-enc-in",
      "port": $vless_p,
      "protocol": "vless",
      "settings": { "clients": $vless_clients, "decryption": "$dec_key" },
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
  "outbounds": [ 
    { "tag": "freedom", "protocol": "freedom" }
EOF

    # 插入自定义出站 (如果存在)
    if [ -f "$CUSTOM_OUT_FILE" ]; then
        echo "    ," >> "$JSON_FILE"
        cat "$CUSTOM_OUT_FILE" >> "$JSON_FILE"
    fi

    # 闭合出站并添加路由
    cat >> "$JSON_FILE" <<EOF
  ],
  "routing": {
    "rules": [
      { "type": "field", "email": "custom", "outboundTag": "custom_out" },
      { "type": "field", "email": "direct", "outboundTag": "freedom" }
    ]
  }
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
    echo -e "=== 安装向导 [Test] ==="
    
    read -p "VMess 端口 (默认 ${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (默认 ${vlessp:-8082}): " port_vl
    read -p "SS    端口 (默认 ${ssocks:-8083}): " port_ss
    
    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}

    # 端口检测省略以保持简洁，生产环境建议保留

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

    # 保存配置
    mkdir -p "$CONF_DIR"
    # 如果已存在 custom_uuid 则保留
    [ -f "$CONF_FILE" ] && grep "UUID_CUSTOM" "$CONF_FILE" > /tmp/xray_custom_uuid_backup
    
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
    
    # 恢复 Custom UUID 如果有
    if [ -f /tmp/xray_custom_uuid_backup ]; then
        cat /tmp/xray_custom_uuid_backup >> "$CONF_FILE"
        rm /tmp/xray_custom_uuid_backup
    fi
    
    # 初次安装不生成 UUID_CUSTOM，除非通过 add_custom_outbound 添加
    source "$CONF_FILE"
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "$UUID_CUSTOM"
    create_service

    echo -e "${GREEN}✅ 安装完成${NC}"
}

add_custom_outbound() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"

    echo -e "\n=== 添加自定义出站 (转发) ==="
    echo -e "请输入 Xray 分享链接 (支持 VMess / Shadowsocks):"
    read -r link_input
    
    if [ -z "$link_input" ]; then echo "取消操作"; return; fi

    if parse_outbound_link "$link_input"; then
        echo -e "${GREEN}✅ 链接解析成功${NC}"
        
        # 生成专用 UUID
        if [ -z "$UUID_CUSTOM" ]; then
            UUID_CUSTOM=$("$XRAY_BIN" uuid)
            echo "UUID_CUSTOM=$UUID_CUSTOM" >> "$CONF_FILE"
        fi
        
        # 重新生成配置
        generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$CFG_SS_CIPHER" "$UUID_CUSTOM"
        systemctl restart xray-proxya
        echo -e "${GREEN}✅ 配置已更新。${NC}"
        echo -e "现在 '查看链接' 菜单中将包含自定义出站选项。"
    else
        echo -e "${RED}❌ 解析失败或不支持的链接格式${NC}"
    fi
    read -n 1 -s -r -p "按任意键返回..."
}

format_ip() {
    local ip=$1
    if [[ "$ip" =~ .*:.* ]]; then echo "[$ip]"; else echo "$ip"; fi
}

print_links_for_uuid() {
    local target_uuid=$1
    local title=$2
    local ip_addr=$3
    
    local fmt_ip=$(format_ip "$ip_addr")
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    
    # VMess
    local vmess_json=$(jq -n \
      --arg add "$ip_addr" --arg port "$PORT_VMESS" --arg id "$target_uuid" --arg path "$PATH_VM" --arg scy "$vm_cipher" --arg ps "$title" \
      '{v:"2", ps:$ps, add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
    local vmess_link="vmess://$(echo -n "$vmess_json" | base64 -w 0)"

    # VLESS
    local vless_link="vless://$target_uuid@$fmt_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#$title"

    echo -e "   🔗 VMess:  ${GREEN}$vmess_link${NC}"
    echo -e "   🔗 VLESS:  ${GREEN}$vless_link${NC}"
}

show_links_menu() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    
    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || echo "")
    
    # 判断是否有自定义出站
    if [ -n "$UUID_CUSTOM" ] && [ -f "$CUSTOM_OUT_FILE" ]; then
        while true; do
            echo -e "\n--- 选择出站模式 ---"
            echo "1. 直接出站 (Direct)"
            echo "2. 自定义出站 (转发)"
            echo "q. 返回上级"
            read -p "选择: " sl_choice
            
            case "$sl_choice" in
                1) 
                    echo -e "\n${BLUE}--- 直接出站 (IPv4: $ipv4) ---${NC}"
                    print_links_for_uuid "$UUID" "Direct-Out" "$ipv4"
                    # SS 仅用于直连
                    local ss_auth=$(echo -n "${CFG_SS_CIPHER}:$PASS_SS" | base64 -w 0)
                    echo -e "   🔗 SS:     ${GREEN}ss://$ss_auth@$(format_ip $ipv4):$PORT_SS#SS-Direct${NC}"
                    read -n 1 -s -r -p "按任意键..."
                    ;;
                2)
                    echo -e "\n${BLUE}--- 自定义转发 (IPv4: $ipv4) ---${NC}"
                    echo -e "${YELLOW}注: 仅 VMess/VLESS 支持自定义转发路由${NC}"
                    print_links_for_uuid "$UUID_CUSTOM" "Custom-Out" "$ipv4"
                    read -n 1 -s -r -p "按任意键..."
                    ;;
                q) return ;;
                *) echo "无效" ;;
            esac
        done
    else
        # 仅直接出站
        echo -e "\n${BLUE}--- 配置链接 (IPv4: $ipv4) ---${NC}"
        print_links_for_uuid "$UUID" "Direct-Out" "$ipv4"
        local ss_auth=$(echo -n "${CFG_SS_CIPHER}:$PASS_SS" | base64 -w 0)
        echo -e "   🔗 SS:     ${GREEN}ss://$ss_auth@$(format_ip $ipv4):$PORT_SS#SS-Direct${NC}"
        read -n 1 -s -r -p "按任意键返回..."
    fi
}

uninstall_xray() {
    echo -e "${YELLOW}⚠️  警告: 将卸载 Xray 服务。${NC}"
    read -p "默认保留配置和核心文件? (N 删除核心 / y 仅删服务) [N/y]: " keep_core
    # 逻辑反转：Prompt说默认N (即删除)，这里按通常习惯 N=No Keep=Delete All?
    # 按照 Prompt: "默认 N (即不保留?不，通常 No 是 default answer)，需要清除系统服务，并询问是否移除 Core"
    
    systemctl stop xray-proxya
    systemctl disable xray-proxya
    rm "$SERVICE_FILE"
    systemctl daemon-reload
    echo -e "${GREEN}服务文件已移除。${NC}"

    if [[ "$keep_core" =~ ^[Yy]$ ]]; then
        echo "Xray 核心文件已保留。"
    else
        rm -rf "$XRAY_DIR"
        rm -rf "$CONF_DIR"
        echo "Xray 核心与配置已移除。"
    fi
    echo -e "${GREEN}✅ 卸载完成${NC}"
    exit 0
}

# --- 主菜单 ---
check_root

while true; do
    echo -e "\n${BLUE}Xray-Proxya [Test Build]${NC}"
    if systemctl is-active --quiet xray-proxya; then
        echo -e "状态: ${GREEN}运行中${NC}"
    else
        echo -e "状态: ${RED}停止${NC}"
    fi
    
    echo "1. 安装 / 重置"
    echo "2. 查看链接"
    echo "3. 添加自定义出站 (转发)"
    echo "4. 服务维护"
    echo "0. 卸载"
    echo "q. 退出"
    read -p "选择: " choice

    case "$choice" in
        1) install_xray ;;
        2) show_links_menu ;;
        3) add_custom_outbound ;;
        4) 
           echo "1.Start 2.Stop 3.Restart q.Back"
           read -p "> " svc_c
           case "$svc_c" in
             1) systemctl start xray-proxya ;;
             2) systemctl stop xray-proxya ;;
             3) systemctl restart xray-proxya ;;
             q) ;;
           esac
           ;;
        0) uninstall_xray ;;
        q) exit 0 ;;
        *) echo "无效" ;;
    esac
done
