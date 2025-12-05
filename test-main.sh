#!/bin/bash

# ==================================================
# Xray-Proxya Manager [BETA: Custom Outbound]
# ==================================================

# --- 配置变量 ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"

CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
XRAY_BIN="/usr/local/sbin/xray-proxya-core/xray" # Beta版建议也放在 sbin
XRAY_DIR="/usr/local/sbin/xray-proxya-core"
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
        # 简单检测是否启用了链式代理
        if [ -f "$CONF_FILE" ]; then
            source "$CONF_FILE"
            if [ -n "$CHAIN_JSON" ]; then
                echo -e "🔗 链式代理: ${GREEN}已启用${NC}"
            else
                echo -e "🔗 链式代理: ${YELLOW}未配置 (直接出站)${NC}"
            fi
        fi
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

# --- 核心逻辑: 配置文件生成 (支持双用户+路由) ---
generate_config() {
    local vmess_p=$1
    local vless_p=$2
    local ss_p=$3
    local uuid_direct=$4
    local uuid_chain=$5
    local vmess_path=$6
    local vless_path=$7
    local enc_key=$8
    local dec_key=$9
    local ss_pass=${10}
    local ss_method=${11}
    local chain_json=${12} # 自定义出站 JSON 字符串

    # 构建出站对象
    # 默认 Freedom
    local outbounds='[ { "protocol": "freedom", "tag": "direct" }'
    
    # 如果有自定义出站，则追加
    if [ -n "$chain_json" ]; then
        # 强制覆盖 tag 为 custom-out 以匹配路由
        local clean_chain=$(echo "$chain_json" | jq '. + {"tag": "custom-out"}')
        outbounds+=",$clean_chain"
    fi
    outbounds+=']'

    # 构建路由规则
    # user: chain -> custom-out
    local routing='{
        "domainStrategy": "AsIs",
        "rules": [
            { "type": "field", "user": ["chain"], "outboundTag": "custom-out" },
            { "type": "field", "user": ["direct"], "outboundTag": "direct" }
        ]
    }'
    # 如果没有自定义出站，所有流量走默认，路由规则其实也可以简化，但保留也无妨(会fallback到第一条freedom)

    cat > "$JSON_FILE" <<EOF
{
  "log": { "loglevel": "warning" },
  "routing": $routing,
  "inbounds": [
    {
      "tag": "vmess-in",
      "port": $vmess_p,
      "protocol": "vmess",
      "settings": { 
        "clients": [ 
            { "id": "$uuid_direct", "level": 0, "email": "direct" },
            { "id": "$uuid_chain", "level": 0, "email": "chain" }
        ] 
      },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "$vmess_path" } }
    },
    {
      "tag": "vless-enc-in",
      "port": $vless_p,
      "protocol": "vless",
      "settings": { 
        "clients": [ 
            { "id": "$uuid_direct", "level": 0, "email": "direct" },
            { "id": "$uuid_chain", "level": 0, "email": "chain" }
        ], 
        "decryption": "$dec_key" 
      },
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
  "outbounds": $outbounds
}
EOF
}

create_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Xray-Proxya Beta Service
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

# --- 解析 VMess 链接为 Xray JSON ---
parse_vmess_to_json() {
    local link=$1
    # 移除前缀 vmess://
    local b64="${link#*://}"
    # 解码
    local json=$(echo "$b64" | base64 -d 2>/dev/null)
    
    if [ -z "$json" ] || ! echo "$json" | jq . >/dev/null 2>&1; then
        echo "" # 解析失败
        return
    fi

    # 提取字段
    local add=$(echo "$json" | jq -r .add)
    local port=$(echo "$json" | jq -r .port)
    local id=$(echo "$json" | jq -r .id)
    local net=$(echo "$json" | jq -r .net)
    local path=$(echo "$json" | jq -r .path)
    local host=$(echo "$json" | jq -r .host)
    local tls=$(echo "$json" | jq -r .tls)

    # 构建 Xray Outbound JSON
    # 这是一个简化版构建，支持最常用的 WS/TCP
    jq -n \
    --arg add "$add" \
    --arg port "$port" \
    --arg id "$id" \
    --arg net "$net" \
    --arg path "$path" \
    --arg host "$host" \
    --arg tls "$tls" \
    '{
        protocol: "vmess",
        settings: {
            vnext: [{
                address: $add,
                port: ($port | tonumber),
                users: [{ id: $id }]
            }]
        },
        streamSettings: {
            network: $net,
            security: (if $tls == "tls" then "tls" else "none" end),
            wsSettings: (if $net == "ws" then {path: $path, headers: {Host: $host}} else null end)
        }
    }'
}

# --- 设置自定义出站 ---
setup_custom_outbound() {
    echo -e "\n=== 配置自定义出站 (转发流量) ==="
    echo -e "说明: 配置后，使用 [链式-UUID] 的入站流量将转发给此节点。"
    echo -e "1. 导入 VMess 链接 (支持标准 vmess://)"
    echo -e "2. 粘贴完整 Outbound JSON (高级, 支持 VLESS/Trojan/Socks)"
    echo -e "3. 清除自定义出站 (恢复直连)"
    read -p "选择: " opt

    local new_json=""

    if [ "$opt" == "1" ]; then
        read -p "请输入 vmess:// 链接: " link
        new_json=$(parse_vmess_to_json "$link")
        if [ -z "$new_json" ]; then
            echo -e "${RED}❌ 解析失败，请检查链接格式。${NC}"
            return
        fi
        echo -e "${GREEN}✅ VMess 链接解析成功！${NC}"

    elif [ "$opt" == "2" ]; then
        echo -e "请输入 JSON (以 { 开头, } 结尾, 单行):"
        read -r json_input
        if echo "$json_input" | jq . >/dev/null 2>&1; then
            new_json="$json_input"
            echo -e "${GREEN}✅ JSON 校验通过！${NC}"
        else
            echo -e "${RED}❌ JSON 格式错误。${NC}"
            return
        fi

    elif [ "$opt" == "3" ]; then
        new_json=""
        echo -e "${YELLOW}🧹 已清除自定义配置。${NC}"
    else
        return
    fi

    # 更新配置文件中的 CHAIN_JSON 变量
    # 使用 base64 存储 JSON 防止特殊字符破坏 config.env
    if [ -n "$new_json" ]; then
        local b64_json=$(echo "$new_json" | base64 -w 0)
        # 更新或追加
        if grep -q "CHAIN_JSON_B64=" "$CONF_FILE"; then
            sed -i "s|^CHAIN_JSON_B64=.*|CHAIN_JSON_B64=$b64_json|" "$CONF_FILE"
        else
            echo "CHAIN_JSON_B64=$b64_json" >> "$CONF_FILE"
        fi
    else
        sed -i "/^CHAIN_JSON_B64=/d" "$CONF_FILE"
    fi

    # 重新加载配置并应用
    source "$CONF_FILE"
    local chain_json_decoded=""
    if [ -n "$CHAIN_JSON_B64" ]; then
        chain_json_decoded=$(echo "$CHAIN_JSON_B64" | base64 -d)
    fi

    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$UUID_CHAIN" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$CFG_SS_CIPHER" "$chain_json_decoded"
    systemctl restart xray-proxya
    echo -e "${GREEN}✅ 配置已更新并重启服务。请在[查看链接]中获取链式专用节点。${NC}"
}

install_xray() {
    echo -e "=== 安装向导 (Beta) ==="
    
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

    echo -e "${BLUE}🔑 生成密钥 (含链式专用 UUID)...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    UUID_CHAIN=$("$XRAY_BIN" uuid) # 生成第二个 UUID
    
    PATH_VM="/$(openssl rand -hex 12)"
    PATH_VL="/$(openssl rand -hex 12)"
    PASS_SS=$(generate_random 24)
    
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"decryption":' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"encryption":' | cut -d '"' -f 4)

    mkdir -p "$CONF_DIR"
    cat > "$CONF_FILE" <<EOF
PORT_VMESS=$PORT_VMESS
PORT_VLESS=$PORT_VLESS
PORT_SS=$PORT_SS
UUID=$UUID
UUID_CHAIN=$UUID_CHAIN
PATH_VM=$PATH_VM
PATH_VL=$PATH_VL
PASS_SS=$PASS_SS
ENC_KEY=$ENC_KEY
DEC_KEY=$DEC_KEY
CFG_VMESS_CIPHER=$VMESS_CIPHER
CFG_SS_CIPHER=$SS_CIPHER
EOF

    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$UUID_CHAIN" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" ""
    create_service

    echo -e "${GREEN}✅ 安装完成${NC}"
    show_links
}

format_ip() {
    local ip=$1
    if [[ "$ip" =~ .*:.* ]]; then echo "[$ip]"; else echo "$ip"; fi
}

# 打印单个链接组
print_single_link_group() {
    local ip=$1
    local uuid=$2
    local label=$3
    local note=$4
    
    local fmt_ip=$(format_ip "$ip")
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    
    # VMess
    local vmess_json=$(jq -n \
      --arg add "$ip" --arg port "$PORT_VMESS" --arg id "$uuid" --arg path "$PATH_VM" --arg scy "$vm_cipher" --arg ps "VMess-$label" \
      '{v:"2", ps:$ps, add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
    local vmess_link="vmess://$(echo -n "$vmess_json" | base64 -w 0)"

    # VLESS
    local vless_link="vless://$uuid@$fmt_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#VLESS-$label"

    echo -e "🔹 $label ($note):"
    echo -e "   VMess: ${GREEN}$vmess_link${NC}"
    echo -e "   VLESS: ${GREEN}$vless_link${NC}"
}

show_links() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未找到配置${NC}"; return; fi
    source "$CONF_FILE"
    
    # 解码链式配置以判断是否显示
    local chain_status="未配置 (效果同直连)"
    if [ -n "$CHAIN_JSON_B64" ]; then chain_status="已启用 (转发至自定义出站)"; fi

    echo -e "\n${BLUE}=== 节点链接信息 ===${NC}"
    echo -e "🔑 主 UUID (直连): ${YELLOW}$UUID${NC}"
    echo -e "🔗 链 UUID (转发): ${YELLOW}$UUID_CHAIN${NC}"
    echo -e "📡 转发状态: $chain_status"

    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    
    if [ -n "$ipv4" ]; then
        echo -e "\n${BLUE}--- IPv4 入口 ($ipv4) ---${NC}"
        print_single_link_group "$ipv4" "$UUID" "Direct" "本机直连"
        echo ""
        print_single_link_group "$ipv4" "$UUID_CHAIN" "Custom" "自定义出站"
        
        # SS 只有直连 (SS 协议本身不支持 user routing 分流，除非多端口，此处仅展示主端口)
        local ss_auth=$(echo -n "${CFG_SS_CIPHER}:$PASS_SS" | base64 -w 0)
        local ss_link="ss://$ss_auth@$(format_ip $ipv4):$PORT_SS#SS-Direct"
        echo -e "\n🔹 Shadowsocks (仅直连):"
        echo -e "   ${GREEN}$ss_link${NC}"
    else
        echo -e "${RED}❌ 无法获取 IPv4${NC}"
    fi
}

change_ports() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    
    read -p "新 VMess (回车跳过): " new_vm
    read -p "新 VLESS (回车跳过): " new_vl
    read -p "新 SS    (回车跳过): " new_ss
    
    [[ ! -z "$new_vm" ]] && sed -i "s/^PORT_VMESS=.*/PORT_VMESS=$new_vm/" "$CONF_FILE"
    [[ ! -z "$new_vl" ]] && sed -i "s/^PORT_VLESS=.*/PORT_VLESS=$new_vl/" "$CONF_FILE"
    [[ ! -z "$new_ss" ]] && sed -i "s/^PORT_SS=.*/PORT_SS=$new_ss/" "$CONF_FILE"
    
    source "$CONF_FILE"
    local chain_json_decoded=""
    if [ -n "$CHAIN_JSON_B64" ]; then chain_json_decoded=$(echo "$CHAIN_JSON_B64" | base64 -d); fi
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_cipher=${CFG_SS_CIPHER:-$SS_CIPHER}
    
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$UUID_CHAIN" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$ss_cipher" "$chain_json_decoded"
    systemctl restart xray-proxya
    echo -e "${GREEN}✅ 端口已更新${NC}"
}

maintenance_menu() {
    while true; do
        echo -e "\n=== 服务维护 ==="
        echo "1. 启动 (Start)"
        echo "2. 停止 (Stop)"
        echo "3. 重启 (Restart)"
        echo "4. 开机自启 (Enable)"
        echo "5. 取消自启 (Disable)"
        echo "0. 返回"
        read -p "选择: " m_choice
        case "$m_choice" in
            1) systemctl start xray-proxya && echo "Done" ;;
            2) systemctl stop xray-proxya && echo "Done" ;;
            3) systemctl restart xray-proxya && echo "Done" ;;
            4) systemctl enable xray-proxya && echo "Done" ;;
            5) systemctl disable xray-proxya && echo "Done" ;;
            0) return ;;
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
echo -e "${BLUE}Xray-Proxya Manager [BETA]${NC}"
check_status
echo -e ""
echo "1. 安装 / 重置 (Beta)"
echo "2. 查看链接 (直连 & 链式)"
echo "3. 修改端口"
echo "4. 服务维护"
echo "5. 卸载"
echo "6. [Beta] 配置自定义出站 (链式代理)"
echo "0. 退出"
read -p "选择: " choice

case "$choice" in
    1) install_xray ;;
    2) show_links ;;
    3) change_ports ;;
    4) maintenance_menu ;;
    5) uninstall_xray ;;
    6) setup_custom_outbound ;;
    0) exit 0 ;;
    *) echo -e "${RED}无效${NC}" ;;
esac
