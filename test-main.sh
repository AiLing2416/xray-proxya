#!/bin/bash

# ==================================================
# Xray-Proxya Manager
# ==================================================

# --- 加密配置 ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"
# ----------------

CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
ROTATE_STATE="$CONF_DIR/rotate.state"
ROTATE_SCRIPT="/usr/local/sbin/xray-rotate"
XRAY_BIN="/usr/local/bin/xray-proxya-core/xray"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
JSON_FILE="$XRAY_DIR/config.json"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
TIMER_FILE="/etc/systemd/system/xray-rotate.timer"
ROTATE_SVC_FILE="/etc/systemd/system/xray-rotate.service"

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
    apt-get install -y curl jq unzip openssl python3 >/dev/null 2>&1
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
    local ss_method=${10}
    local priority=${11:-4} # 4 or 6

    # 确定域名解析策略
    local domain_strat="UseIPv4"
    if [ "$priority" == "6" ]; then
        domain_strat="UseIPv6"
    fi

    cat > "$JSON_FILE" <<EOF
{
  "log": { "loglevel": "warning" },
  "routing": {
    "domainStrategy": "$domain_strat",
    "rules": [
      { "type": "field", "ip": [ "geoip:private" ], "outboundTag": "blocked" }
    ]
  },
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
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "blocked", "protocol": "blackhole" }
  ]
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

# --- IPv6 轮换逻辑 ---

create_rotate_script() {
    local cidr=$1
    local interface=$2
    
    cat > "$ROTATE_SCRIPT" <<EOF
#!/bin/bash
# 自动生成的新 IPv6 绑定并重载 Xray

CIDR="$cidr"
IFACE="$interface"
STATE_FILE="$ROTATE_STATE"
JSON_FILE="$JSON_FILE"

# 1. 使用 Python 生成 CIDR 内的随机 IP
NEW_IP=\$(python3 -c "import ipaddress, random; net = ipaddress.IPv6Network('$cidr', strict=False); print(ipaddress.IPv6Address(net.network_address + random.getrandbits(net.max_prefixlen - net.prefixlen)))")

if [ -z "\$NEW_IP" ]; then
    echo "IP 生成失败"
    exit 1
fi

echo "生成新 IP: \$NEW_IP"

# 2. 绑定新 IP (preferred_lft 0 防止被系统作为默认出口，仅供 Xray 指定使用)
ip addr add "\$NEW_IP/128" dev "\$IFACE" preferred_lft 0

# 3. 清理旧 IP
if [ -f "\$STATE_FILE" ]; then
    OLD_IP=\$(cat "\$STATE_FILE")
    if [ ! -z "\$OLD_IP" ]; then
        echo "清理旧 IP: \$OLD_IP"
        ip addr del "\$OLD_IP/128" dev "\$IFACE" 2>/dev/null
    fi
fi

# 4. 保存新 IP 状态
echo "\$NEW_IP" > "\$STATE_FILE"

# 5. 更新 config.json 的 sendThrough
# 这里我们假设 default outbound 是列表中的第一个 (index 0)
tmp_json=\$(mktemp)
jq --arg ip "\$NEW_IP" '.outbounds[0].sendThrough = \$ip' "\$JSON_FILE" > "\$tmp_json" && mv "\$tmp_json" "\$JSON_FILE"

# 6. 重启服务
systemctl restart xray-proxya
echo "轮换完成"
EOF
    chmod 755 "$ROTATE_SCRIPT"
}

setup_rotation() {
    echo -e "=== IPv6 动态轮换设置 ==="
    
    # 检测 IPv6
    if ! ip -6 addr | grep -q "inet6"; then
        echo -e "${RED}❌ 未检测到 IPv6 环境，无法开启。${NC}"
        return
    fi
    
    # 自动探测网卡
    DEFAULT_IFACE=$(ip -6 route show default | awk '/dev/ {print $5}' | head -n1)
    read -p "网卡接口名称 (默认 ${DEFAULT_IFACE:-eth0}): " iface
    IFACE=${iface:-${DEFAULT_IFACE:-eth0}}

    echo -e "请输入 IPv6 CIDR (如 2001:db8::/64 或 /112)"
    read -p "CIDR: " cidr
    if [[ ! "$cidr" =~ .*:.*\/[0-9]+ ]]; then
        echo -e "${RED}❌ 格式错误 (示例: 2001:db8::/64)${NC}"
        return
    fi

    read -p "轮换间隔 (分钟, 默认 60): " interval
    INTERVAL=${interval:-60}

    # 创建执行脚本
    create_rotate_script "$cidr" "$IFACE"

    # 创建 Systemd Service
    cat > "$ROTATE_SVC_FILE" <<EOF
[Unit]
Description=Xray IPv6 Rotation
After=network.target

[Service]
Type=oneshot
ExecStart=$ROTATE_SCRIPT
EOF

    # 创建 Systemd Timer
    cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Run Xray IPv6 Rotation every $INTERVAL minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=${INTERVAL}min
Unit=xray-rotate.service

[Install]
WantedBy=timers.target
EOF

    # 保存配置变量
    if grep -q "ROTATION_ENABLED" "$CONF_FILE"; then
        sed -i "s/^ROTATION_ENABLED=.*/ROTATION_ENABLED=true/" "$CONF_FILE"
    else
        echo "ROTATION_ENABLED=true" >> "$CONF_FILE"
    fi
    echo "ROTATION_CIDR=$cidr" >> "$CONF_FILE"
    echo "ROTATION_IFACE=$IFACE" >> "$CONF_FILE"

    systemctl daemon-reload
    systemctl enable --now xray-rotate.timer
    
    echo -e "${GREEN}✅ 轮换已开启。${NC}"
    echo -e "正在执行第一次轮换测试..."
    $ROTATE_SCRIPT
}

stop_rotation() {
    systemctl disable --now xray-rotate.timer 2>/dev/null
    systemctl stop xray-rotate.service 2>/dev/null
    
    # 清理残留 IP
    if [ -f "$ROTATE_STATE" ]; then
        OLD_IP=$(cat "$ROTATE_STATE")
        if [ ! -z "$OLD_IP" ] && [ -f "$CONF_FILE" ]; then
            source "$CONF_FILE"
            ip addr del "$OLD_IP/128" dev "$ROTATION_IFACE" 2>/dev/null
        fi
        rm "$ROTATE_STATE"
    fi
    
    # 移除 sendThrough
    tmp_json=$(mktemp)
    jq 'del(.outbounds[0].sendThrough)' "$JSON_FILE" > "$tmp_json" && mv "$tmp_json" "$JSON_FILE"
    systemctl restart xray-proxya
    
    if grep -q "ROTATION_ENABLED" "$CONF_FILE"; then
        sed -i "s/^ROTATION_ENABLED=.*/ROTATION_ENABLED=false/" "$CONF_FILE"
    fi
    
    echo -e "${YELLOW}已关闭轮换并恢复默认配置。${NC}"
}

# --- 主逻辑 ---

install_xray() {
    echo -e "=== 安装向导 ==="
    echo -e "算法: VMess [${YELLOW}$VMESS_CIPHER${NC}] | SS [${YELLOW}$SS_CIPHER${NC}]"
    
    read -p "VMess 端口 (默认 ${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (默认 ${vlessp:-8082}): " port_vl
    read -p "SS    端口 (默认 ${ssocks:-8083}): " port_ss
    echo -e "优先出站协议: [4] IPv4 / [6] IPv6"
    read -p "选择 (默认 4): " priority
    
    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}
    IP_PRIORITY=${priority:-4}

    for p in $PORT_VMESS $PORT_VLESS $PORT_SS; do
        if ss -lnt | grep -q ":$p "; then 
            echo -e "${RED}⚠️  端口 $p 被占用${NC}"; return
        fi
    done

    install_deps
    download_core

    echo -e "${BLUE}🔑 生成密钥...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(openssl rand -hex 12)"
    PATH_VL="/$(openssl rand -hex 12)"
    PASS_SS=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 24)
    
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"decryption":' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"encryption":' | cut -d '"' -f 4)

    if [ -z "$DEC_KEY" ]; then echo -e "${RED}❌ 密钥生成失败${NC}"; return 1; fi

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
IP_PRIORITY=$IP_PRIORITY
EOF

    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "$IP_PRIORITY"
    create_service

    echo -e "${GREEN}✅ 安装完成${NC}"
    show_links
}

format_ip() {
    local ip=$1
    if [[ "$ip" =~ .*:.* ]]; then echo "[$ip]"; else echo "$ip"; fi
}

print_config_group() {
    local ip_addr=$1
    local label=$2
    if [ -z "$ip_addr" ]; then return; fi
    local fmt_ip=$(format_ip "$ip_addr")
    
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_cipher=${CFG_SS_CIPHER:-$SS_CIPHER}

    local vmess_json=$(jq -n \
      --arg add "$ip_addr" --arg port "$PORT_VMESS" --arg id "$UUID" --arg path "$PATH_VM" --arg scy "$vm_cipher" \
      '{v:"2", ps:("VMess-" + $scy), add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
    local vmess_link="vmess://$(echo -n "$vmess_json" | base64 -w 0)"

    local vless_link="vless://$UUID@$fmt_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#VLESS-XHTTP-ENC"

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
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    
    echo -e "🔑 UUID: ${YELLOW}$UUID${NC}"
    echo -e "🔐 SS 密码: ${YELLOW}$PASS_SS${NC}"
    echo -e "⚖️  出站优先: $([ "$IP_PRIORITY" == "6" ] && echo "IPv6" || echo "IPv4")"

    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    local ipv6=$(curl -s -6 --max-time 2 https://ifconfig.co)

    if [ -n "$ipv4" ]; then print_config_group "$ipv4" "IPv4 配置"; fi
    if [ -n "$ipv6" ]; then print_config_group "$ipv6" "IPv6 配置"; fi
    
    if systemctl is-active --quiet xray-rotate.timer; then
        echo -e "\n🌀 ${GREEN}IPv6 轮换已开启${NC}"
    fi
}

change_ports() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    
    read -p "新 VMess (${PORT_VMESS}): " new_vm
    read -p "新 VLESS (${PORT_VLESS}): " new_vl
    read -p "新 SS    (${PORT_SS}): " new_ss
    read -p "新优先 (4/6, 当前 $IP_PRIORITY): " new_p
    
    [[ ! -z "$new_vm" ]] && sed -i "s/^PORT_VMESS=.*/PORT_VMESS=$new_vm/" "$CONF_FILE"
    [[ ! -z "$new_vl" ]] && sed -i "s/^PORT_VLESS=.*/PORT_VLESS=$new_vl/" "$CONF_FILE"
    [[ ! -z "$new_ss" ]] && sed -i "s/^PORT_SS=.*/PORT_SS=$new_ss/" "$CONF_FILE"
    [[ ! -z "$new_p" ]] && sed -i "s/^IP_PRIORITY=.*/IP_PRIORITY=$new_p/" "$CONF_FILE"
    
    source "$CONF_FILE"
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_cipher=${CFG_SS_CIPHER:-$SS_CIPHER}
    
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$ss_cipher" "$IP_PRIORITY"
    
    # 保持 sendThrough 配置
    if systemctl is-active --quiet xray-rotate.timer; then
        $ROTATE_SCRIPT
    else
        systemctl restart xray-proxya
    fi
    echo -e "${GREEN}✅ 已更新${NC}"
}

maintenance_menu() {
    while true; do
        echo -e "\n=== 服务维护 ==="
        echo "1. 启动服务"
        echo "2. 停止服务"
        echo "3. 重启服务"
        echo "4. 开机自启 (Enable)"
        echo "5. 取消自启 (Disable)"
        echo "0. 返回"
        read -p "选择: " m_choice
        case "$m_choice" in
            1) systemctl start xray-proxya && echo "已启动" ;;
            2) systemctl stop xray-proxya && echo "已停止" ;;
            3) systemctl restart xray-proxya && echo "已重启" ;;
            4) systemctl enable xray-proxya && echo "已Enable" ;;
            5) systemctl disable xray-proxya && echo "已Disable" ;;
            0) return ;;
            *) echo -e "${RED}无效${NC}" ;;
        esac
    done
}

rotate_menu() {
    while true; do
        echo -e "\n=== IPv6 轮换 (Beta) ==="
        if systemctl is-active --quiet xray-rotate.timer; then
            echo -e "状态: ${GREEN}运行中${NC}"
        else
            echo -e "状态: ${RED}未开启${NC}"
        fi
        echo "1. 开启 / 修改设置"
        echo "2. 关闭轮换"
        echo "3. 立即触发一次"
        echo "0. 返回"
        read -p "选择: " r_choice
        case "$r_choice" in
            1) setup_rotation ;;
            2) stop_rotation ;;
            3) if [ -f "$ROTATE_SCRIPT" ]; then $ROTATE_SCRIPT; else echo "未配置"; fi ;;
            0) return ;;
            *) echo -e "${RED}无效${NC}" ;;
        esac
    done
}

uninstall_xray() {
    read -p "确认卸载? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi
    stop_rotation
    systemctl stop xray-proxya
    systemctl disable xray-proxya
    rm "$SERVICE_FILE" "$TIMER_FILE" "$ROTATE_SVC_FILE" "$ROTATE_SCRIPT" 2>/dev/null
    rm -rf "$XRAY_DIR" "$CONF_DIR"
    systemctl daemon-reload
    echo -e "${GREEN}✅ 已卸载${NC}"
}

check_root
echo -e "${BLUE}Xray-Proxya 管理${NC}"
check_status
echo -e ""
echo "1. 安装 / 重置"
echo "2. 查看链接"
echo "3. 修改配置 (端口/优先级)"
echo "4. 服务维护"
echo "5. IPv6 轮换 (Beta)"
echo "6. 卸载"
echo "0. 退出"
read -p "选择: " choice

case "$choice" in
    1) install_xray ;;
    2) show_links ;;
    3) change_ports ;;
    4) maintenance_menu ;;
    5) rotate_menu ;;
    6) uninstall_xray ;;
    0) exit 0 ;;
    *) echo -e "${RED}无效${NC}" ;;
esac