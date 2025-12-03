#!/bin/bash

# ==================================================
# Xray-Proxya Manager (Beta v5 - Dashboard Optimized)
# ==================================================

# --- 用户配置变量 ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"
# 如自动识别错误，在此填入物理网卡名称 (如 "eth0")
FORCE_IFACE="" 
# ------------------

CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
ROTATION_CONF="$CONF_DIR/rotation.env"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
XRAY_BIN="$XRAY_DIR/xray"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
JSON_FILE="$XRAY_DIR/config.json"
ROTATION_SCRIPT="$XRAY_DIR/rotate_ipv6.sh"
CURRENT_IP_FILE="$CONF_DIR/current_ipv6"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

check_root() {
    if [ "$EUID" -ne 0 ]; then echo -e "${RED}❌ 需要 root 权限${NC}"; exit 1; fi
}

check_deps() {
    local deps=("curl" "jq" "openssl" "python3" "ip")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo -e "${YELLOW}正在安装依赖: $dep ...${NC}"
            apt-get update -qq && apt-get install -y $dep >/dev/null 2>&1
        fi
    done
}

# --- 网络信息获取 (纯本地，不联网) ---

get_local_net_info() {
    # 1. 识别物理网卡 (NDP 绑定目标)
    if [ -n "$FORCE_IFACE" ]; then
        DEFAULT_IFACE="$FORCE_IFACE"
    else
        # 排除回环、点对点(WARP)、虚拟接口，寻找物理接口
        DEFAULT_IFACE=$(ip -o link show up \
            | grep -v "LOOPBACK" | grep -v "POINTOPOINT" | grep -v "noqueue" \
            | grep -vE ": (docker|br-|veth|tun|wg)" \
            | awk -F': ' '{print $2}' | head -n 1)
        
        # 兜底
        if [ -z "$DEFAULT_IFACE" ]; then
            DEFAULT_IFACE=$(ip -6 -o addr show scope global | grep -vE "^(lo|warp|wg|tun|docker|br-|veth)" | head -n 1 | awk '{print $2}')
        fi
        [ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE="eth0"
    fi
    
    # 2. 获取该接口的物理 IP (基准 IP)
    MAIN_IPV4=$(ip -4 addr show dev "$DEFAULT_IFACE" | grep inet | awk '{print $2}' | head -n 1 | cut -d/ -f1)
    MAIN_IPV6=$(ip -6 addr show dev "$DEFAULT_IFACE" scope global | grep inet6 | awk '{print $2}' | head -n 1 | cut -d/ -f1)
    
    # 3. 读取配置的轮换 IP (理论值)
    if [ -f "$CURRENT_IP_FILE" ]; then
        ROTATING_IP=$(cat "$CURRENT_IP_FILE")
    else
        ROTATING_IP="未激活"
    fi

    # 4. 读取优先级配置
    if [ -f "$CONF_FILE" ]; then
        # 仅提取 PRIORITY 变量
        CURRENT_PRIORITY=$(grep "^PRIORITY=" "$CONF_FILE" | cut -d= -f2)
    else
        CURRENT_PRIORITY="N/A"
    fi
}

show_dashboard() {
    get_local_net_info
    clear
    echo -e "${BLUE}==================================================${NC}"
    echo -e "           Xray-Proxya 管理面板 (Beta v5)"
    echo -e "${BLUE}==================================================${NC}"
    
    # 1. 物理层信息
    echo -e "📡 主接口 (Physical): ${CYAN}$DEFAULT_IFACE${NC}"
    echo -e "   ├─ 物理 IPv4: ${YELLOW}${MAIN_IPV4:-无}${NC}"
    echo -e "   └─ 物理 IPv6: ${YELLOW}${MAIN_IPV6:-无}${NC}"
    
    echo -e "\n⚙️  出站配置状态 (理论值):"
    
    # 2. 轮换状态
    if systemctl is-active --quiet xray-rotate.timer; then
        echo -e "   ├─ IPv6 轮换:    [ ${GREEN}开启${NC} ] (当前: ${CYAN}$ROTATING_IP${NC})"
    else
        echo -e "   ├─ IPv6 轮换:    [ ${YELLOW}关闭${NC} ]"
    fi
    
    # 3. 优先级状态
    if [[ "$CURRENT_PRIORITY" == "ipv6" ]]; then
        echo -e "   └─ 流量优先级:   [ ${GREEN}IPv6 轮换优先${NC} ]"
    else
        echo -e "   └─ 流量优先级:   [ ${BLUE}IPv4/系统默认${NC} ]"
    fi
    
    echo -e "\n📊 系统服务:"
    if systemctl is-active --quiet xray-proxya; then
        echo -e "   └─ Xray Core:    [ ${GREEN}运行中${NC} ]"
    else
        echo -e "   └─ Xray Core:    [ ${RED}已停止${NC} ]"
    fi
    
    echo -e "${BLUE}==================================================${NC}"
}

# --- 核心功能 ---

install_core() {
    if [ -f "$XRAY_BIN" ]; then return 0; fi
    echo -e "${BLUE}⬇️  准备 Xray Core...${NC}"
    if ! curl -s -I --connect-timeout 5 https://api.github.com >/dev/null; then
        echo -e "${RED}⚠️  GitHub API 连接失败${NC}"
        echo -e "请手动上传 'xray' 文件到: ${YELLOW}$XRAY_DIR${NC}"
        read -p "完成上传后按回车..."
        [ ! -f "$XRAY_BIN" ] && exit 1
        chmod +x "$XRAY_BIN"
    else
        LATEST_URL=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
        mkdir -p "$XRAY_DIR"
        curl -L -o /tmp/xray.zip "$LATEST_URL"
        unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
        rm /tmp/xray.zip
        chmod +x "$XRAY_BIN"
    fi
}

generate_config() {
    local vmess_p=$1 vless_p=$2 ss_p=$3 uuid=$4 vmess_path=$5 vless_path=$6 
    local enc_key=$7 dec_key=$8 ss_pass=$9 ss_method=${10} priority=${11:-ipv4}

    local route_tag="outbound-ipv4"
    [[ "$priority" == "ipv6" ]] && route_tag="outbound-ipv6"

    cat > "$JSON_FILE" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vmess-in", "port": $vmess_p, "protocol": "vmess",
      "settings": { "clients": [ { "id": "$uuid", "level": 0 } ] },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "$vmess_path" } }
    },
    {
      "tag": "vless-enc-in", "port": $vless_p, "protocol": "vless",
      "settings": { "clients": [ { "id": "$uuid", "level": 0 } ], "decryption": "$dec_key" },
      "streamSettings": { "network": "xhttp", "xhttpSettings": { "path": "$vless_path" } }
    },
    {
      "tag": "shadowsocks-in", "port": $ss_p, "protocol": "shadowsocks",
      "settings": { "method": "$ss_method", "password": "$ss_pass", "network": "tcp,udp" }
    },
    {
      "tag": "test-in", "port": 10086, "listen": "127.0.0.1", "protocol": "http", "settings": {} }
  ],
  "outbounds": [
    { "tag": "outbound-ipv4", "protocol": "freedom", "settings": { "domainStrategy": "UseIP" } },
    { "tag": "outbound-ipv6", "protocol": "freedom", "settings": { "domainStrategy": "UseIPv6" } }
  ],
  "routing": {
    "rules": [
      { "type": "field", "inboundTag": ["test-in"], "outboundTag": "outbound-ipv6" },
      { "type": "field", "network": "udp,tcp", "outboundTag": "$route_tag" }
    ]
  }
}
EOF
}

# --- IPv6 轮换模块 ---

test_rotation_connectivity() {
    echo -e "\n=== 轮换 IP 连通性测试 ==="
    
    if [ ! -f "$CURRENT_IP_FILE" ]; then
        echo -e "${RED}❌ 当前未配置轮换 IP。请先进行设置。${NC}"
        read -p "按回车返回..."
        return
    fi
    
    TARGET_IP=$(cat "$CURRENT_IP_FILE")
    echo -e "理论出站 IP: ${CYAN}$TARGET_IP${NC}"
    echo -e "正在通过本地代理 (127.0.0.1:10086) 测试..."
    
    # 使用 curl 通过本地代理访问，强制走 outbound-ipv6
    REAL_IP=$(curl -x http://127.0.0.1:10086 -s --max-time 8 https://ipconfig.me || echo "Error")
    
    echo -e "---------------------------------"
    if [[ "$REAL_IP" == *"$TARGET_IP"* ]]; then
        echo -e "测试结果: ${GREEN}成功 ✅${NC}"
        echo -e "实际 IP:  $REAL_IP"
        echo -e "说明: 配置已生效，出站流量正通过轮换 IP 发送。"
    else
        echo -e "测试结果: ${RED}失败 ❌${NC}"
        echo -e "实际 IP:  $REAL_IP"
        echo -e "说明: 可能 CIDR 配置错误、被商家拦截或 NDP 尚未广播生效。"
    fi
    echo -e "---------------------------------"
    read -p "按回车返回..."
}

setup_rotation_logic() {
    get_local_net_info # 刷新接口变量
    echo -e "\n=== 设置 IPv6 轮换 ==="
    echo -e "目标接口: ${GREEN}$DEFAULT_IFACE${NC}"
    
    read -p "确认接口? (y/n): " c
    if [[ "$c" == "n" ]]; then
        read -p "输入接口名: " DEFAULT_IFACE
    fi
    
    read -p "输入 CIDR (如 2a00:f48::/64): " user_cidr
    if ! python3 -c "import ipaddress; ipaddress.IPv6Network('$user_cidr', strict=False)" 2>/dev/null; then
        echo -e "${RED}无效 CIDR${NC}"; read -p ""; return
    fi
    
    echo -e "优先级: [1] IPv4优先  [2] IPv6轮换优先"
    read -p "选择: " pri
    local pv="ipv4"; [[ "$pri" == "2" ]] && pv="ipv6"
    
    read -p "间隔 (分): " intv
    [[ ! "$intv" =~ ^[0-9]+$ ]] && intv=60
    
    # 写入轮换脚本
    cat > "$ROTATION_SCRIPT" <<EOF
#!/bin/bash
source $CONF_DIR/rotation.env
XRAY_CFG="$JSON_FILE"
LOG_FILE="/var/log/xray-proxya-rotation.log"
log() { echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> "\$LOG_FILE"; }

NEW_IP=\$(python3 -c "import ipaddress, random; net=ipaddress.IPv6Network('$user_cidr', strict=False); print(ipaddress.IPv6Address(random.randint(int(net.network_address), int(net.broadcast_address))))")

log "Binding \$NEW_IP to $DEFAULT_IFACE"
ip -6 addr add "\$NEW_IP/128" dev "$DEFAULT_IFACE" preferred_lft 0

# Update Xray
tmp_json=\$(mktemp)
jq --arg ip "\$NEW_IP" '(.outbounds[] | select(.tag=="outbound-ipv6").sendThrough) = \$ip' "\$XRAY_CFG" > "\$tmp_json" && mv "\$tmp_json" "\$XRAY_CFG"

systemctl restart xray-proxya

# Auto-Check
CHECK_IP=\$(curl -x http://127.0.0.1:10086 -s --max-time 5 https://ipconfig.me || echo "fail")
if [[ "\$CHECK_IP" == *"\$NEW_IP"* ]]; then
    log "OK: \$NEW_IP"
    if [ -f "$CURRENT_IP_FILE" ]; then
        OLD_IP=\$(cat "$CURRENT_IP_FILE")
        ip -6 addr del "\$OLD_IP/128" dev "$DEFAULT_IFACE" 2>/dev/null
    fi
    echo "\$NEW_IP" > "$CURRENT_IP_FILE"
else
    log "FAIL: Got \$CHECK_IP"
    ip -6 addr del "\$NEW_IP/128" dev "$DEFAULT_IFACE"
    # Revert logic can go here
fi
EOF
    chmod +x "$ROTATION_SCRIPT"
    echo "DEFAULT_IFACE=$DEFAULT_IFACE" > "$ROTATION_CONF"
    
    sed -i "s/^PRIORITY=.*/PRIORITY=$pv/" "$CONF_FILE"
    source "$CONF_FILE"
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "$pv"

    cat > "/etc/systemd/system/xray-rotate.service" <<EOF
[Unit]
Description=Xray Rotation
[Service]
Type=oneshot
ExecStart=$ROTATION_SCRIPT
EOF
    cat > "/etc/systemd/system/xray-rotate.timer" <<EOF
[Unit]
Description=Timer for Xray Rotation
[Timer]
OnBootSec=2min
OnUnitActiveSec=${intv}min
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now xray-rotate.timer
    
    echo -e "${GREEN}✅ 设置完成，正在生成第一个 IP...${NC}"
    bash "$ROTATION_SCRIPT"
    echo -e "完成。请使用测试功能验证。"
    read -p "按回车返回..."
}

ipv6_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== IPv6 轮换管理 ===${NC}"
        echo "1. 设置 / 更新轮换策略"
        echo "2. 手动测试连通性 (本地代理)"
        echo "0. 返回主菜单"
        read -p "选择: " c
        case "$c" in
            1) 
               if [ ! -f "$CONF_FILE" ]; then echo "请先安装主服务"; read -p ""; return; fi
               source "$CONF_FILE"; setup_rotation_logic ;;
            2) test_rotation_connectivity ;;
            0) return ;;
        esac
    done
}

# --- 主安装 ---

install_xray() {
    echo -e "\n=== 安装向导 ==="
    check_deps
    
    read -p "VMess (Def ${vmessp:-8081}): " pm
    read -p "VLESS (Def ${vlessp:-8082}): " pl
    read -p "SS    (Def ${ssocks:-8083}): " ps
    PORT_VMESS=${pm:-${vmessp:-8081}}; PORT_VLESS=${pl:-${vlessp:-8082}}; PORT_SS=${ps:-${ssocks:-8083}}

    if ss -lnt | grep -q -E ":($PORT_VMESS|$PORT_VLESS|$PORT_SS) "; then echo "端口占用"; return; fi

    get_local_net_info
    install_core

    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(openssl rand -hex 12)"; PATH_VL="/$(openssl rand -hex 12)"
    PASS_SS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
    
    RAW=$("$XRAY_BIN" vlessenc)
    DEC=$(echo "$RAW" | grep -A 5 "ML-KEM" | grep 'decryption' | cut -d '"' -f 4)
    ENC=$(echo "$RAW" | grep -A 5 "ML-KEM" | grep 'encryption' | cut -d '"' -f 4)
    
    mkdir -p "$CONF_DIR"
    cat > "$CONF_FILE" <<EOF
PORT_VMESS=$PORT_VMESS
PORT_VLESS=$PORT_VLESS
PORT_SS=$PORT_SS
UUID=$UUID
PATH_VM=$PATH_VM
PATH_VL=$PATH_VL
PASS_SS=$PASS_SS
ENC_KEY=$ENC
DEC_KEY=$DEC
PRIORITY=ipv4
CFG_VMESS_CIPHER=$VMESS_CIPHER
CFG_SS_CIPHER=$SS_CIPHER
EOF
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC" "$DEC" "$PASS_SS" "$SS_CIPHER" "ipv4"
    
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
    systemctl enable --now xray-proxya
    
    echo -e "${GREEN}✅ 安装完成${NC}"
    read -p "按回车继续..."
    show_links
}

show_links() {
    if [ ! -f "$CONF_FILE" ]; then echo "无配置"; return; fi
    source "$CONF_FILE"
    
    echo -e "\n🔑 UUID: ${YELLOW}$UUID${NC}"
    echo -e "正在获取外部 IP (需联网)..."
    local v4=$(curl -s -4 --max-time 3 https://ipconfig.me)
    local v6=$(curl -s -6 --max-time 3 https://ifconfig.co)
    
    print_l() {
        local ip=$1; local lbl=$2
        [ -z "$ip" ] && return
        local fmt=$ip; [[ "$ip" =~ : ]] && fmt="[$ip]"
        
        local vm_j=$(jq -n --arg i "$ip" --arg p "$PORT_VMESS" --arg u "$UUID" --arg pa "$PATH_VM" --arg s "$CFG_VMESS_CIPHER" \
            '{v:"2", ps:("VM-"+$s), add:$i, port:$p, id:$u, aid:"0", scy:$s, net:"ws", type:"none", host:"", path:$pa, tls:""}')
        echo -e "\n${BLUE}--- $lbl ($ip) ---${NC}"
        echo -e "VMess: vmess://$(echo -n "$vm_j" | base64 -w 0)"
        echo -e "VLESS: vless://$UUID@$fmt:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL#VLESS-ENC"
    }
    
    print_l "$v4" "IPv4"
    print_l "$v6" "IPv6"
    read -p "按回车返回..."
}

uninstall() {
    read -p "确认卸载? (y/n): " c
    [[ "$c" != "y" ]] && return
    systemctl stop xray-proxya xray-rotate.timer xray-rotate.service 2>/dev/null
    systemctl disable xray-proxya xray-rotate.timer xray-rotate.service 2>/dev/null
    
    # 清理 IP
    if [ -f "$CURRENT_IP_FILE" ]; then
        get_local_net_info
        OLD=$(cat "$CURRENT_IP_FILE")
        ip -6 addr del "$OLD/128" dev "$DEFAULT_IFACE" 2>/dev/null
    fi

    rm -rf "$XRAY_DIR" "$CONF_DIR" "/etc/systemd/system/xray-proxya.service" "/etc/systemd/system/xray-rotate.service" "/etc/systemd/system/xray-rotate.timer"
    systemctl daemon-reload
    echo "已卸载"
    exit 0
}

# --- Main ---
check_root
while true; do
    show_dashboard
    echo -e "\n1. 安装 / 重置"
    echo -e "2. 查看链接 (含真实 IP 检测)"
    echo -e "3. IPv6 轮换菜单 (Beta)"
    echo -e "4. 卸载"
    echo -e "0. 退出"
    read -p "选择: " choice
    case "$choice" in
        1) install_xray ;;
        2) show_links ;;
        3) ipv6_menu ;;
        4) uninstall ;;
        0) exit 0 ;;
    esac
done