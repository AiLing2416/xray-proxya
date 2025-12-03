#!/bin/bash

# ==================================================
# Xray-Proxya Manager (Beta v4 - Complex Net Fix)
# ==================================================

# --- 用户配置变量 ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"
# 如果脚本依然识别错误，请在此手动指定物理网卡名称 (如 "eth0")
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

# --- 增强版网络探测 ---

get_net_info() {
    # 1. 尝试识别物理出站网卡 (用于绑定 IPv6)
    if [ -n "$FORCE_IFACE" ]; then
        DEFAULT_IFACE="$FORCE_IFACE"
    else
        # 逻辑: 列出所有网卡 -> 排除 回环/点对点(WARP)/Docker/网桥 -> 找第一个 UP 的
        # eth0 在你的输出中是 BROADCAST,MULTICAST,UP，而 warp 是 POINTOPOINT
        DEFAULT_IFACE=$(ip -o link show up \
            | grep -v "LOOPBACK" \
            | grep -v "POINTOPOINT" \
            | grep -v "noqueue" \
            | grep -vE ": (docker|br-|veth|tun|wg)" \
            | awk -F': ' '{print $2}' | head -n 1)
            
        # 兜底：如果上面的逻辑找不到，尝试找有 Global IPv6 的网卡
        if [ -z "$DEFAULT_IFACE" ]; then
            DEFAULT_IFACE=$(ip -6 -o addr show scope global | grep -vE "^(lo|warp|wg|tun|docker|br-|veth)" | head -n 1 | awk '{print $2}')
        fi
        
        # 最后的兜底
        [ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE="eth0"
    fi
    
    # 2. 获取用于展示的 IP (物理网卡上的 IP)
    # 注意: 这里获取的是物理网卡的 IP，不是 WARP 的 IP
    MAIN_IPV4=$(ip -4 addr show dev "$DEFAULT_IFACE" | grep inet | awk '{print $2}' | head -n 1)
    MAIN_IPV6=$(ip -6 addr show dev "$DEFAULT_IFACE" scope global | grep inet6 | awk '{print $2}' | head -n 1)
    
    # 3. 获取真实出站 IP (可能是 WARP 的 IP)
    # 增加超时和重试，适应 WARP 环境
    PUBLIC_IPV4=$(curl -s -4 --max-time 3 https://ipconfig.me || echo "N/A")
    # 如果物理机没有 IPv4 出站，PUBLIC_IPV4 可能是空的或者 N/A，但如果走了 WARP，就会显示 Cloudflare IP
}

show_dashboard() {
    get_net_info
    clear
    echo -e "${BLUE}==================================================${NC}"
    echo -e "           Xray-Proxya 管理面板 (Beta v4)"
    echo -e "${BLUE}==================================================${NC}"
    
    # 网络信息
    echo -e "📡 物理接口 (NDP绑定): ${CYAN}$DEFAULT_IFACE${NC}"
    echo -e "   接口 IPv6: ${YELLOW}${MAIN_IPV6:-未检测到}${NC} (用于子网基准)"
    echo -e "   --------------------------------------------"
    echo -e "   实际出站 IPv4: ${GREEN}$PUBLIC_IPV4${NC} (可能经由 WARP)"
    
    # 服务状态
    echo -e "\n📊 服务状态监控:"
    
    if systemctl is-active --quiet xray-proxya; then
        echo -e "   Xray Core:     [ ${GREEN}运行中${NC} ]"
    else
        echo -e "   Xray Core:     [ ${RED}已停止${NC} ]"
    fi
    
    if systemctl is-active --quiet xray-rotate.timer; then
        NEXT_RUN=$(systemctl list-timers xray-rotate.timer --no-pager | awk '/xray-rotate.timer/ {print $2, $3}' | head -n 1)
        echo -e "   IPv6 轮换任务: [ ${GREEN}已激活${NC} ] (下次: $NEXT_RUN)"
    else
        echo -e "   IPv6 轮换任务: [ ${CYAN}未配置${NC} ]"
    fi
    
    echo -e "${BLUE}==================================================${NC}"
}

# --- 核心功能函数 ---

install_core() {
    if [ -f "$XRAY_BIN" ]; then return 0; fi
    echo -e "${BLUE}⬇️  准备 Xray Core...${NC}"
    
    # 检测 GitHub 连通性 (IPv4 或 IPv6)
    if ! curl -s -I --connect-timeout 5 https://api.github.com >/dev/null; then
        echo -e "${RED}⚠️  无法连接 GitHub API。${NC}"
        echo -e "系统环境复杂(WARP/IPv6 Only)，请协助手动安装："
        echo -e "1. 下载 Xray-linux-64.zip"
        echo -e "2. 解压并提取 'xray' 文件"
        echo -e "3. 上传到: ${YELLOW}$XRAY_DIR${NC}"
        echo -e "4. 执行: chmod +x $XRAY_BIN"
        echo -e "--------------------------------------------------"
        read -p "完成上述步骤后，按回车继续..."
        if [ ! -f "$XRAY_BIN" ]; then echo -e "${RED}未找到文件，退出。${NC}"; exit 1; fi
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

setup_rotation() {
    echo -e "\n=== IPv6 轮换设置 (复杂网络增强版) ==="
    get_net_info
    
    echo -e "检测到物理接口: ${GREEN}$DEFAULT_IFACE${NC}"
    echo -e "注意: IP 将绑定到此接口以处理 NDP。出站流量可能经由 WARP 路由，但源 IP 将是我们绑定的 IPv6。"
    
    # 交互确认接口，防止误判
    read -p "确认使用接口 $DEFAULT_IFACE ? (y/n, n手动输入): " confirm_iface
    if [[ "$confirm_iface" == "n" ]]; then
        read -p "请输入物理网卡名称 (如 eth0): " user_iface
        DEFAULT_IFACE="$user_iface"
    fi
    
    read -p "输入 CIDR (如 2a00:f48:1000:48a::/64): " user_cidr
    
    if ! python3 -c "import ipaddress; ipaddress.IPv6Network('$user_cidr', strict=False)" 2>/dev/null; then
        echo -e "${RED}❌ CIDR 格式无效${NC}"; return
    fi
    
    echo -e "优先策略: [1] IPv4 (WARP) 优先  [2] IPv6 轮换优先"
    read -p "选择: " pri_choice
    local pri_val="ipv4"
    [[ "$pri_choice" == "2" ]] && pri_val="ipv6"

    read -p "轮换间隔 (分钟，默认 60): " interval
    [[ ! "$interval" =~ ^[0-9]+$ ]] && interval=60

    # 生成轮换脚本
    cat > "$ROTATION_SCRIPT" <<EOF
#!/bin/bash
source $CONF_DIR/rotation.env
XRAY_CFG="$JSON_FILE"
LOG_FILE="/var/log/xray-proxya-rotation.log"

log() { echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> "\$LOG_FILE"; }

# 1. 生成 IP
NEW_IP=\$(python3 -c "import ipaddress, random; net=ipaddress.IPv6Network('$user_cidr', strict=False); print(ipaddress.IPv6Address(random.randint(int(net.network_address), int(net.broadcast_address))))")

# 2. 绑定 IP (关键: 绑定到物理网卡 $DEFAULT_IFACE)
log "Binding \$NEW_IP to $DEFAULT_IFACE"
# preferred_lft 0 防止它变成系统默认源 IP，这在 WARP 环境下尤为重要
ip -6 addr add "\$NEW_IP/128" dev "$DEFAULT_IFACE" preferred_lft 0

# 3. 更新 Xray
tmp_json=\$(mktemp)
jq --arg ip "\$NEW_IP" '(.outbounds[] | select(.tag=="outbound-ipv6").sendThrough) = \$ip' "\$XRAY_CFG" > "\$tmp_json" && mv "\$tmp_json" "\$XRAY_CFG"

# 4. 重载
systemctl restart xray-proxya

# 5. 自检 (通过 Xray 代理访问)
CHECK_IP=\$(curl -x http://127.0.0.1:10086 -s --max-time 5 https://ipconfig.me || echo "fail")

if [[ "\$CHECK_IP" == *"\$NEW_IP"* ]]; then
    log "Success: \$NEW_IP"
    if [ -f "$CONF_DIR/current_ipv6" ]; then
        OLD_IP=\$(cat "$CONF_DIR/current_ipv6")
        ip -6 addr del "\$OLD_IP/128" dev "$DEFAULT_IFACE" 2>/dev/null
    fi
    echo "\$NEW_IP" > "$CONF_DIR/current_ipv6"
else
    log "Failed (Got: \$CHECK_IP). Reverting..."
    ip -6 addr del "\$NEW_IP/128" dev "$DEFAULT_IFACE"
    # 可选回滚逻辑
fi
EOF
    chmod +x "$ROTATION_SCRIPT"
    echo "DEFAULT_IFACE=$DEFAULT_IFACE" > "$ROTATION_CONF"
    
    # 更新配置
    sed -i "s/^PRIORITY=.*/PRIORITY=$pri_val/" "$CONF_FILE"
    source "$CONF_FILE"
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "$pri_val"

    # Timer Setup
    cat > "/etc/systemd/system/xray-rotate.service" <<EOF
[Unit]
Description=Xray IPv6 Rotation
[Service]
Type=oneshot
ExecStart=$ROTATION_SCRIPT
EOF

    cat > "/etc/systemd/system/xray-rotate.timer" <<EOF
[Unit]
Description=Run Xray IPv6 Rotation
[Timer]
OnBootSec=2min
OnUnitActiveSec=${interval}min
[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now xray-rotate.timer
    
    echo -e "${GREEN}✅ 设置完成，首次轮换中...${NC}"
    bash "$ROTATION_SCRIPT"
}

install_xray() {
    echo -e "\n=== 安装向导 ==="
    check_deps
    
    read -p "VMess 端口 (默认 ${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (默认 ${vlessp:-8082}): " port_vl
    read -p "SS    端口 (默认 ${ssocks:-8083}): " port_ss
    PORT_VMESS=${port_vm:-${vmessp:-8081}}; PORT_VLESS=${port_vl:-${vlessp:-8082}}; PORT_SS=${port_ss:-${ssocks:-8083}}

    if ss -lnt | grep -q -E ":($PORT_VMESS|$PORT_VLESS|$PORT_SS) "; then echo -e "${RED}端口占用${NC}"; return; fi

    get_net_info
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
    read -p "按回车查看链接..."
    show_links
}

show_links() {
    if [ ! -f "$CONF_FILE" ]; then echo "无配置"; return; fi
    source "$CONF_FILE"
    get_net_info
    
    echo -e "\n🔑 UUID: ${YELLOW}$UUID${NC}"
    
    # 获取出口 IP (可能经由 WARP)
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
    
    print_l "$v4" "IPv4 (可能为 WARP)"
    print_l "$v6" "IPv6"
    read -p "按回车返回..."
}

uninstall() {
    echo -e "${RED}⚠️  即将卸载${NC}"
    read -p "确认? (y/n): " c
    [[ "$c" != "y" ]] && return

    systemctl stop xray-proxya xray-rotate.timer xray-rotate.service 2>/dev/null
    systemctl disable xray-proxya xray-rotate.timer xray-rotate.service 2>/dev/null
    
    if [ -f "$CONF_DIR/current_ipv6" ]; then
        get_net_info
        OLD_IP=$(cat "$CONF_DIR/current_ipv6")
        ip -6 addr del "$OLD_IP/128" dev "$DEFAULT_IFACE" 2>/dev/null
    fi

    rm -rf "$XRAY_DIR" "$CONF_DIR" \
           "/etc/systemd/system/xray-proxya.service" \
           "/etc/systemd/system/xray-rotate.service" \
           "/etc/systemd/system/xray-rotate.timer"
           
    systemctl daemon-reload
    echo -e "${GREEN}✅ 已卸载${NC}"
    read -p "按回车退出..."
    exit 0
}

check_root
while true; do
    show_dashboard
    echo -e "\n1. 安装 / 重置"
    echo -e "2. 查看链接"
    echo -e "3. IPv6 轮换设置 (Beta)"
    echo -e "4. 卸载"
    echo -e "0. 退出"
    read -p "选择: " choice
    
    case "$choice" in
        1) install_xray ;;
        2) show_links ;;
        3) 
           if [ ! -f "$CONF_FILE" ]; then echo "请先安装"; read -p ""; continue; fi
           source "$CONF_FILE"; setup_rotation ;;
        4) uninstall ;;
        0) exit 0 ;;
    esac
done