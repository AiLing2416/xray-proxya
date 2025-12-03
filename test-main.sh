#!/bin/bash

# ==================================================
# Xray-Proxya Manager (Beta v6)
# ==================================================

# --- 用户配置变量 ---
# 外部获取 IP 的 API 地址
IP_API_URL="https://iconfig.me"

# 加密算法配置
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"

# 本地回环测试端口
TEST_PORT=57280

# 强制指定物理网卡 (若自动识别错误，请在此填入如 "eth0")
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
    if [ "$EUID" -ne 0 ]; then echo -e "${RED}❌ 错误: 需要 root 权限${NC}"; exit 1; fi
}

check_deps() {
    local deps=("curl" "jq" "openssl" "python3" "ip")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            apt-get update -qq && apt-get install -y $dep >/dev/null 2>&1
        fi
    done
}

# --- 网络探测 ---

identify_interface() {
    if [ -n "$FORCE_IFACE" ]; then
        DEFAULT_IFACE="$FORCE_IFACE"
    else
        # 排除回环、点对点(WARP)、虚拟网桥，寻找物理网卡
        DEFAULT_IFACE=$(ip -o link show up \
            | grep -v "LOOPBACK" | grep -v "POINTOPOINT" | grep -v "noqueue" \
            | grep -vE ": (docker|br-|veth|tun|wg)" \
            | awk -F': ' '{print $2}' | head -n 1)
        
        # 兜底：找有 Global IPv6 的网卡
        if [ -z "$DEFAULT_IFACE" ]; then
            DEFAULT_IFACE=$(ip -6 -o addr show scope global | grep -vE "^(lo|warp|wg|tun|docker|br-|veth)" | head -n 1 | awk '{print $2}')
        fi
        [ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE="eth0"
    fi
}

get_phy_info() {
    identify_interface
    # 仅读取本机网卡配置，不联网
    PHY_IPV4=$(ip -4 addr show dev "$DEFAULT_IFACE" | grep inet | awk '{print $2}' | head -n 1 | cut -d/ -f1)
    PHY_IPV6=$(ip -6 addr show dev "$DEFAULT_IFACE" scope global | grep inet6 | awk '{print $2}' | head -n 1 | cut -d/ -f1)
}

show_dashboard() {
    get_phy_info
    
    # 获取理论配置的出站 IP (读取文件)
    # 逻辑: 如果轮换 Timer 激活且有记录文件，则显示轮换 IP，否则显示默认
    if [ -f "$CONF_DIR/current_ipv6" ] && systemctl is-active --quiet xray-rotate.timer; then
        CFG_OUT_IPV6=$(cat "$CONF_DIR/current_ipv6")
        ROTATION_STATE="${GREEN}运行中${NC}"
        OUTBOUND_DISPLAY="${GREEN}$CFG_OUT_IPV6${NC} (轮换中)"
    else
        CFG_OUT_IPV6="系统默认"
        ROTATION_STATE="${CYAN}未启用${NC}"
        OUTBOUND_DISPLAY="${YELLOW}系统默认 (未指定)${NC}"
    fi

    clear
    echo -e "${BLUE}==================================================${NC}"
    echo -e "           Xray-Proxya 管理面板 (Beta v6)"
    echo -e "${BLUE}==================================================${NC}"
    
    echo -e "📡 物理接口信息 (${CYAN}$DEFAULT_IFACE${NC}):"
    echo -e "   物理 IPv4: ${YELLOW}${PHY_IPV4:-无}${NC}"
    echo -e "   物理 IPv6: ${YELLOW}${PHY_IPV6:-无}${NC}"
    echo -e ""
    echo -e "🚀 当前配置出站 (理论值):"
    echo -e "   IPv4 出站: 遵循系统路由 (或 WARP)"
    echo -e "   IPv6 出站: $OUTBOUND_DISPLAY"
    echo -e "" 
    
    # 服务状态
    echo -e "📊 服务运行状态:"
    if systemctl is-active --quiet xray-proxya; then
        echo -e "   主服务:   [ ${GREEN}运行中${NC} ]"
    else
        echo -e "   主服务:   [ ${RED}已停止${NC} ]"
    fi
    echo -e "   IPv6轮换: [ $ROTATION_STATE ]"
    
    echo -e "${BLUE}==================================================${NC}"
}

# --- 核心配置 ---

install_core() {
    if [ -f "$XRAY_BIN" ]; then return 0; fi
    echo -e "${BLUE}⬇️  准备 Xray Core...${NC}"
    # 使用用户定义的 IP_API_URL 测试连通性或作为占位，实际上这里只测 GitHub API
    if ! curl -s -I --connect-timeout 5 https://api.github.com >/dev/null; then
        echo -e "${RED}⚠️  无法连接 GitHub API${NC}"
        echo -e "请手动上传 'xray' 文件到: ${YELLOW}$XRAY_DIR${NC}"
        read -p "按回车继续..."
        if [ ! -f "$XRAY_BIN" ]; then echo -e "${RED}失败${NC}"; exit 1; fi
    else
        LATEST_URL=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
        mkdir -p "$XRAY_DIR"
        curl -L -o /tmp/xray.zip "$LATEST_URL"
        unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
        rm /tmp/xray.zip
    fi
    chmod +x "$XRAY_BIN"
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
    { "tag": "vmess-in", "port": $vmess_p, "protocol": "vmess", "settings": { "clients": [ { "id": "$uuid", "level": 0 } ] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "$vmess_path" } } },
    { "tag": "vless-enc-in", "port": $vless_p, "protocol": "vless", "settings": { "clients": [ { "id": "$uuid", "level": 0 } ], "decryption": "$dec_key" }, "streamSettings": { "network": "xhttp", "xhttpSettings": { "path": "$vless_path" } } },
    { "tag": "shadowsocks-in", "port": $ss_p, "protocol": "shadowsocks", "settings": { "method": "$ss_method", "password": "$ss_pass", "network": "tcp,udp" } },
    { "tag": "test-in", "port": $TEST_PORT, "listen": "127.0.0.1", "protocol": "http", "settings": {} }
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

# --- 轮换功能模块 ---

enable_rotation() {
    echo -e "\n=== 启用/配置 IPv6 轮换 ==="
    identify_interface
    
    # 优化展示：列出当前接口的所有 IPv6 地址供参考
    echo -e "物理接口: ${GREEN}$DEFAULT_IFACE${NC}"
    echo -e "现有 IPv6 地址 (供参考 CIDR):"
    ip -6 addr show dev "$DEFAULT_IFACE" scope global | grep inet6 | awk '{print "   - " $2}'
    echo -e "------------------------------------------------"
    
    read -p "请输入 CIDR (如 2001:db8::/64): " user_cidr
    
    if ! python3 -c "import ipaddress; ipaddress.IPv6Network('$user_cidr', strict=False)" 2>/dev/null; then
        echo -e "${RED}❌ CIDR 格式无效${NC}"; return
    fi
    
    echo -e "\n优先策略: [1] IPv4优先  [2] IPv6轮换优先"
    read -p "选择: " pri_choice
    local pri_val="ipv4"
    [[ "$pri_choice" == "2" ]] && pri_val="ipv6"

    read -p "轮换间隔 (分钟, 默认60): " interval
    [[ ! "$interval" =~ ^[0-9]+$ ]] && interval=60

    # 生成轮换脚本
    cat > "$ROTATION_SCRIPT" <<EOF
#!/bin/bash
source $CONF_DIR/rotation.env
XRAY_CFG="$JSON_FILE"
LOG_FILE="/var/log/xray-proxya-rotation.log"
log() { echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> "\$LOG_FILE"; }

NEW_IP=\$(python3 -c "import ipaddress, random; net=ipaddress.IPv6Network('$user_cidr', strict=False); print(ipaddress.IPv6Address(random.randint(int(net.network_address), int(net.broadcast_address))))")

log "Binding \$NEW_IP to $DEFAULT_IFACE"
ip -6 addr add "\$NEW_IP/128" dev "$DEFAULT_IFACE" preferred_lft 0

tmp_json=\$(mktemp)
jq --arg ip "\$NEW_IP" '(.outbounds[] | select(.tag=="outbound-ipv6").sendThrough) = \$ip' "\$XRAY_CFG" > "\$tmp_json" && mv "\$tmp_json" "\$XRAY_CFG"

systemctl restart xray-proxya

# 自检 (使用定义的 IP_API_URL)
CHECK_IP=\$(curl -x http://127.0.0.1:$TEST_PORT -s --max-time 5 $IP_API_URL || echo "fail")

if [[ "\$CHECK_IP" == *"\$NEW_IP"* ]]; then
    log "OK: \$NEW_IP"
    if [ -f "$CONF_DIR/current_ipv6" ]; then
        OLD_IP=\$(cat "$CONF_DIR/current_ipv6")
        ip -6 addr del "\$OLD_IP/128" dev "$DEFAULT_IFACE" 2>/dev/null
    fi
    echo "\$NEW_IP" > "$CONF_DIR/current_ipv6"
else
    log "Fail: \$CHECK_IP"
    ip -6 addr del "\$NEW_IP/128" dev "$DEFAULT_IFACE"
fi
EOF
    chmod +x "$ROTATION_SCRIPT"
    echo "DEFAULT_IFACE=$DEFAULT_IFACE" > "$ROTATION_CONF"
    
    # 更新配置
    sed -i "s/^PRIORITY=.*/PRIORITY=$pri_val/" "$CONF_FILE"
    source "$CONF_FILE"
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "$pri_val"

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
    echo -e "${GREEN}✅ 已启用并执行首次轮换${NC}"
}

test_rotation() {
    echo -e "\n=== 轮换可用性测试 ==="
    echo -e "正在通过本地代理 (127.0.0.1:$TEST_PORT) 请求 $IP_API_URL ..."
    
    START_TIME=$(date +%s%3N)
    RESULT=$(curl -x http://127.0.0.1:$TEST_PORT -s --max-time 8 $IP_API_URL || echo "Error")
    END_TIME=$(date +%s%3N)
    DURATION=$((END_TIME - START_TIME))
    
    if [ -f "$CONF_DIR/current_ipv6" ]; then
        EXPECTED=$(cat "$CONF_DIR/current_ipv6")
        echo -e "理论配置 IP: ${CYAN}$EXPECTED${NC}"
    else
        echo -e "理论配置 IP: (未启用)"
    fi
    
    echo -e "实际检测 IP: ${YELLOW}$RESULT${NC}"
    echo -e "请求耗时:    ${DURATION}ms"
    
    if [[ "$RESULT" == *":"* ]]; then
        echo -e "测试结果:    ${GREEN}连接成功 (IPv6)${NC}"
    elif [[ "$RESULT" == "Error" ]]; then
        echo -e "测试结果:    ${RED}连接失败 (超时或阻断)${NC}"
    else
        echo -e "测试结果:    ${YELLOW}连接成功 (但返回了 IPv4，可能未走轮换)${NC}"
    fi
    read -p "按回车返回..."
}

disable_rotation() {
    echo -e "\n=== 停用 IPv6 轮换 ==="
    read -p "确定要移除轮换服务并恢复默认吗? (y/n): " confirm
    [[ "$confirm" != "y" ]] && return

    # 1. 停止服务
    systemctl stop xray-rotate.timer xray-rotate.service 2>/dev/null
    systemctl disable xray-rotate.timer xray-rotate.service 2>/dev/null
    
    # 2. 清理 IP
    identify_interface
    if [ -f "$CONF_DIR/current_ipv6" ]; then
        OLD_IP=$(cat "$CONF_DIR/current_ipv6")
        echo -e "正在移除 IP: $OLD_IP ..."
        ip -6 addr del "$OLD_IP/128" dev "$DEFAULT_IFACE" 2>/dev/null
        rm "$CONF_DIR/current_ipv6"
    fi
    
    # 3. 清理文件
    rm -f "$ROTATION_SCRIPT" "/etc/systemd/system/xray-rotate.service" "/etc/systemd/system/xray-rotate.timer"
    systemctl daemon-reload
    
    # 4. 重置 Xray 配置
    echo -e "正在重置 Xray 配置..."
    source "$CONF_FILE"
    sed -i "s/^PRIORITY=.*/PRIORITY=ipv4/" "$CONF_FILE"
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "ipv4"
    
    systemctl restart xray-proxya
    echo -e "${GREEN}✅ 轮换已停用，服务已恢复默认。${NC}"
    read -p "按回车返回..."
}

rotation_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== IPv6 轮换管理 ===${NC}"
        if systemctl is-active --quiet xray-rotate.timer; then
            echo -e "状态: ${GREEN}已启用${NC}"
            [ -f "$CONF_DIR/current_ipv6" ] && echo -e "当前轮换 IP: $(cat $CONF_DIR/current_ipv6)"
        else
            echo -e "状态: ${YELLOW}未启用${NC}"
        fi
        echo -e "---------------------"
        echo "1. 启用 / 重设轮换"
        echo "2. 手动测试 (通过本地代理)"
        echo "3. 停用轮换 (移除服务)"
        echo "0. 返回主菜单"
        read -p "选择: " r_choice
        case "$r_choice" in
            1) enable_rotation; read -p "按回车继续..." ;;
            2) test_rotation ;;
            3) disable_rotation ;;
            0) return ;;
            *) echo "无效" ;;
        esac
    done
}

install_xray() {
    echo -e "\n=== 安装向导 ==="
    check_deps
    read -p "VMess 端口 (默认 ${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (默认 ${vlessp:-8082}): " port_vl
    read -p "SS    端口 (默认 ${ssocks:-8083}): " port_ss
    PORT_VMESS=${port_vm:-${vmessp:-8081}}; PORT_VLESS=${port_vl:-${vlessp:-8082}}; PORT_SS=${port_ss:-${ssocks:-8083}}
    
    if ss -lnt | grep -q -E ":($PORT_VMESS|$PORT_VLESS|$PORT_SS) "; then echo -e "${RED}端口占用${NC}"; return; fi
    identify_interface; install_core

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
    systemctl daemon-reload; systemctl enable --now xray-proxya
    echo -e "${GREEN}✅ 安装完成${NC}"; read -p "回车查看链接..."; show_links
}

show_links() {
    if [ ! -f "$CONF_FILE" ]; then echo "无配置"; return; fi
    source "$CONF_FILE"
    
    echo -e "\n🔑 UUID: ${YELLOW}$UUID${NC}"
    # 使用变量 IP_API_URL
    local v4=$(curl -s -4 --max-time 3 $IP_API_URL)
    local v6=$(curl -s -6 --max-time 3 $IP_API_URL)
    
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
    print_l "$v4" "IPv4"; print_l "$v6" "IPv6"; read -p "回车返回..."
}

uninstall() {
    read -p "确认卸载? (y/n): " c; [[ "$c" != "y" ]] && return
    disable_rotation <<< "y" >/dev/null 2>&1
    systemctl stop xray-proxya; systemctl disable xray-proxya
    rm -rf "$XRAY_DIR" "$CONF_DIR" "/etc/systemd/system/xray-proxya.service"
    systemctl daemon-reload
    echo -e "${GREEN}✅ 已卸载${NC}"; exit 0
}

check_root
while true; do
    show_dashboard
    echo -e "\n1. 安装 / 重置"
    echo -e "2. 查看链接"
    echo -e "3. IPv6 轮换菜单"
    echo -e "4. 卸载"
    echo -e "0. 退出"
    read -p "选择: " choice
    case "$choice" in
        1) install_xray ;;
        2) show_links ;;
        3) 
           if [ ! -f "$CONF_FILE" ]; then echo "请先安装"; read -p ""; continue; fi
           source "$CONF_FILE"; rotation_menu ;;
        4) uninstall ;;
        0) exit 0 ;;
    esac
done