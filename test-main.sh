#!/bin/bash

# ==================================================
# Xray-Proxya Manager (Beta)
# ==================================================

# --- 加密套件配置 ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"

# --- 全局变量 ---
CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
XRAY_BIN="/usr/local/bin/xray-proxya-core/xray"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
JSON_FILE="$XRAY_DIR/config.json"
ROTATE_SERVICE="/etc/systemd/system/xray-proxya-rotate.service"
ROTATE_TIMER="/etc/systemd/system/xray-proxya-rotate.timer"
TEST_PORT=54321 # 本地回环测试端口

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
    echo -e "${BLUE}📦 检查依赖 (curl, jq, openssl, python3, iproute2)...${NC}"
    apt-get update -qq >/dev/null
    apt-get install -y curl jq unzip openssl python3 iproute2 >/dev/null 2>&1
}

detect_interface() {
    # 查找 IPv6 默认路由的出口网卡，如果没有则查 IPv4
    DEFAULT_IFACE=$(ip -6 route show default | awk '/default/ {print $5}' | head -n1)
    if [ -z "$DEFAULT_IFACE" ]; then
        DEFAULT_IFACE=$(ip -4 route show default | awk '/default/ {print $5}' | head -n1)
    fi
    echo "$DEFAULT_IFACE"
}

get_ipv6_list() {
    local iface=$1
    ip -6 addr show dev "$iface" scope global | awk '/inet6/ {print $2}'
}

# Python 辅助: 生成指定 CIDR 内的随机 IP
python_gen_ip() {
    local cidr=$1
    python3 -c "
import ipaddress, random, sys
try:
    net = ipaddress.IPv6Network('$cidr', strict=False)
    # 排除全0网络地址和全1广播地址(虽然IPv6没有广播，但作为最佳实践)
    min_int = int(net.network_address) + 1
    max_int = int(net.broadcast_address) - 1
    if max_int <= min_int:
        print('Error: Subnet too small')
        sys.exit(1)
    rand_int = random.randint(min_int, max_int)
    print(ipaddress.IPv6Address(rand_int))
except Exception as e:
    print('Error')
    sys.exit(1)
"
}

check_status() {
    if systemctl is-active --quiet xray-proxya; then
        echo -e "🟢 服务: ${GREEN}运行中${NC}"
    else
        echo -e "🔴 服务: ${RED}未运行${NC}"
    fi
    
    # 检查轮换状态
    if systemctl is-active --quiet xray-proxya-rotate.timer; then
        echo -e "🔄 轮换: ${GREEN}已启用${NC}"
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
    local ss_method=${10}
    # IPv6 轮换相关参数
    local rotate_ip=${11}
    local priority=${12} # 1=IPv4优先, 2=IPv6优先

    # 构建 Routing 规则
    local routing_rule=""
    if [ "$priority" == "2" ]; then
        # IPv6 优先: 默认流量全走 IPv6 出站
        routing_rule='{ "type": "field", "outboundTag": "out-v6-rotate", "network": "tcp,udp" }'
    else
        # IPv4 优先 (默认): 仅当明确匹配时走 IPv6 (此处留空，走默认 out-v4)
        routing_rule='{ "type": "field", "outboundTag": "out-v4", "domain": ["geosite:google", "geosite:netflix"] }' # 示例规则
    fi

    # 构建 Outbound: IPv6
    local v6_outbound_settings='{ "protocol": "freedom" }'
    # 只有当 rotate_ip 存在时才设置 sendThrough
    if [ ! -z "$rotate_ip" ] && [ "$rotate_ip" != "null" ]; then
        v6_outbound_settings="{ \"protocol\": \"freedom\", \"sendThrough\": \"$rotate_ip\" }"
    fi

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
      "settings": { "method": "$ss_method", "password": "$ss_pass", "network": "tcp,udp" }
    },
    {
      "tag": "test-in",
      "port": $TEST_PORT,
      "listen": "127.0.0.1",
      "protocol": "http",
      "settings": {}
    }
  ],
  "outbounds": [
    { "tag": "out-v4", "protocol": "freedom" },
    { "tag": "out-v6-rotate", "protocol": "freedom", "sendThrough": "$rotate_ip" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      $routing_rule
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

# --- IPv6 轮换逻辑 ---

rotate_logic() {
    # 此函数由 Timer 调用，或用户手动触发
    if [ ! -f "$CONF_FILE" ]; then echo "Config missing"; exit 1; fi
    source "$CONF_FILE"
    
    if [ -z "$ROTATION_CIDR" ] || [ -z "$ROTATION_IFACE" ]; then
        echo "Rotation config missing"
        exit 1
    fi

    echo "--- 开始轮换任务 ---"
    
    # 1. 生成新 IP
    NEW_IP=$(python_gen_ip "$ROTATION_CIDR")
    if [[ "$NEW_IP" == "Error"* ]] || [ -z "$NEW_IP" ]; then
        echo "Failed to generate IP"
        exit 1
    fi
    echo "Generated IP: $NEW_IP"

    # 2. 绑定新 IP (IP Alias)
    ip -6 addr add "$NEW_IP/$ROTATION_MASK" dev "$ROTATION_IFACE"
    if [ $? -ne 0 ]; then echo "Failed to bind IP"; exit 1; fi

    # 3. 记录旧 IP (用于回滚或稍后删除)
    OLD_IP=$CURRENT_ROTATE_IP

    # 4. 更新配置并重启
    # 临时更新配置文件中的 IP 变量
    sed -i "s/^CURRENT_ROTATE_IP=.*/CURRENT_ROTATE_IP=$NEW_IP/" "$CONF_FILE"
    
    # 重新生成 Config
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$CFG_SS_CIPHER" "$NEW_IP" "$ROTATION_PRIORITY"
    
    systemctl restart xray-proxya
    sleep 2

    # 5. 自我测试 (Self Test)
    echo "Testing connectivity..."
    TEST_RES=$(curl -x "http://127.0.0.1:$TEST_PORT" -s -L --max-time 5 -6 https://ipconfig.me 2>/dev/null)
    
    if [[ "$TEST_RES" == *":"* ]]; then
        echo "✅ Test Passed. Outbound IP: $TEST_RES"
        # 测试成功，删除旧 IP
        if [ ! -z "$OLD_IP" ] && [ "$OLD_IP" != "$NEW_IP" ]; then
            ip -6 addr del "$OLD_IP/$ROTATION_MASK" dev "$ROTATION_IFACE" 2>/dev/null
        fi
    else
        echo "❌ Test Failed (Result: $TEST_RES). Rolling back..."
        # 回滚逻辑
        # 删除坏 IP
        ip -6 addr del "$NEW_IP/$ROTATION_MASK" dev "$ROTATION_IFACE"
        # 恢复旧 IP 记录
        sed -i "s/^CURRENT_ROTATE_IP=.*/CURRENT_ROTATE_IP=$OLD_IP/" "$CONF_FILE"
        # 恢复 Config
        generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$CFG_SS_CIPHER" "$OLD_IP" "$ROTATION_PRIORITY"
        systemctl restart xray-proxya
    fi
}

setup_rotation() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}请先安装主服务${NC}"; return; fi
    source "$CONF_FILE"
    
    # 探测接口
    local auto_iface=$(detect_interface)
    
    echo -e "\n=== IPv6 动态轮换 (Beta) ==="
    echo -e "此功能将在您的网卡上动态绑定临时 IPv6 用于出站。"
    echo -e "当前检测到的出口网卡: ${GREEN}${auto_iface:-未知}${NC}"
    echo -e "当前网卡的 IPv6 地址参考:"
    get_ipv6_list "$auto_iface"
    echo -e "----------------------------------------"
    
    read -p "请输入使用的 CIDR (如 2001:db8::/64): " user_cidr
    read -p "请输入出站网卡 (回车默认 $auto_iface): " user_iface
    user_iface=${user_iface:-$auto_iface}
    
    # 提取掩码位 (如 64)
    local mask=$(echo "$user_cidr" | awk -F'/' '{print $2}')
    if [ -z "$mask" ]; then echo -e "${RED}格式错误，必须包含掩码 (如 /64)${NC}"; return; fi

    # 验证 CIDR
    local test_ip=$(python_gen_ip "$user_cidr")
    if [[ "$test_ip" == "Error"* ]]; then
        echo -e "${RED}CIDR 无效或无法解析，请检查输入${NC}"
        return
    fi
    echo -e "CIDR 验证通过，测试生成: $test_ip"

    echo -e "\n优先策略:"
    echo -e "1. IPv4 优先 (IPv6 仅做备用)"
    echo -e "2. IPv6 优先 (强制走轮换 IP)"
    read -p "选择 [1-2]: " priority
    priority=${priority:-1}

    read -p "轮换间隔 (分钟): " interval

    # 保存配置
    # 注意：追加或更新变量
    sed -i '/ROTATION_/d' "$CONF_FILE"
    sed -i '/CURRENT_ROTATE_IP/d' "$CONF_FILE"
    cat >> "$CONF_FILE" <<EOF
ROTATION_CIDR=$user_cidr
ROTATION_MASK=$mask
ROTATION_IFACE=$user_iface
ROTATION_PRIORITY=$priority
CURRENT_ROTATE_IP=
EOF

    # 创建 Timer
    cat > "$ROTATE_SERVICE" <<EOF
[Unit]
Description=Xray IPv6 Rotate Task

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xray-proxya rotate-task
EOF

    cat > "$ROTATE_TIMER" <<EOF
[Unit]
Description=Run Xray IPv6 Rotation

[Timer]
OnBootSec=5min
OnUnitActiveSec=${interval}min

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now xray-proxya-rotate.timer
    
    echo -e "${GREEN}✅ 轮换定时任务已激活！${NC}"
    echo -e "正在执行首次生成..."
    rotate_logic
}

# --- 基础安装流程 ---

install_xray() {
    install_deps
    
    echo -e "=== 安装向导 (Beta) ==="
    read -p "VMess 端口 (默认 ${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (默认 ${vlessp:-8082}): " port_vl
    read -p "SS    端口 (默认 ${ssocks:-8083}): " port_ss
    
    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}

    for p in $PORT_VMESS $PORT_VLESS $PORT_SS $TEST_PORT; do
        if ss -lnt | grep -q ":$p "; then 
            echo -e "${RED}⚠️  端口 $p 被占用${NC}"; return
        fi
    done

    download_core

    echo -e "${BLUE}🔑 生成配置...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(openssl rand -hex 12)"
    PATH_VL="/$(openssl rand -hex 12)"
    PASS_SS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 24)
    
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"decryption":' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"encryption":' | cut -d '"' -f 4)

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
ROTATION_PRIORITY=1
EOF

    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "" "1"
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
    
    local vm_c=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_c=${CFG_SS_CIPHER:-$SS_CIPHER}

    local vmess_json=$(jq -n --arg add "$ip_addr" --arg port "$PORT_VMESS" --arg id "$UUID" --arg path "$PATH_VM" --arg scy "$vm_c" \
      '{v:"2", ps:("VMess-"+$scy), add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
    local vmess_link="vmess://$(echo -n "$vmess_json" | base64 -w 0)"

    local vless_link="vless://$UUID@$fmt_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#VLESS-XHTTP-ENC"
    local ss_auth=$(echo -n "${ss_c}:$PASS_SS" | base64 -w 0)
    local ss_link="ss://$ss_auth@$fmt_ip:$PORT_SS#SS-Xray"

    echo -e "\n${BLUE}--- $label ($ip_addr) ---${NC}"
    echo -e "1️⃣  VMess ($vm_c):"
    echo -e "    ${GREEN}$vmess_link${NC}"
    echo -e "2️⃣  VLESS (XHTTP-ENC):"
    echo -e "    ${GREEN}$vless_link${NC}"
    echo -e "3️⃣  Shadowsocks ($ss_c):"
    echo -e "    ${GREEN}$ss_link${NC}"
}

show_links() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    
    echo -e "🔑 UUID: ${YELLOW}$UUID${NC}"
    echo -e "🔐 SS 密码: ${YELLOW}$PASS_SS${NC}"

    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    local ipv6=$(curl -s -6 --max-time 2 https://ipconfig.me || curl -s -6 --max-time 2 https://ifconfig.co)

    if [ -n "$ipv4" ]; then print_config_group "$ipv4" "IPv4"; fi
    if [ -n "$ipv6" ]; then print_config_group "$ipv6" "IPv6"; fi
    
    if [ -f "$ROTATE_TIMER" ]; then
        echo -e "\n🔄 动态 IPv6: ${GREEN}启用${NC}"
        echo -e "   当前出口: ${CURRENT_ROTATE_IP:-无}"
    fi
}

change_ports() {
    if [ ! -f "$CONF_FILE" ]; then echo "未安装"; return; fi
    source "$CONF_FILE"
    
    read -p "新 VMess (回车跳过): " new_vm
    read -p "新 VLESS (回车跳过): " new_vl
    read -p "新 SS    (回车跳过): " new_ss
    
    [[ ! -z "$new_vm" ]] && sed -i "s/^PORT_VMESS=.*/PORT_VMESS=$new_vm/" "$CONF_FILE"
    [[ ! -z "$new_vl" ]] && sed -i "s/^PORT_VLESS=.*/PORT_VLESS=$new_vl/" "$CONF_FILE"
    [[ ! -z "$new_ss" ]] && sed -i "s/^PORT_SS=.*/PORT_SS=$new_ss/" "$CONF_FILE"
    
    source "$CONF_FILE"
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$CFG_SS_CIPHER" "$CURRENT_ROTATE_IP" "$ROTATION_PRIORITY"
    systemctl restart xray-proxya
    echo -e "${GREEN}✅ 已重启${NC}"
}

maintenance_menu() {
    while true; do
        echo -e "\n=== 维护 ==="
        echo "1. 启动"
        echo "2. 停止"
        echo "3. 重启"
        echo "4. 开启自启"
        echo "5. 关闭自启"
        echo "0. 返回"
        read -p "选择: " c
        case "$c" in
            1) systemctl start xray-proxya ;;
            2) systemctl stop xray-proxya ;;
            3) systemctl restart xray-proxya ;;
            4) systemctl enable xray-proxya ;;
            5) systemctl disable xray-proxya ;;
            0) return ;;
        esac
    done
}

uninstall_xray() {
    read -p "确认卸载? (y/n): " c
    if [[ "$c" != "y" ]]; then return; fi

    systemctl stop xray-proxya xray-proxya-rotate.timer 2>/dev/null
    systemctl disable xray-proxya xray-proxya-rotate.timer 2>/dev/null
    rm -f "$SERVICE_FILE" "$ROTATE_SERVICE" "$ROTATE_TIMER"
    rm -rf "$XRAY_DIR" "$CONF_DIR"
    systemctl daemon-reload
    echo -e "${GREEN}✅ 已卸载${NC}"
}

# --- 入口 ---

# 隐藏参数: rotate-task 由 Timer 调用
if [ "$1" == "rotate-task" ]; then
    check_root
    rotate_logic
    exit 0
fi

check_root
echo -e "${BLUE}Xray-Proxya (Beta)${NC}"
check_status
echo "1. 安装 / 重置"
echo "2. 查看链接"
echo "3. 修改端口"
echo "4. 维护菜单"
echo "5. 卸载"
echo "6. IPv6 轮换 (Beta)"
echo "0. 退出"
read -p "选择: " choice

case "$choice" in
    1) install_xray ;;
    2) show_links ;;
    3) change_ports ;;
    4) maintenance_menu ;;
    5) uninstall_xray ;;
    6) setup_rotation ;;
    0) exit 0 ;;
    *) echo "无效" ;;
esac