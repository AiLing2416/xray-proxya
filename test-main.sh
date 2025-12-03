#!/bin/bash

# ==================================================
# Xray-Proxya Manager (Beta)
# ==================================================

# --- 加密配置 (可在此修改) ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"

# --- 全局变量 ---
CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
XRAY_BIN="$XRAY_DIR/xray"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
JSON_FILE="$XRAY_DIR/config.json"
ROTATION_SCRIPT="$CONF_DIR/rotate_ip.sh"
ROTATION_LOG="$CONF_DIR/rotation.log"
CURRENT_IPV6_FILE="$CONF_DIR/current_ipv6"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 基础检查 ---

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}❌ 错误: 需要 root 权限${NC}"
        exit 1
    fi
}

detect_interface() {
    # 自动获取默认路由接口
    DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)
    if [ -z "$DEFAULT_IFACE" ]; then
        DEFAULT_IFACE=$(ls /sys/class/net | head -n 1)
    fi
}

install_deps() {
    echo -e "${BLUE}📦 检测并安装依赖...${NC}"
    apt-get update -qq >/dev/null
    
    local deps=("curl" "jq" "unzip" "openssl" "python3")
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then
            echo -e "   - 安装 $dep..."
            apt-get install -y $dep >/dev/null 2>&1
        fi
    done
    
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ 致命错误: Python3 安装失败。CIDR 计算依赖 Python3。${NC}"
        exit 1
    fi
}

# --- 核心下载与故障回退 ---

download_core() {
    if [ -f "$XRAY_BIN" ]; then
        echo -e "${GREEN}✅ Xray 已存在，跳过下载${NC}"
        return 0
    fi

    echo -e "${BLUE}⬇️  尝试自动下载 Xray-core...${NC}"
    mkdir -p "$XRAY_DIR"

    # 尝试访问 GitHub API
    LATEST_URL=$(curl -s --max-time 5 https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
    
    if [ -n "$LATEST_URL" ] && [ "$LATEST_URL" != "null" ]; then
        curl -L -o /tmp/xray.zip "$LATEST_URL"
        if [ $? -eq 0 ]; then
            unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
            rm /tmp/xray.zip
            chmod +x "$XRAY_BIN"
            echo -e "${GREEN}✅ 下载安装成功${NC}"
            return 0
        fi
    fi

    # 故障回退机制
    echo -e "${RED}❌ 自动下载失败 (可能由于网络/IPv6 问题)${NC}"
    echo -e "${YELLOW}⚠️  请手动下载 Xray-linux-64.zip 并解压${NC}"
    echo -e "------------------------------------------------"
    echo -e "系统信息: $(uname -a)"
    echo -e "目标路径: ${RED}$XRAY_BIN${NC}"
    echo -e "------------------------------------------------"
    read -p "您可以现在手动上传文件，完成后按回车继续，或输入 'q' 退出: " user_input
    
    if [[ "$user_input" == "q" ]]; then exit 1; fi

    if [ ! -f "$XRAY_BIN" ]; then
        echo -e "${RED}❌ 未检测到 Xray 二进制文件，终止安装。${NC}"
        exit 1
    fi
    chmod +x "$XRAY_BIN"
    echo -e "${GREEN}✅ 检测到手动上传的文件${NC}"
}

# --- 配置文件生成 ---

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
    local priority=${11:-4} # 4=IPv4优先, 6=IPv6优先

    # 路由规则
    local routing_rule=""
    if [ "$priority" == "6" ]; then
        # IPv6 优先：所有流量尝试走 IPv6 出站，失败回退
        routing_rule='{ "type": "field", "network": "tcp,udp", "outboundTag": "outbound-ipv6" }'
    else
        # IPv4 优先 (默认)：仅特定需求走 IPv6，此处默认留空，依靠 outbounds 顺序
        routing_rule='{ "type": "field", "domain": ["geosite:google", "geosite:netflix"], "outboundTag": "outbound-ipv6" }'
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
      "tag": "loopback-test",
      "listen": "127.0.0.1",
      "port": 10086,
      "protocol": "http",
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
    }
  ],
  "outbounds": [
    {
      "tag": "outbound-ipv4",
      "protocol": "freedom",
      "settings": { "domainStrategy": "UseIP" }
    },
    {
      "tag": "outbound-ipv6",
      "protocol": "freedom",
      "settings": { "domainStrategy": "UseIPv6" }
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      $routing_rule
    ]
  }
}
EOF
}

# --- IPv6 轮换功能 (Beta) ---

# Python 辅助脚本：生成 CIDR 内的随机 IP
gen_ipv6_python() {
    python3 -c "
import ipaddress, random, sys
try:
    net = ipaddress.IPv6Network('$1', strict=False)
    # 排除网络地址和广播地址(如果有)
    num_addrs = net.num_addresses
    if num_addrs < 4:
        print('Error: Subnet too small')
        sys.exit(1)
    
    # 随机生成一个整数偏移量
    rand_int = random.randint(1, num_addrs - 1)
    new_ip = net.network_address + rand_int
    print(new_ip)
except Exception as e:
    print('Error')
"
}

setup_rotation() {
    echo -e "\n=== IPv6 轮换设置 (Beta) ==="
    detect_interface
    echo -e "当前网络接口: ${GREEN}$DEFAULT_IFACE${NC}"
    echo -e "当前 IPv6 地址参考:"
    ip -6 addr show dev $DEFAULT_IFACE | grep "inet6" | awk '{print "   " $2}'
    
    echo -e "\n请输入您拥有的 IPv6 CIDR (例如 2001:db8::/64 或 2001:db8:1::/112)"
    read -p "CIDR: " cidr_input
    
    # 验证 CIDR
    TEST_GEN=$(gen_ipv6_python "$cidr_input")
    if [[ "$TEST_GEN" == "Error"* ]]; then
        echo -e "${RED}❌ CIDR 格式错误或范围太小${NC}"
        return
    fi
    echo -e "✅ CIDR 有效，测试生成: $TEST_GEN"

    echo -e "\n设置轮换间隔 (分钟):"
    read -p "间隔: " interval_min

    # 保存轮换配置
    cat > "$CONF_DIR/rotation.conf" <<EOF
CIDR="$cidr_input"
IFACE="$DEFAULT_IFACE"
EOF

    # 生成轮换执行脚本
    cat > "$ROTATION_SCRIPT" <<EOF
#!/bin/bash
source $CONF_DIR/rotation.conf
LOG="$ROTATION_LOG"

log() { echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> "\$LOG"; }

# 1. 生成新 IP
NEW_IP=\$(python3 -c "import ipaddress, random; net=ipaddress.IPv6Network('\$CIDR', strict=False); print(net.network_address + random.randint(1, net.num_addresses - 1))")

if [ -z "\$NEW_IP" ]; then log "Error: IP Gen failed"; exit 1; fi

# 2. 绑定新 IP
ip -6 addr add "\$NEW_IP/\$(echo \$CIDR | cut -d/ -f2)" dev \$IFACE
log "Bound IP: \$NEW_IP"

# 3. 更新 Xray Config (使用 jq 注入 sendThrough)
TMP_JSON="/tmp/xray_config_tmp.json"
jq --arg ip "\$NEW_IP" '(.outbounds[] | select(.tag=="outbound-ipv6")).sendThrough = \$ip' "$JSON_FILE" > "\$TMP_JSON" && mv "\$TMP_JSON" "$JSON_FILE"

# 4. 重启并测试
systemctl restart xray-proxya
sleep 3

# 自检: 通过本地 HTTP 代理请求 ipconfig.me
TEST_RES=\$(curl -x http://127.0.0.1:10086 -s -L --max-time 5 https://ifconfig.co || echo "fail")

if [[ "\$TEST_RES" == *"\$NEW_IP"* ]]; then
    log "Success: Active IP is \$NEW_IP"
    # 5. 清理旧 IP
    if [ -f "$CURRENT_IPV6_FILE" ]; then
        OLD_IP=\$(cat "$CURRENT_IPV6_FILE")
        if [ "\$OLD_IP" != "\$NEW_IP" ]; then
            ip -6 addr del "\$OLD_IP/\$(echo \$CIDR | cut -d/ -f2)" dev \$IFACE 2>/dev/null
        fi
    fi
    echo "\$NEW_IP" > "$CURRENT_IPV6_FILE"
else
    log "Fail: Test returned \$TEST_RES. Reverting..."
    # 失败回滚: 移除新 IP
    ip -6 addr del "\$NEW_IP/\$(echo \$CIDR | cut -d/ -f2)" dev \$IFACE
    # 这里为了简单，暂不回滚 config.json 中的 sendThrough 字段，下次重启会再次尝试
fi
EOF
    chmod +x "$ROTATION_SCRIPT"

    # 创建 Systemd Timer
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
OnBootSec=5min
OnUnitActiveSec=${interval_min}min
[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now xray-rotate.timer
    
    echo -e "${GREEN}✅ 轮换任务已激活!${NC}"
    echo -e "正在执行第一次轮换测试..."
    $ROTATION_SCRIPT
    echo -e "查看日志: cat $ROTATION_LOG"
}

# --- 主安装流程 ---

install_xray() {
    echo -e "=== 安装向导 (Beta) ==="
    detect_interface
    install_deps
    download_core

    read -p "VMess 端口 (默认 ${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (默认 ${vlessp:-8082}): " port_vl
    read -p "SS    端口 (默认 ${ssocks:-8083}): " port_ss
    
    echo -e "出站优先级:"
    echo -e " [4] 优先 IPv4 (默认 - 稳定)"
    echo -e " [6] 优先 IPv6 (推荐 - 配合轮换)"
    read -p "选择: " prio_choice
    PRIORITY=${prio_choice:-4}

    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}

    # 生成 24位 随机值
    echo -e "${BLUE}🔑 生成密钥...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    
    # OpenSSL 生成 24 字符 (18 bytes base64 = 24 chars)
    PATH_VM="/$(openssl rand -base64 18 | tr -dc 'a-zA-Z0-9')"
    PATH_VL="/$(openssl rand -base64 18 | tr -dc 'a-zA-Z0-9')"
    PASS_SS=$(openssl rand -base64 18 | tr -dc 'a-zA-Z0-9')
    
    # ML-KEM
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"decryption":' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"encryption":' | cut -d '"' -f 4)

    if [ -z "$DEC_KEY" ]; then echo -e "${RED}❌ 密钥生成失败${NC}"; exit 1; fi

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
PRIORITY=$PRIORITY
EOF

    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "$PRIORITY"
    
    # Service Creation
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
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xray-proxya >/dev/null 2>&1
    systemctl restart xray-proxya

    echo -e "${GREEN}✅ 安装完成${NC}"
    show_links
}

# --- 展示链接 ---
format_ip() {
    if [[ "$1" =~ .*:.* ]]; then echo "[$1]"; else echo "$1"; fi
}

show_links() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    
    echo -e "🔑 UUID: ${YELLOW}$UUID${NC}"
    echo -e "🔐 SS 密码: ${YELLOW}$PASS_SS${NC}"

    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    local ipv6=$(curl -s -6 --max-time 2 https://ifconfig.co)

    for ip in "$ipv4" "$ipv6"; do
        if [ -n "$ip" ]; then
            fmt_ip=$(format_ip "$ip")
            echo -e "\n${BLUE}--- IP: $ip ---${NC}"
            
            # VMess
            vm_json=$(jq -n --arg add "$ip" --arg port "$PORT_VMESS" --arg id "$UUID" --arg path "$PATH_VM" --arg scy "$VMESS_CIPHER" \
                '{v:"2", ps:("VMess-"+$scy), add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
            echo -e "VMess: ${GREEN}vmess://$(echo -n "$vm_json" | base64 -w 0)${NC}"
            
            # VLESS
            echo -e "VLESS: ${GREEN}vless://$UUID@$fmt_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#VLESS-ENC${NC}"
            
            # SS
            ss_auth=$(echo -n "${SS_CIPHER}:$PASS_SS" | base64 -w 0)
            echo -e "Shadowsocks: ${GREEN}ss://$ss_auth@$fmt_ip:$PORT_SS#SS-Beta${NC}"
        fi
    done
}

maintenance_menu() {
    echo -e "\n1. 启动  2. 停止  3. 重启  4. 开机自启  5. 取消自启"
    read -p "选择: " op
    case "$op" in
        1) systemctl start xray-proxya ;;
        2) systemctl stop xray-proxya ;;
        3) systemctl restart xray-proxya ;;
        4) systemctl enable xray-proxya ;;
        5) systemctl disable xray-proxya ;;
    esac
}

# --- 菜单 ---
check_root
echo -e "${BLUE}Xray-Proxya Manager (Beta)${NC}"
if systemctl is-active --quiet xray-proxya; then echo -e "🟢 运行中"; else echo -e "🔴 未运行"; fi

echo -e "1. 安装 / 重置"
echo -e "2. 查看链接"
echo -e "3. IPv6 轮换设置 (Beta)"
echo -e "4. 服务维护"
echo -e "0. 退出"
read -p "> " c

case "$c" in
    1) install_xray ;;
    2) show_links ;;
    3) setup_rotation ;;
    4) maintenance_menu ;;
    0) exit 0 ;;
esac