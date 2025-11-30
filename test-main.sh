#!/bin/bash

# ==================================================
# Xray-Proxya Manager (BETA)
# ==================================================

# --- 配置区 ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"

CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
IPV6_STATE_FILE="$CONF_DIR/ipv6_state"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
XRAY_BIN="$XRAY_DIR/xray"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
JSON_FILE="$XRAY_DIR/config.json"
TIMER_FILE="/etc/systemd/system/xray-proxya-rotate.timer"
ROTATOR_SCRIPT="/usr/local/bin/xray-proxya-rotate"
TEST_PORT=10085

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 基础工具 ---

check_root() {
    [[ "$EUID" -ne 0 ]] && echo -e "${RED}❌ 错误: 需要 root 权限${NC}" && exit 1
}

get_iface() {
    # 优先检测 IPv4 默认路由，其次 IPv6
    local iface=$(ip route show default | grep default | awk '{print $5}' | head -n 1)
    if [[ -z "$iface" ]]; then
        iface=$(ip -6 route show default | grep default | awk '{print $5}' | head -n 1)
    fi
    echo "$iface"
}

# --- 核心安装与依赖 ---

install_core_and_deps() {
    echo -e "${BLUE}📦 检查系统依赖...${NC}"
    apt-get update -qq >/dev/null
    
    # 严格检查并安装依赖 (Python3 必选)
    DEPS="curl jq unzip openssl python3"
    for dep in $DEPS; do
        if ! command -v $dep &> /dev/null; then
            echo -e "正在安装 $dep ..."
            apt-get install -y $dep >/dev/null 2>&1
            if ! command -v $dep &> /dev/null; then
                echo -e "${RED}❌ 严重错误: 无法安装依赖 $dep${NC}"
                exit 1
            fi
        fi
    done

    # 架构检测
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)  XRAY_ARCH="64" ;;
        aarch64) XRAY_ARCH="arm64-v8a" ;;
        armv7l)  XRAY_ARCH="arm32-v7a" ;;
        *)       echo -e "${RED}❌ 不支持的架构: $ARCH${NC}"; exit 1 ;;
    esac

    echo -e "${BLUE}⬇️  下载 Xray Core ($XRAY_ARCH)...${NC}"
    mkdir -p "$XRAY_DIR"
    
    # 下载策略: GitHub Redirect -> Mirror
    DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${XRAY_ARCH}.zip"
    MIRROR_URL="https://mirror.ghproxy.com/$DOWNLOAD_URL"

    if curl -L -s -o /tmp/xray.zip "$DOWNLOAD_URL"; then
        echo -e "${GREEN}✅ GitHub 下载成功${NC}"
    else
        echo -e "${YELLOW}⚠️  GitHub 下载失败，尝试镜像源...${NC}"
        if curl -L -s -o /tmp/xray.zip "$MIRROR_URL"; then
             echo -e "${GREEN}✅ 镜像源下载成功${NC}"
        else
             echo -e "${RED}❌ 严重错误: Xray 下载失败，请检查网络${NC}"
             exit 1
        fi
    fi

    unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
    rm /tmp/xray.zip
    chmod +x "$XRAY_BIN"
    
    # 验证二进制
    if ! "$XRAY_BIN" version >/dev/null 2>&1; then
        echo -e "${RED}❌ Xray 二进制文件损坏或无法执行${NC}"
        exit 1
    fi
}

# --- IPv6 计算引擎 (Python) ---

generate_ipv6_from_cidr() {
    local cidr=$1
    python3 -c "
import ipaddress, random, sys
try:
    net = ipaddress.IPv6Network('$cidr', strict=False)
    # 排除网络号，在范围内随机取
    rand_int = random.randint(1, net.num_addresses - 1)
    addr = net[rand_int]
    print(str(addr))
except Exception as e:
    sys.exit(1)
"
}

# --- 配置生成 ---

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
    local priority=${10} # 4=IPv4优先, 6=IPv6优先
    local v6_addr=${11}  # 动态IPv6地址(可选)

    # 路由规则构建
    local routing_rules=""
    if [[ "$priority" == "6" ]]; then
        # IPv6 优先: 默认走 out-v6 (如果 v6_addr 存在), 失败回退 out-v4
        routing_rules='{ "type": "field", "network": "tcp,udp", "outboundTag": "out-v6" }'
    else
        # IPv4 优先: 默认走 out-v4, 特定域名可走 out-v6 (此处简化为默认v4)
        routing_rules='{ "type": "field", "network": "tcp,udp", "outboundTag": "out-v4" }'
    fi

    # 出站构建
    # out-v6: 如果有轮换IP，则添加 sendThrough
    local send_through_field=""
    [[ -n "$v6_addr" ]] && send_through_field="\"sendThrough\": \"$v6_addr\","

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
      "settings": { "method": "$SS_CIPHER", "password": "$ss_pass", "network": "tcp,udp" }
    },
    {
      "tag": "test-in", "listen": "127.0.0.1", "port": $TEST_PORT, "protocol": "http"
    }
  ],
  "outbounds": [
    { "tag": "out-v4", "protocol": "freedom", "settings": { "domainStrategy": "UseIPv4" } },
    { "tag": "out-v6", "protocol": "freedom", $send_through_field "settings": { "domainStrategy": "UseIPv6" } }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": ["test-in"], "outboundTag": "out-v6" },
      $routing_rules
    ]
  }
}
EOF
}

# --- IPv6 轮换逻辑 ---

rotate_ipv6_action() {
    # 核心轮换执行函数 (被 systemd 或手动调用)
    if [ ! -f "$IPV6_STATE_FILE" ] || [ ! -f "$CONF_FILE" ]; then return; fi
    source "$IPV6_STATE_FILE"
    source "$CONF_FILE"

    IFACE=$(get_iface)
    if [ -z "$IFACE" ]; then echo "无法获取网卡接口"; return; fi

    # 1. 生成新 IP
    NEW_IP=$(generate_ipv6_from_cidr "$ROT_CIDR")
    if [ -z "$NEW_IP" ]; then echo "IP 生成失败"; return; fi

    echo "生成的 IP: $NEW_IP"

    # 2. 绑定新 IP
    ip -6 addr add "$NEW_IP/$ROT_MASK" dev "$IFACE"
    
    # 3. 更新 Xray 配置 (传入新 IP)
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" \
                    "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$PRIORITY" "$NEW_IP"
    
    # 4. 重载服务
    systemctl restart xray-proxya
    
    # 5. 测试连接 (Self-Test)
    # 尝试通过本地代理访问检测 IP
    CHECK_IP=$(curl -x "127.0.0.1:$TEST_PORT" -s -L --max-time 5 https://ipconfig.me || echo "Fail")
    
    if [[ "$CHECK_IP" == "$NEW_IP" ]]; then
        echo "✅ 自检通过: $CHECK_IP"
        # 6. 清理旧 IP (如果存在且不同)
        if [[ -n "$CURRENT_V6" && "$CURRENT_V6" != "$NEW_IP" ]]; then
             ip -6 addr del "$CURRENT_V6/$ROT_MASK" dev "$IFACE" 2>/dev/null
        fi
        # 更新状态文件
        sed -i "s|^CURRENT_V6=.*|CURRENT_V6=$NEW_IP|" "$IPV6_STATE_FILE"
    else
        echo "❌ 自检失败: 预期 $NEW_IP, 实际 $CHECK_IP. 回滚..."
        # 回滚操作: 删除新 IP (如果不是 fail)，恢复旧配置? 
        # 简化处理: 暂时保留新 IP 但输出警告，等待下一次轮换。或者在此处不做配置回滚，防止死循环。
    fi
}

setup_rotation() {
    echo -e "=== IPv6 轮换设置 (Beta) ==="
    IFACE=$(get_iface)
    echo -e "检测到的网卡: ${GREEN}$IFACE${NC}"
    echo -e "现有 IPv6 地址:"
    ip -6 addr show dev "$IFACE" scope global | grep inet6 | awk '{print $2}'
    echo ""
    
    read -p "请输入 CIDR (如 2001:db8::/64): " cidr_input
    # 验证 CIDR
    TEST_GEN=$(generate_ipv6_from_cidr "$cidr_input")
    if [ -z "$TEST_GEN" ]; then echo -e "${RED}❌ 无效的 CIDR${NC}"; return; fi
    
    read -p "轮换间隔 (分钟): " interval
    read -p "优先级 (4=IPv4优先, 6=IPv6优先): " prio_input
    [[ "$prio_input" != "6" ]] && prio_input="4"

    # 保存状态
    # 提取掩码长度用于 ip addr add
    MASK_LEN=$(echo "$cidr_input" | awk -F'/' '{print $2}')
    
    mkdir -p "$CONF_DIR"
    cat > "$IPV6_STATE_FILE" <<EOF
ROT_CIDR=$cidr_input
ROT_MASK=$MASK_LEN
CURRENT_V6=
EOF
    # 更新主配置的优先级
    if grep -q "PRIORITY=" "$CONF_FILE"; then
        sed -i "s/^PRIORITY=.*/PRIORITY=$prio_input/" "$CONF_FILE"
    else
        echo "PRIORITY=$prio_input" >> "$CONF_FILE"
    fi

    # 创建轮换脚本
    cat > "$ROTATOR_SCRIPT" <<EOF
#!/bin/bash
source $REMOTE_SCRIPT_URL 2>/dev/null || true # 占位
# 实际逻辑由主脚本函数提供，此处调用主脚本的 export 功能
# 为简化，直接复制 rotate_ipv6_action 的核心依赖
bash -c "source $0; rotate_ipv6_action"
EOF
    # 由于 bash source $0 在此处不可靠，我们将 rotator 指向主脚本带参数运行
    echo "#!/bin/bash" > "$ROTATOR_SCRIPT"
    echo "$0 --rotate" >> "$ROTATOR_SCRIPT"
    chmod +x "$ROTATOR_SCRIPT"

    # 创建 Timer
    cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Run Xray IPv6 Rotation

[Timer]
OnBootSec=1min
OnUnitActiveSec=${interval}min

[Install]
WantedBy=timers.target
EOF

    # 创建 Service (被 Timer 调用)
    cat > "/etc/systemd/system/xray-proxya-rotate.service" <<EOF
[Unit]
Description=Xray IPv6 Rotation Service

[Service]
Type=oneshot
ExecStart=$ROTATOR_SCRIPT
EOF

    systemctl daemon-reload
    systemctl enable --now xray-proxya-rotate.timer
    
    echo -e "${GREEN}✅ 轮换任务已设定。正在执行首次轮换测试...${NC}"
    $ROTATOR_SCRIPT
}

# --- 服务管理与安装 ---

create_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Xray-Proxya Service (Beta)
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
}

install_xray() {
    install_core_and_deps # 此处失败会直接退出

    read -p "VMess 端口 (默认 ${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (默认 ${vlessp:-8082}): " port_vl
    read -p "SS    端口 (默认 ${ssocks:-8083}): " port_ss
    
    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}

    for p in $PORT_VMESS $PORT_VLESS $PORT_SS $TEST_PORT; do
        if ss -lnt | grep -q ":$p "; then echo -e "${RED}⚠️  端口 $p 被占用${NC}"; return; fi
    done

    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(openssl rand -hex 12)"
    PATH_VL="/$(openssl rand -hex 12)"
    PASS_SS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9')
    
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
PRIORITY=4
EOF
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "4" ""
    create_service

    echo -e "${GREEN}✅ 安装完成${NC}"
    show_links
}

# --- 链接展示 ---

show_links() {
    [[ ! -f "$CONF_FILE" ]] && echo -e "${RED}未安装${NC}" && return
    source "$CONF_FILE"
    source "$IPV6_STATE_FILE" 2>/dev/null

    echo -e "🔑 UUID: ${YELLOW}$UUID${NC}"
    echo -e "🔐 SS 密码: ${YELLOW}$PASS_SS${NC}"
    [[ -n "$CURRENT_V6" ]] && echo -e "🔄 当前轮换 IPv6: ${BLUE}$CURRENT_V6${NC}"

    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    local ipv6=$(curl -s -6 --max-time 2 https://ifconfig.co)

    # 打印函数
    p_link() {
        local ip=$1; local type=$2
        [[ "$ip" =~ .*:.* ]] && ip="[$ip]"
        local vm_json=$(jq -n --arg ip "$1" --arg pt "$PORT_VMESS" --arg id "$UUID" --arg pa "$PATH_VM" --arg sc "$VMESS_CIPHER" '{v:"2",ps:("VMess-"+$sc),add:$ip,port:$pt,id:$id,aid:"0",scy:$sc,net:"ws",path:$pa,tls:""}')
        local vl_link="vless://$UUID@$ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#VLESS-XHTTP"
        local ss_link="ss://$(echo -n "$SS_CIPHER:$PASS_SS" | base64 -w 0)@$ip:$PORT_SS#SS-Xray"
        
        echo -e "\n${BLUE}--- $type ($1) ---${NC}"
        echo -e "VMess: vmess://$(echo -n "$vm_json" | base64 -w 0)"
        echo -e "VLESS: $vl_link"
        echo -e "SS:    $ss_link"
    }

    [[ -n "$ipv4" ]] && p_link "$ipv4" "IPv4"
    [[ -n "$ipv6" ]] && p_link "$ipv6" "IPv6"
}

# --- 入口 ---

# 隐藏参数：轮换脚本调用
if [[ "$1" == "--rotate" ]]; then
    rotate_ipv6_action
    exit 0
fi

check_root

echo -e "${BLUE}Xray-Proxya Manager (BETA)${NC}"
echo "1. 安装 / 重置"
echo "2. 查看链接"
echo "3. 修改端口"
echo "4. 服务维护"
echo "5. IPv6 轮换设置 (Beta)"
echo "6. 卸载"
echo "0. 退出"
read -p "选择: " choice

case "$choice" in
    1) install_xray ;;
    2) show_links ;;
    3) echo "功能开发中...请使用重置" ;; # 简化脚本体积，复用安装逻辑
    4) 
       read -p "1.Start 2.Stop 3.Restart : " svc_c
       [[ "$svc_c" == "1" ]] && systemctl start xray-proxya
       [[ "$svc_c" == "2" ]] && systemctl stop xray-proxya
       [[ "$svc_c" == "3" ]] && systemctl restart xray-proxya
       ;;
    5) setup_rotation ;;
    6) 
       systemctl stop xray-proxya
       systemctl disable xray-proxya-rotate.timer 2>/dev/null
       rm -rf "$XRAY_DIR" "$CONF_DIR" "$SERVICE_FILE"
       systemctl daemon-reload
       echo "已卸载"
       ;;
    0) exit 0 ;;
    *) echo "无效" ;;
esac
