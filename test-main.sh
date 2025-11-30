#!/bin/bash

# ==================================================
# Xray-Proxya Manager (Beta/Testing)
# ==================================================

# --- 加密算法配置 ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"

# --- 全局变量 ---
CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
ROTATION_STATE="$CONF_DIR/rotation.state"
XRAY_BIN="/usr/local/bin/xray-proxya-core/xray"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
JSON_FILE="$XRAY_DIR/config.json"
MIRROR_PREFIX="https://git.icrosser.net"

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

get_default_interface() {
    ip route show default | awk '/default/ {print $5}' | head -n1
}

install_deps_and_core() {
    echo -e "${BLUE}📦 检查并安装系统依赖 (python3, jq, curl)...${NC}"
    apt-get update -qq >/dev/null
    apt-get install -y curl jq unzip openssl python3 >/dev/null 2>&1

    # 再次检查关键依赖
    if ! command -v python3 &> /dev/null; then echo -e "${RED}❌ Python3 安装失败${NC}"; exit 1; fi
    if ! command -v jq &> /dev/null; then echo -e "${RED}❌ jq 安装失败${NC}"; exit 1; fi

    echo -e "${BLUE}⬇️  下载 Xray-core (via Mirror)...${NC}"
    
    # 构造镜像 API URL
    local api_url="${MIRROR_PREFIX}/https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    
    # 获取下载直链
    local dl_url=$(curl -s "$api_url" | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
    
    if [ -z "$dl_url" ] || [ "$dl_url" == "null" ]; then
        echo -e "${RED}❌ 无法获取 Xray 下载地址 (API 失败)${NC}"
        exit 1
    fi

    # 构造镜像下载链接
    local full_dl_url="${MIRROR_PREFIX}/${dl_url}"
    echo -e "🔗 镜像源: $full_dl_url"

    systemctl stop xray-proxya 2>/dev/null
    mkdir -p "$XRAY_DIR"
    
    if ! curl -L -o /tmp/xray.zip "$full_dl_url"; then
        echo -e "${RED}❌ Xray 下载失败，终止安装${NC}"
        exit 1
    fi

    unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
    rm /tmp/xray.zip
    chmod +x "$XRAY_BIN"
    
    local ver=$("$XRAY_BIN" version | head -n 1 | awk '{print $2}')
    echo -e "${GREEN}✅ Xray $ver 安装成功${NC}"
}

generate_random() {
    openssl rand -base64 $(($1 * 2)) | tr -dc 'a-zA-Z0-9' | head -c $1
}

# 使用 Python 计算 CIDR 范围内的随机 IP
generate_ipv6_in_cidr() {
    local cidr=$1
    python3 -c "import ipaddress, random; n = ipaddress.IPv6Network('$cidr', strict=False); print(ipaddress.IPv6Address(n.network_address + random.randint(1, n.num_addresses - 1)))" 2>/dev/null
}

check_status() {
    if systemctl is-active --quiet xray-proxya; then
        echo -e "🟢 服务状态: ${GREEN}运行中${NC}"
    else
        echo -e "🔴 服务状态: ${RED}未运行${NC}"
    fi
}

# 生成配置 (支持 IPv6 轮换结构)
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
    local ipv6_out=${11} # 动态 IPv6 地址
    local priority=${12} # 1=IPv4优先, 2=IPv6优先

    # 路由规则构建
    local routing_rule=""
    if [ "$priority" == "2" ]; then
        # IPv6 优先: 默认走 IPv6 出站，失败回退 (由 freedom 自身特性决定，这里主要指定首选)
        # 注意: 如果指定了 sendThrough，freedom 只能走该 IP。
        # 为了稳妥，我们使用 rules 将流量导向 IPv6 tag
        routing_rule='"routing": { "domainStrategy": "AsIs", "rules": [ { "type": "field", "network": "tcp,udp", "outboundTag": "out-ipv6" } ] },'
    else
        # IPv4 优先 (默认): 不强制指定，让 Xray 自动选择，或者默认走 out-ipv4
        routing_rule='"routing": { "domainStrategy": "AsIs", "rules": [ { "type": "field", "network": "tcp,udp", "outboundTag": "out-ipv4" } ] },'
    fi

    # IPv6 出站配置对象
    local out_v6_obj='{ "tag": "out-ipv6", "protocol": "freedom" }'
    if [ -n "$ipv6_out" ]; then
        out_v6_obj="{ \"tag\": \"out-ipv6\", \"protocol\": \"freedom\", \"sendThrough\": \"$ipv6_out\" }"
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
      "tag": "test-http-in",
      "port": 10086,
      "listen": "127.0.0.1",
      "protocol": "http"
    }
  ],
  "outbounds": [
    { "tag": "out-ipv4", "protocol": "freedom" },
    $out_v6_obj
  ],
  $routing_rule
  "policy": {
    "levels": { "0": { "handshake": 4, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 5, "bufferSize": 4 } }
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
    echo -e "=== 安装向导 (Beta) ==="
    
    read -p "VMess 端口 (默认 ${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (默认 ${vlessp:-8082}): " port_vl
    read -p "SS    端口 (默认 ${ssocks:-8083}): " port_ss
    
    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}

    install_deps_and_core # 这里会处理依赖和下载，失败则退出

    echo -e "${BLUE}🔑 生成密钥...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(openssl rand -hex 12)"
    PATH_VL="/$(openssl rand -hex 12)"
    PASS_SS=$(generate_random 24)
    
    local raw_enc=$("$XRAY_BIN" vlessenc)
    DEC_KEY=$(echo "$raw_enc" | grep -A 5 "Authentication: ML-KEM-768" | grep '"decryption":' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$raw_enc" | grep -A 5 "Authentication: ML-KEM-768" | grep '"encryption":' | cut -d '"' -f 4)

    mkdir -p "$CONF_DIR"
    # 保存基础配置
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

    # 默认无 IPv6 轮换，IPv4 优先
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "" "1"
    create_service

    echo -e "${GREEN}✅ 安装完成${NC}"
    show_links
}

# --- IPv6 轮换逻辑 ---

rotate_ipv6_task() {
    # 此函数由定时任务或手动调用
    if [ ! -f "$ROTATION_STATE" ] || [ ! -f "$CONF_FILE" ]; then
        echo "无轮换配置，跳过。"
        return
    fi
    
    source "$CONF_FILE"
    source "$ROTATION_STATE" # 包含 CIDR, IFACE, LAST_IP, PRIORITY

    # 1. 生成新 IP
    local new_ip=$(generate_ipv6_in_cidr "$CIDR")
    if [ -z "$new_ip" ]; then echo "IP 生成失败"; return 1; fi

    echo "新 IP: $new_ip"

    # 2. 绑定新 IP
    ip -6 addr add "$new_ip/128" dev "$IFACE"
    if [ $? -ne 0 ]; then echo "IP 绑定失败"; return 1; fi

    # 3. 更新 Xray 配置
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$CFG_SS_CIPHER" "$new_ip" "$PRIORITY"
    systemctl restart xray-proxya

    # 4. 自检 (通过本地 HTTP 代理测试)
    # 尝试连接 ipconfig.me，5秒超时
    local test_ip=$(curl -x http://127.0.0.1:10086 -s -L --max-time 5 https://ipconfig.me)
    
    echo "测试结果: $test_ip"

    if [[ "$test_ip" == *"$new_ip"* ]]; then
        echo "✅ 验证成功"
        # 5. 清理旧 IP
        if [ -n "$LAST_IP" ]; then
            ip -6 addr del "$LAST_IP/128" dev "$IFACE" 2>/dev/null
        fi
        # 更新状态文件
        sed -i "s|^LAST_IP=.*|LAST_IP=$new_ip|" "$ROTATION_STATE"
    else
        echo "❌ 验证失败 (可能是网络不通)，执行回滚..."
        # 回滚配置
        generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$CFG_SS_CIPHER" "$LAST_IP" "$PRIORITY"
        systemctl restart xray-proxya
        # 删除刚才绑定的无效 IP
        ip -6 addr del "$new_ip/128" dev "$IFACE" 2>/dev/null
    fi
}

setup_rotation() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}请先安装 Xray${NC}"; return; fi
    
    local def_if=$(get_default_interface)
    echo -e "\n=== IPv6 轮换设置 (Beta) ==="
    echo -e "检测到的默认接口: ${GREEN}${def_if:-未知}${NC}"
    
    echo -e "当前接口 IPv6 地址参考:"
    ip -6 addr show dev "$def_if" | grep "inet6" | awk '{print "  " $2}'
    
    read -p "请输入 IPv6 CIDR (如 2001:db8::/64): " cidr_input
    if [ -z "$cidr_input" ]; then return; fi
    
    # 简单校验 CIDR 格式
    if ! python3 -c "import ipaddress; ipaddress.IPv6Network('$cidr_input', strict=False)" 2>/dev/null; then
        echo -e "${RED}CIDR 格式无效${NC}"
        return
    fi
    
    echo -e "优先级设置:"
    echo "1. 优先使用 IPv4 (仅特定分流走 IPv6)"
    echo "2. 优先使用 IPv6 (轮换 IP)"
    read -p "选择 [1/2]: " pri_choice
    local pri=${pri_choice:-1}

    read -p "轮换间隔 (分钟): " interval
    if [[ ! "$interval" =~ ^[0-9]+$ ]]; then interval=60; fi

    # 保存轮换配置
    cat > "$ROTATION_STATE" <<EOF
CIDR=$cidr_input
IFACE=$def_if
PRIORITY=$pri
LAST_IP=
EOF

    # 创建 Systemd Timer
    echo -e "${BLUE}配置 Systemd 定时任务...${NC}"
    
    # Service
    cat > /etc/systemd/system/xray-rotate.service <<EOF
[Unit]
Description=Xray IPv6 Rotation Task

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xray-proxya _rotate_task
EOF

    # Timer
    cat > /etc/systemd/system/xray-rotate.timer <<EOF
[Unit]
Description=Run Xray Rotation every $interval mins

[Timer]
OnBootSec=5min
OnUnitActiveSec=${interval}min
Unit=xray-rotate.service

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now xray-rotate.timer
    
    echo -e "${GREEN}✅ 定时任务已启动${NC}"
    echo -e "正在执行首次轮换测试..."
    rotate_ipv6_task
}

# --- 辅助功能 ---

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

    local vmess_json=$(jq -n --arg add "$ip_addr" --arg port "$PORT_VMESS" --arg id "$UUID" --arg path "$PATH_VM" --arg scy "$vm_cipher" \
      '{v:"2", ps:("VMess-" + $scy), add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
    local vmess_link="vmess://$(echo -n "$vmess_json" | base64 -w 0)"

    local vless_link="vless://$UUID@$fmt_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#VLESS-XHTTP-ENC"

    local ss_auth=$(echo -n "${ss_cipher}:$PASS_SS" | base64 -w 0)
    local ss_link="ss://$ss_auth@$fmt_ip:$PORT_SS#SS-Xray"

    echo -e "\n${BLUE}--- $label ($ip_addr) ---${NC}"
    echo -e "1️⃣  VMess ($vm_cipher): ${GREEN}$vmess_link${NC}"
    echo -e "2️⃣  VLESS (XHTTP-ENC):  ${GREEN}$vless_link${NC}"
    echo -e "3️⃣  Shadowsocks ($ss_cipher): ${GREEN}$ss_link${NC}"
}

show_links() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}无配置${NC}"; return; fi
    source "$CONF_FILE"
    echo -e "🔑 UUID: ${YELLOW}$UUID${NC} | SS密码: ${YELLOW}$PASS_SS${NC}"
    
    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me)
    local ipv6=$(curl -s -6 --max-time 2 https://ifconfig.co)
    
    if [ -n "$ipv4" ]; then print_config_group "$ipv4" "IPv4"; fi
    if [ -n "$ipv6" ]; then print_config_group "$ipv6" "IPv6"; fi
    
    if [ -f "$ROTATION_STATE" ]; then
        source "$ROTATION_STATE"
        if [ -n "$LAST_IP" ]; then
            echo -e "\n${YELLOW}ℹ️  当前动态 IPv6 出口: $LAST_IP${NC}"
        fi
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
    
    # 重新生成配置时需保留 IPv6 轮换状态
    local cur_ip=""
    local cur_pri="1"
    if [ -f "$ROTATION_STATE" ]; then
        source "$ROTATION_STATE"
        cur_ip="$LAST_IP"
        cur_pri="$PRIORITY"
    fi
    
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_cipher=${CFG_SS_CIPHER:-$SS_CIPHER}
    
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$ss_cipher" "$cur_ip" "$cur_pri"
    systemctl restart xray-proxya
    echo -e "${GREEN}✅ 已更新${NC}"
}

maintenance_menu() {
    echo -e "\n1. 启动  2. 停止  3. 重启  4. 开机自启  5. 取消自启  0. 返回"
    read -p "选择: " c
    case "$c" in
        1) systemctl start xray-proxya ;;
        2) systemctl stop xray-proxya ;;
        3) systemctl restart xray-proxya ;;
        4) systemctl enable xray-proxya ;;
        5) systemctl disable xray-proxya ;;
    esac
}

uninstall_xray() {
    read -p "确认卸载? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi
    systemctl stop xray-proxya
    systemctl disable xray-proxya xray-rotate.timer 2>/dev/null
    rm "$SERVICE_FILE" "/etc/systemd/system/xray-rotate.service" "/etc/systemd/system/xray-rotate.timer" 2>/dev/null
    rm -rf "$XRAY_DIR" "$CONF_DIR"
    systemctl daemon-reload
    echo -e "${GREEN}✅ 已卸载${NC}"
}

# --- 入口 ---

# 隐藏的轮换任务入口，供 Systemd 调用
if [ "$1" == "_rotate_task" ]; then
    rotate_ipv6_task
    exit 0
fi

check_root
echo -e "${BLUE}Xray-Proxya Manager (Beta)${NC}"
check_status
echo -e ""
echo "1. 安装 / 重置"
echo "2. 查看链接"
echo "3. 修改端口"
echo "4. 服务维护"
echo "5. 卸载"
echo "6. IPv6 轮换设置 (Beta)"
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
esac
