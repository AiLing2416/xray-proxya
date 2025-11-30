#!/bin/bash

# ==================================================
# Xray-Proxya Manager (Beta)
# ==================================================

# --- 默认加密配置 ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"

# --- 全局变量 ---
CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
XRAY_BIN="$XRAY_DIR/xray"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
JSON_FILE="$XRAY_DIR/config.json"
TIMER_FILE="/etc/systemd/system/xray-proxya-rotate.timer"
ROTATOR_SERVICE="/etc/systemd/system/xray-proxya-rotate.service"
LOCAL_TEST_PORT=10999

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 核心工具函数 ---

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}❌ 错误: 需要 root 权限${NC}"
        exit 1
    fi
}

install_deps() {
    echo -e "${BLUE}📦 正在检测依赖...${NC}"
    local pkgs="curl jq unzip openssl iproute2"
    
    # 检测 Python3 (Debian Cloud-init 经常精简)
    if ! command -v python3 &> /dev/null; then
        pkgs="$pkgs python3"
    fi

    apt-get update -qq >/dev/null
    apt-get install -y $pkgs >/dev/null 2>&1
}

detect_interface() {
    # 基于默认路由检测出口网卡
    DEFAULT_IF=$(ip route show default | awk '/default/ {print $5}' | head -n1)
    if [ -z "$DEFAULT_IF" ]; then
        # 回退策略：取第一个非 lo 网卡
        DEFAULT_IF=$(ls /sys/class/net | grep -v lo | head -n1)
    fi
}

get_xray_download_url() {
    # 策略: 优先 GitHub API (IPv4)，失败则使用 ghproxy (IPv6 友好)
    local api_url="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    local download_url=""

    # 尝试直接访问 (超时 3秒)
    if curl -s -4 --connect-timeout 3 https://www.google.com >/dev/null; then
        download_url=$(curl -s "$api_url" | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
    fi

    # 如果无法获取 (通常是 IPv6 Only 环境或 API 限制)，使用镜像
    if [ -z "$download_url" ] || [ "$download_url" == "null" ]; then
        echo -e "${YELLOW}⚠️  检测到 IPv6 Only 或网络受限，切换至镜像源...${NC}"
        # 获取最新版本号用于拼接镜像链接
        # 这里为了简化，IPv6 环境下如果 API 也不通，尝试硬编码获取或解析 HTML (复杂)。
        # 简单方案：直接尝试下载最新 release 的固定镜像格式
        # 注意：此处假设 ghproxy 可用。
        local ver_tag=$(curl -s -L https://github.com/XTLS/Xray-core/releases/latest | grep -o 'v[0-9]*\.[0-9]*\.[0-9]*' | head -n1)
        if [ -n "$ver_tag" ]; then
             download_url="https://ghproxy.com/https://github.com/XTLS/Xray-core/releases/download/${ver_tag}/Xray-linux-64.zip"
        else
             # 最后的保底：Blind download latest
             echo -e "${RED}❌ 无法获取版本信息，请检查网络。${NC}"
             return 1
        fi
    fi
    echo "$download_url"
}

download_core() {
    echo -e "${BLUE}⬇️  获取 Xray-core...${NC}"
    local url=$(get_xray_download_url)
    
    if [ -z "$url" ]; then return 1; fi

    systemctl stop xray-proxya 2>/dev/null
    mkdir -p "$XRAY_DIR"
    
    curl -L -o /tmp/xray.zip "$url"
    if [ $? -ne 0 ]; then echo -e "${RED}下载失败${NC}"; return 1; fi
    
    unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
    rm /tmp/xray.zip
    chmod +x "$XRAY_BIN"
}

# --- Python 辅助 IP 计算 ---
generate_ipv6_in_cidr() {
    local cidr=$1
    python3 -c "
import ipaddress, random, sys
try:
    net = ipaddress.IPv6Network('$cidr', strict=False)
    if net.prefixlen == 128:
        print(str(net.network_address))
    else:
        # 生成随机主机位
        rand_bits = random.getrandbits(128)
        host_mask = int(net.hostmask)
        net_addr = int(net.network_address)
        # 组合: (网络位) | (随机位 & 主机掩码)
        addr_int = net_addr | (rand_bits & host_mask)
        # 排除全0(网络地址)和全1(有些协议不支持)
        if addr_int == net_addr: addr_int += 1
        print(str(ipaddress.IPv6Address(addr_int)))
except:
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
    local ss_m=${10}
    local ipv6_out=${11} # 轮换的 IPv6 地址
    local priority=${12} # 1=IPv4优先, 2=IPv6优先

    # 构造 Outbounds
    # 默认出站 (自由)
    local out_v4='{ "tag": "out-v4", "protocol": "freedom" }'
    local out_v6='{ "tag": "out-v6", "protocol": "freedom" }'
    
    # 如果指定了 IPv6 出口 IP
    if [ -n "$ipv6_out" ]; then
        out_v6="{ \"tag\": \"out-v6\", \"protocol\": \"freedom\", \"sendThrough\": \"$ipv6_out\" }"
    fi

    # 排序
    local outbounds=""
    if [ "$priority" == "2" ]; then
        outbounds="$out_v6, $out_v4" # IPv6 First
    else
        outbounds="$out_v4, $out_v6" # IPv4 First (Default)
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
      "settings": { "method": "$ss_m", "password": "$ss_pass", "network": "tcp,udp" }
    },
    {
      "tag": "test-http",
      "port": $LOCAL_TEST_PORT,
      "listen": "127.0.0.1",
      "protocol": "http",
      "settings": {}
    }
  ],
  "outbounds": [ $outbounds ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "inboundTag": ["test-http"], "outboundTag": "out-v6" } 
    ]
  }
}
EOF
# 注意：上面的 routing 规则强制测试端口走 out-v6 以验证轮换是否生效
}

# --- 核心操作 ---

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
    install_deps
    detect_interface
    
    echo -e "加密配置: VMess [${YELLOW}$VMESS_CIPHER${NC}] | SS [${YELLOW}$SS_CIPHER${NC}]"
    
    read -p "VMess 端口 (默认 ${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (默认 ${vlessp:-8082}): " port_vl
    read -p "SS    端口 (默认 ${ssocks:-8083}): " port_ss
    
    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}

    for p in $PORT_VMESS $PORT_VLESS $PORT_SS; do
        if ss -lnt | grep -q ":$p "; then echo -e "${RED}⚠️  端口 $p 被占用${NC}"; return; fi
    done

    download_core

    echo -e "${BLUE}🔑 生成密钥...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(openssl rand -hex 12)"
    PATH_VL="/$(openssl rand -hex 12)"
    PASS_SS=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 24)
    
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
DEFAULT_IF=$DEFAULT_IF
EOF

    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "" "1"
    create_service

    echo -e "${GREEN}✅ 安装完成${NC}"
    show_links
}

# --- IPv6 轮换模块 ---

setup_rotation() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    detect_interface

    echo -e "\n=== IPv6 动态轮换设置 ==="
    echo -e "当前接口: ${GREEN}$DEFAULT_IF${NC}"
    echo -e "现有 IPv6 地址参考:"
    ip -6 addr show dev $DEFAULT_IF | grep inet6 | awk '{print "   " $2}'
    echo ""

    read -p "请输入拥有的 CIDR (如 2001:db8::/64): " cidr
    # 简单验证 CIDR 格式
    if [[ ! "$cidr" =~ .*:.*\/[0-9]+ ]]; then echo -e "${RED}格式错误${NC}"; return; fi

    echo -e "优先级设置:"
    echo "1. 优先使用 IPv4 (默认)"
    echo "2. 优先使用 IPv6 (轮换 IP)"
    read -p "选择 [1-2]: " pri
    PRIORITY=${pri:-1}

    read -p "轮换间隔 (分钟): " interval
    if [[ ! "$interval" =~ ^[0-9]+$ ]]; then interval=60; fi

    # 测试生成
    echo -e "正在测试生成 IP..."
    local test_ip=$(generate_ipv6_in_cidr "$cidr")
    if [ -z "$test_ip" ]; then echo -e "${RED}生成失败，请检查 CIDR${NC}"; return; fi
    echo -e "测试生成成功: $test_ip"

    # 保存轮换配置
    echo "ROTATE_CIDR=$cidr" >> "$CONF_FILE"
    echo "ROTATE_PRIORITY=$PRIORITY" >> "$CONF_FILE"
    # 清理旧的重复行
    sort -u -t '=' -k 1,1 "$CONF_FILE" -o "$CONF_FILE"

    # 创建 Systemd Timer
    cat > "$ROTATOR_SERVICE" <<EOF
[Unit]
Description=Xray IPv6 Rotator

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xray-proxya --rotate
EOF

    cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Run Xray IPv6 Rotator

[Timer]
OnBootSec=5min
OnUnitActiveSec=${interval}min

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now xray-proxya-rotate.timer
    
    echo -e "${GREEN}✅ 轮换任务已设定 (每 ${interval} 分钟)${NC}"
    echo -e "正在执行首次轮换测试..."
    perform_rotation
}

perform_rotation() {
    source "$CONF_FILE"
    detect_interface
    
    if [ -z "$ROTATE_CIDR" ]; then echo "未配置轮换"; exit 1; fi

    local new_ip=$(generate_ipv6_in_cidr "$ROTATE_CIDR")
    if [ -z "$new_ip" ]; then echo "生成 IP 失败"; exit 1; fi

    echo "新 IP: $new_ip"

    # 1. 绑定新 IP
    ip -6 addr add "$new_ip/${ROTATE_CIDR#*/}" dev "$DEFAULT_IF"

    # 2. 生成新配置
    local vm_c=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_c=${CFG_SS_CIPHER:-$SS_CIPHER}
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$ss_c" "$new_ip" "$ROTATE_PRIORITY"

    # 3. 重启服务
    systemctl restart xray-proxya

    # 4. 验证 (自检)
    echo "验证连接..."
    # 通过本地 HTTP 代理请求，强制走 out-v6
    local check_ip=$(curl -s -x "http://127.0.0.1:$LOCAL_TEST_PORT" -L --max-time 5 https://ifconfig.co)
    
    if [ "$check_ip" == "$new_ip" ]; then
        echo "✅ 验证成功: $check_ip"
        # 记录成功的 IP 以便下次清理
        if [ -f "$CONF_DIR/last_ipv6" ]; then
            local old_ip=$(cat "$CONF_DIR/last_ipv6")
            # 删除旧 IP (忽略错误)
            ip -6 addr del "$old_ip/${ROTATE_CIDR#*/}" dev "$DEFAULT_IF" 2>/dev/null
        fi
        echo "$new_ip" > "$CONF_DIR/last_ipv6"
    else
        echo "❌ 验证失败 (实际: $check_ip, 预期: $new_ip)"
        echo "正在回滚..."
        # 回滚配置 (不带 IPv6)
        generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$ss_c" "" "1"
        systemctl restart xray-proxya
        ip -6 addr del "$new_ip/${ROTATE_CIDR#*/}" dev "$DEFAULT_IF" 2>/dev/null
    fi
}

# --- 其他功能 ---

show_links() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    
    echo -e "🔑 UUID: ${YELLOW}$UUID${NC}"
    echo -e "🔐 SS 密码: ${YELLOW}$PASS_SS${NC}"
    
    # 获取本地 HTTP 代理检测出的真实出口 IP
    local proxy_ip=$(curl -s -x "http://127.0.0.1:$LOCAL_TEST_PORT" -L --max-time 3 https://ifconfig.co)
    if [ -n "$proxy_ip" ]; then
         echo -e "🔄 当前 IPv6 出口: ${GREEN}$proxy_ip${NC} (由轮换控制)"
    fi

    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me)
    local ipv6=$(curl -s -6 --max-time 2 https://ifconfig.co)

    print_links() {
        local ip=$1
        local label=$2
        if [ -z "$ip" ]; then return; fi
        local fmt_ip=$ip
        if [[ "$ip" =~ .*:.* ]]; then fmt_ip="[$ip]"; fi
        
        local vm_c=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
        local ss_c=${CFG_SS_CIPHER:-$SS_CIPHER}
        
        local vm_json=$(jq -n --arg ip "$ip" --arg pt "$PORT_VMESS" --arg id "$UUID" --arg pa "$PATH_VM" --arg sc "$vm_c" \
            '{v:"2", ps:("VMess-"+$sc), add:$ip, port:$pt, id:$id, aid:"0", scy:$sc, net:"ws", type:"none", host:"", path:$pa, tls:""}')
        local vm_link="vmess://$(echo -n "$vm_json" | base64 -w 0)"
        local vl_link="vless://$UUID@$fmt_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#VLESS-XHTTP-ENC"
        local ss_link="ss://$(echo -n "${ss_c}:$PASS_SS" | base64 -w 0)@$fmt_ip:$PORT_SS#SS-Xray"

        echo -e "\n${BLUE}--- $label ($ip) ---${NC}"
        echo -e "1️⃣  VMess: $vm_link"
        echo -e "2️⃣  VLESS: $vl_link"
        echo -e "3️⃣  SS:    $ss_link"
    }

    print_links "$ipv4" "IPv4"
    print_links "$ipv6" "IPv6"
}

maintenance_menu() {
    while true; do
        echo -e "\n=== 维护 ==="
        echo "1. 启动 (Start)"
        echo "2. 停止 (Stop)"
        echo "3. 重启 (Restart)"
        echo "4. 开机自启 (Enable)"
        echo "5. 取消自启 (Disable)"
        echo "0. 返回"
        read -p "选择: " c
        case "$c" in
            1) systemctl start xray-proxya && echo "OK" ;;
            2) systemctl stop xray-proxya && echo "OK" ;;
            3) systemctl restart xray-proxya && echo "OK" ;;
            4) systemctl enable xray-proxya && echo "OK" ;;
            5) systemctl disable xray-proxya && echo "OK" ;;
            0) return ;;
        esac
    done
}

uninstall_xray() {
    read -p "确认卸载? (y/n): " c
    if [[ "$c" != "y" ]]; then return; fi
    systemctl stop xray-proxya xray-proxya-rotate.timer 2>/dev/null
    systemctl disable xray-proxya xray-proxya-rotate.timer 2>/dev/null
    rm "$SERVICE_FILE" "$TIMER_FILE" "$ROTATOR_SERVICE" 2>/dev/null
    rm -rf "$XRAY_DIR" "$CONF_DIR"
    systemctl daemon-reload
    echo -e "${GREEN}已卸载${NC}"
}

# --- 命令行入口 ---

if [ "$1" == "--rotate" ]; then
    perform_rotation
    exit 0
fi

# --- 主菜单 ---
check_root
echo -e "${BLUE}Xray-Proxya Manager (Beta)${NC}"
# check_status 略过不表，节省篇幅
echo "1. 安装 / 重置"
echo "2. 查看链接"
echo "3. 维护菜单"
echo "4. IPv6 轮换设置 (Beta)"
echo "5. 卸载"
echo "0. 退出"
read -p "选择: " choice

case "$choice" in
    1) install_xray ;;
    2) show_links ;;
    3) maintenance_menu ;;
    4) setup_rotation ;;
    5) uninstall_xray ;;
    0) exit 0 ;;
    *) echo "无效" ;;
esac