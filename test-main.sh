#!/bin/bash

# ==================================================
# Xray-Proxya Manager (Beta Test Version)
# ==================================================

# --- 用户配置变量 (可在此修改默认加密) ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"
# -----------------------------------------------

# 核心路径定义
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
NC='\033[0m'

# 1. 权限检查
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}❌ 错误: 需要 root 权限${NC}"
        exit 1
    fi
}

# 2. 依赖检查 (Python3 强制要求)
check_deps() {
    echo -e "${BLUE}📦 检查系统依赖...${NC}"
    local deps=("curl" "jq" "openssl" "python3")
    local install_list=""
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            install_list="$install_list $dep"
        fi
    done

    if [ -n "$install_list" ]; then
        echo -e "${YELLOW}⚠️  发现缺失依赖: $install_list，尝试安装...${NC}"
        apt-get update -qq >/dev/null
        apt-get install -y $install_list >/dev/null 2>&1
        
        # 二次检查
        for dep in "${deps[@]}"; do
            if ! command -v "$dep" &> /dev/null; then
                echo -e "${RED}❌ 严重错误: 无法安装依赖 '$dep'。${NC}"
                echo -e "Debian Cloud 镜像可能需要启用 standard 源或手动安装 python3。"
                exit 1
            fi
        done
    fi
}

# 3. 网络接口探测
detect_interface() {
    # 查找默认路由的出口网卡
    DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n 1)
    
    if [ -z "$DEFAULT_IFACE" ]; then
        DEFAULT_IFACE="eth0" # Fallback
    fi
    
    echo -e "${BLUE}🔍 网络探测:${NC}"
    echo -e "   默认网卡: ${GREEN}$DEFAULT_IFACE${NC}"
    echo -e "   现有 IPv6 地址 (供参考):"
    ip -6 addr show dev "$DEFAULT_IFACE" scope global | grep "inet6" | awk '{print "   - " $2}'
    echo ""
}

# 4. Core 下载 / 手动模式
install_core() {
    # 检查是否已存在
    if [ -f "$XRAY_BIN" ]; then
        local ver=$("$XRAY_BIN" version | head -n 1 | awk '{print $2}')
        echo -e "${GREEN}✅ 检测到 Xray Core ($ver)${NC}"
        return 0
    fi

    echo -e "${BLUE}⬇️  尝试从 GitHub 下载 Xray-core...${NC}"
    
    # 测试 GitHub 连通性 (curl -I)
    if curl -s -I --connect-timeout 5 https://api.github.com >/dev/null; then
        LATEST_URL=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
        mkdir -p "$XRAY_DIR"
        curl -L -o /tmp/xray.zip "$LATEST_URL"
        unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
        rm /tmp/xray.zip
        chmod +x "$XRAY_BIN"
    else
        echo -e "${RED}❌ 无法连接 GitHub API (可能是 IPv6 网络问题)。${NC}"
        echo -e "⚠️  请手动安装 Xray Core。"
        echo -e "--------------------------------------------------"
        echo -e "系统信息: $(uname -s) / $(uname -m)"
        echo -e "目标目录: ${YELLOW}$XRAY_DIR${NC}"
        echo -e "文件名:   xray"
        echo -e "--------------------------------------------------"
        echo -e "请下载 Xray-linux-64.zip 解压并将 'xray' 文件放入上述目录，并赋予 +x 权限。"
        echo -e "下载地址示例: https://github.com/XTLS/Xray-core/releases"
        echo -e "--------------------------------------------------"
        read -p "完成上述操作后，按回车键继续检测..." dummy
        
        if [ ! -f "$XRAY_BIN" ]; then
             echo -e "${RED}❌ 未检测到 Xray 文件，安装终止。${NC}"
             exit 1
        fi
        chmod +x "$XRAY_BIN"
    fi
}

# 5. 配置文件生成 (含自检入站)
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
    local priority=${11:-"ipv4"} # ipv4 或 ipv6

    # 路由规则：根据优先级调整
    local routing_rule=""
    if [ "$priority" == "ipv6" ]; then
        # 优先走 IPv6 出站 (tag: outbound-ipv6)
        routing_rule='{ "type": "field", "outboundTag": "outbound-ipv6", "network": "udp,tcp" }'
    else
        # 默认 IPv4，特定域名可走 IPv6 (此处简化为默认走 IPv4/System)
        routing_rule='{ "type": "field", "outboundTag": "outbound-ipv4", "network": "udp,tcp" }'
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
      "settings": {
        "method": "$ss_method",
        "password": "$ss_pass",
        "network": "tcp,udp"
      }
    },
    {
      "tag": "test-in",
      "port": 10086,
      "listen": "127.0.0.1",
      "protocol": "http",
      "settings": {}
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
    "rules": [
      { "type": "field", "inboundTag": ["test-in"], "outboundTag": "outbound-ipv6" },
      $routing_rule
    ]
  }
}
EOF
}

# 6. IPv6 轮换核心逻辑
setup_ipv6_rotation() {
    echo -e "\n=== IPv6 轮换设置 (Beta) ==="
    detect_interface
    
    echo -e "此功能将在指定 CIDR 内随机生成 IP 并绑定到接口，用于出站流量。"
    echo -e "${YELLOW}⚠️  请确保您有权使用该 CIDR，否则会导致网络中断。${NC}"
    
    read -p "请输入 IPv6 CIDR (例 2001:db8::/64): " user_cidr
    
    # Python 校验 CIDR
    if ! python3 -c "import ipaddress; ipaddress.IPv6Network('$user_cidr', strict=False)" 2>/dev/null; then
        echo -e "${RED}❌ 无效的 CIDR 格式。${NC}"
        return
    fi
    
    echo -e "\n优先级设置:"
    echo -e "1. 优先使用 IPv4 (仅特定或测试流量走轮换 IP)"
    echo -e "2. 优先使用 IPv6 (所有流量默认走轮换 IP)"
    read -p "选择 [1-2]: " pri_choice
    local pri_val="ipv4"
    [[ "$pri_choice" == "2" ]] && pri_val="ipv6"

    read -p "轮换间隔 (分钟): " interval
    if [[ ! "$interval" =~ ^[0-9]+$ ]]; then interval=60; fi

    # 生成轮换脚本
    cat > "$ROTATION_SCRIPT" <<EOF
#!/bin/bash
# Auto-generated by Xray-Proxya
source $CONF_DIR/rotation.env
XRAY_CFG="$JSON_FILE"
LOG_FILE="/var/log/xray-proxya-rotation.log"

log() { echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> "\$LOG_FILE"; }

# 1. 生成新 IP (Python)
NEW_IP=\$(python3 -c "import ipaddress, random; net=ipaddress.IPv6Network('$user_cidr', strict=False); print(ipaddress.IPv6Address(random.randint(int(net.network_address), int(net.broadcast_address))))")

# 2. 绑定 IP (IP Alias)
log "Adding IP: \$NEW_IP to $DEFAULT_IFACE"
ip -6 addr add "\$NEW_IP/128" dev "$DEFAULT_IFACE"

# 3. 更新 Xray 配置 (jq)
# 仅更新 outbound-ipv6 的 sendThrough
tmp_json=\$(mktemp)
jq --arg ip "\$NEW_IP" '(.outbounds[] | select(.tag=="outbound-ipv6").sendThrough) = \$ip' "\$XRAY_CFG" > "\$tmp_json" && mv "\$tmp_json" "\$XRAY_CFG"

# 4. 重启 Xray
systemctl restart xray-proxya

# 5. 自检 (Curl Local Proxy -> IP Check)
# 尝试访问 ipconfig.me，如果返回的 IP 不是 NEW_IP，或者失败，则回滚
CHECK_IP=\$(curl -x http://127.0.0.1:10086 -s --max-time 5 https://ipconfig.me || echo "failed")

if [[ "\$CHECK_IP" == *"\$NEW_IP"* ]]; then
    log "Check PASSED. Active IP: \$NEW_IP"
    # 保存当前 IP 以便下次删除
    if [ -f "$CONF_DIR/current_ipv6" ]; then
        OLD_IP=\$(cat "$CONF_DIR/current_ipv6")
        ip -6 addr del "\$OLD_IP/128" dev "$DEFAULT_IFACE" 2>/dev/null
    fi
    echo "\$NEW_IP" > "$CONF_DIR/current_ipv6"
else
    log "Check FAILED (Got: \$CHECK_IP). Rolling back..."
    ip -6 addr del "\$NEW_IP/128" dev "$DEFAULT_IFACE"
    # 这里可以选择是否恢复旧 IP，为简单起见，保持现状(可能回退到无 sendThrough 或上一个 IP)
fi
EOF
    chmod +x "$ROTATION_SCRIPT"

    # 保存环境配置
    echo "DEFAULT_IFACE=$DEFAULT_IFACE" > "$ROTATION_CONF"
    
    # 更新主配置的优先级
    sed -i "s/^PRIORITY=.*/PRIORITY=$pri_val/" "$CONF_FILE"
    # 重新生成主配置以应用优先级
    source "$CONF_FILE"
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "$pri_val"

    # Systemd Timer
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
OnUnitActiveSec=${interval}min
[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now xray-rotate.timer
    
    echo -e "${GREEN}✅ 轮换设置已完成！${NC}"
    echo -e "正在执行首次测试..."
    bash "$ROTATION_SCRIPT"
    echo -e "请检查日志: /var/log/xray-proxya-rotation.log"
}

# 7. 主安装流程
install_xray() {
    echo -e "=== 安装向导 (Beta) ==="
    check_deps
    
    read -p "VMess 端口 (默认 ${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (默认 ${vlessp:-8082}): " port_vl
    read -p "SS    端口 (默认 ${ssocks:-8083}): " port_ss
    
    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}

    # 简单占用检测
    if ss -lnt | grep -q -E ":($PORT_VMESS|$PORT_VLESS|$PORT_SS) "; then
        echo -e "${RED}⚠️  端口被占用，请更换。${NC}"
        return
    fi

    detect_interface
    install_core

    echo -e "${BLUE}🔑 生成密钥...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(openssl rand -hex 12)"
    PATH_VL="/$(openssl rand -hex 12)"
    PASS_SS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
    
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"decryption":' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"encryption":' | cut -d '"' -f 4)

    if [ -z "$DEC_KEY" ]; then
        echo -e "${RED}❌ 密钥生成失败(检查 Xray 版本)。${NC}"
        return 1
    fi

    mkdir -p "$CONF_DIR"
    # 默认优先级 ipv4
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
PRIORITY=ipv4
CFG_VMESS_CIPHER=$VMESS_CIPHER
CFG_SS_CIPHER=$SS_CIPHER
EOF

    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "ipv4"
    
    # Systemd Service
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

    echo -e "${GREEN}✅ 基础安装完成${NC}"
    show_links
}

# 8. 显示链接 (双栈)
show_links() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    
    # 动态获取算法配置
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_cipher=${CFG_SS_CIPHER:-$SS_CIPHER}

    echo -e "🔑 UUID: ${YELLOW}$UUID${NC}"
    echo -e "🔐 SS 密码: ${YELLOW}$PASS_SS${NC}"
    echo -e "📂 路径: VMess [$PATH_VM] | VLESS [$PATH_VL]"

    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    local ipv6=$(curl -s -6 --max-time 2 https://ifconfig.co)

    # 打印函数
    print_links() {
        local ip=$1; local label=$2
        [ -z "$ip" ] && return
        local fmt_ip=$ip
        [[ "$ip" =~ .*:.* ]] && fmt_ip="[$ip]"

        local vmess_json=$(jq -n --arg ip "$ip" --arg pt "$PORT_VMESS" --arg id "$UUID" --arg pa "$PATH_VM" --arg sc "$vm_cipher" \
            '{v:"2", ps:("VMess-"+$sc), add:$ip, port:$pt, id:$id, aid:"0", scy:$sc, net:"ws", type:"none", host:"", path:$pa, tls:""}')
        local vmess="vmess://$(echo -n "$vmess_json" | base64 -w 0)"
        local vless="vless://$UUID@$fmt_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#VLESS-XHTTP"
        local ss_auth=$(echo -n "${ss_cipher}:$PASS_SS" | base64 -w 0)
        local ss="ss://$ss_auth@$fmt_ip:$PORT_SS#SS-Xray"

        echo -e "\n${BLUE}--- $label ($ip) ---${NC}"
        echo -e "1️⃣  VMess: $vmess"
        echo -e "2️⃣  VLESS: $vless"
        echo -e "3️⃣  SS:    $ss"
    }

    print_links "$ipv4" "IPv4"
    print_links "$ipv6" "IPv6"
}

# 菜单系统
check_root
echo -e "${BLUE}Xray-Proxya Manager (Beta)${NC}"
echo "1. 安装 / 重置"
echo "2. 查看链接"
echo "3. IPv6 轮换设置 (Beta)"
echo "4. 服务维护"
echo "5. 卸载"
echo "0. 退出"
read -p "选择: " choice

case "$choice" in
    1) install_xray ;;
    2) show_links ;;
    3) 
       if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}请先安装基础服务${NC}"; exit 1; fi
       source "$CONF_FILE" # 加载变量供 setup 使用
       setup_ipv6_rotation ;;
    4) echo "功能开发中 (Start/Stop/Restart)..."; systemctl restart xray-proxya; echo "已重启" ;;
    5) systemctl stop xray-proxya; systemctl disable xray-proxya xray-rotate.timer; rm -rf "$XRAY_DIR" "$CONF_DIR" "/etc/systemd/system/xray-proxya.service"; systemctl daemon-reload; echo "已卸载" ;;
    0) exit 0 ;;
    *) echo "无效" ;;
esac