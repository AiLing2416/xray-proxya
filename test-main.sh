#!/bin/bash

# ==================================================
# Xray-Proxya Manager
# ==================================================

# --- 用户可配置变量 ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"
# --------------------

CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
ROTATOR_CONF="$CONF_DIR/rotator.env"
XRAY_BIN="/usr/local/bin/xray-proxya-core/xray"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
ROTATOR_SERVICE="/etc/systemd/system/xray-ipv6-rotate.service"
ROTATOR_BIN="/usr/local/bin/xray-ipv6-rotator"
JSON_FILE="$XRAY_DIR/config.json"
# 日志文件
LOG_ACCESS="/var/log/xray-access.log"
LOG_ERROR="/var/log/xray-error.log"
LOG_IPV6="/var/log/xray-ipv6.log"

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
    echo -e "${BLUE}📦 安装依赖 (iptables, python3, etc)...${NC}"
    apt-get update -qq >/dev/null
    # 增加 iptables 依赖，防止 ip6tables 命令缺失
    apt-get install -y curl jq unzip openssl python3 iptables >/dev/null 2>&1
}

generate_random() {
    local length=$1
    openssl rand -base64 $((length * 2)) | tr -dc 'a-zA-Z0-9' | head -c $length
}

check_status() {
    # 1. Xray 服务
    if systemctl is-active --quiet xray-proxya; then
        echo -e "🟢 Xray 服务: ${GREEN}运行中${NC}"
    else
        echo -e "🔴 Xray 服务: ${RED}未运行${NC}"
    fi

    # 2. IPv6 轮换
    if systemctl is-active --quiet xray-ipv6-rotate; then
        echo -ne "🟢 IPv6 轮换: ${GREEN}运行中${NC}"
        local current_ip=""
        if [ -f "$LOG_IPV6" ]; then
            current_ip=$(tail -n 1 "$LOG_IPV6" | awk '{print $NF}')
        fi

        if [ -n "$current_ip" ]; then
            echo -ne " | 目标: ${YELLOW}$current_ip${NC}"
            
            # 简易状态检查 (详细检查在调试菜单)
            if [ -f "$CONF_FILE" ]; then
                local dbg=$(grep "PORT_DEBUG" "$CONF_FILE" | cut -d= -f2)
                # 仅做极快检查 (1s)
                if curl -s -6 --max-time 1 -x socks5h://127.0.0.1:$dbg https://ipconfig.me >/dev/null 2>&1; then
                    echo -e " [${GREEN}OK${NC}]"
                else
                    echo -e " [${RED}Check Fail${NC}]"
                fi
            fi
        else
            echo -e " (等待生成...)"
        fi
    else
        echo -e "⚪ IPv6 轮换: 未启用"
    fi
}

download_core() {
    echo -e "${BLUE}⬇️  获取 Xray-core...${NC}"
    LATEST_URL=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
    if [ -z "$LATEST_URL" ]; then echo -e "${RED}❌ 下载失败${NC}"; return 1; fi

    systemctl stop xray-proxya 2>/dev/null
    mkdir -p "$XRAY_DIR"
    curl -L -o /tmp/xray.zip "$LATEST_URL"
    unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
    rm /tmp/xray.zip
    chmod +x "$XRAY_BIN"
}

generate_config() {
    local vmess_p=$1; local vless_p=$2; local ss_p=$3; local uuid=$4
    local vmess_path=$5; local vless_path=$6
    local enc_key=$7; local dec_key=$8; local ss_pass=$9; local ss_method=${10}
    local debug_p=${11}

    # 策略调整: UseIPv4v6 提高兼容性
    cat > "$JSON_FILE" <<EOF
{
  "log": {
    "loglevel": "info",
    "access": "$LOG_ACCESS",
    "error": "$LOG_ERROR"
  },
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
      "tag": "debug-in", "port": $debug_p, "listen": "127.0.0.1", "protocol": "socks",
      "settings": { "udp": true }
    }
  ],
  "outbounds": [ 
    { 
      "protocol": "freedom",
      "settings": { "domainStrategy": "UseIPv4v6" },
      "streamSettings": { "sockopt": { "mark": 255 } }
    } 
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
ExecStartPre=/bin/sh -c 'truncate -s 0 $LOG_ACCESS $LOG_ERROR'
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

# --- IPv6 轮换模块 ---

generate_rotator_script() {
    cat > "$ROTATOR_BIN" <<'EOF'
#!/bin/bash
CONF_FILE="/etc/xray-proxya/rotator.env"
LOG_FILE="/var/log/xray-ipv6.log"

if [ ! -f "$CONF_FILE" ]; then echo "No config"; exit 1; fi
source "$CONF_FILE"

echo "--- Service Started $(date) ---" > "$LOG_FILE"

# 启动时清理残留规则，防止累积
ip6tables -t nat -D POSTROUTING -m mark --mark 255 -j SNAT --to-source "$CURRENT_IP" 2>/dev/null
# 暴力清理可能存在的旧规则 (循环删除直到报错)
while ip6tables -t nat -D POSTROUTING -m mark --mark 255 2>/dev/null; do :; done

cleanup() {
    echo "Stopping..." >> "$LOG_FILE"
    if [ ! -z "$CURRENT_IP" ]; then
        ip6tables -t nat -D POSTROUTING -m mark --mark 255 -j SNAT --to-source "$CURRENT_IP" 2>/dev/null
    fi
    ip route del local "$CIDR" dev lo 2>/dev/null
    exit 0
}
trap cleanup SIGTERM SIGINT

ip route add local "$CIDR" dev lo 2>/dev/null
CURRENT_IP=""

while true; do
    NEW_IP=$(python3 -c "import ipaddress, random; net = ipaddress.IPv6Network('$CIDR'); print(net[random.randint(1, net.num_addresses - 1)])")
    
    if [ -z "$NEW_IP" ]; then
        echo "Gen IP Error" >> "$LOG_FILE"; sleep 60; continue
    fi

    # 仅针对 Xray Mark 255 流量
    ip6tables -t nat -I POSTROUTING 1 -m mark --mark 255 -j SNAT --to-source "$NEW_IP"
    echo "$(date '+%Y-%m-%d %H:%M:%S') Rotated to: $NEW_IP" >> "$LOG_FILE"

    if [ ! -z "$CURRENT_IP" ]; then
        ip6tables -t nat -D POSTROUTING -m mark --mark 255 -j SNAT --to-source "$CURRENT_IP" 2>/dev/null
    fi
    
    CURRENT_IP="$NEW_IP"
    sleep $((INTERVAL * 60))
done
EOF
    chmod +x "$ROTATOR_BIN"

    cat > "$ROTATOR_SERVICE" <<EOF
[Unit]
Description=Xray IPv6 Outbound Rotator
After=network.target xray-proxya.service

[Service]
Type=simple
User=root
ExecStart=$ROTATOR_BIN
ExecStop=/bin/kill -s SIGTERM \$MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

configure_ipv6_rotate() {
    local old_cidr=""
    local old_int=""
    if [ -f "$ROTATOR_CONF" ]; then
        source "$ROTATOR_CONF"
        old_cidr=$CIDR
        old_int=$INTERVAL
    fi

    echo -e "=== 配置 IPv6 轮换 ==="
    echo -e "${BLUE}本机 IPv6:${NC}"
    ip -6 addr show scope global | grep inet6 | awk '{print "   " $2}'
    echo ""
    
    if [ -n "$old_cidr" ]; then
        echo -e "当前: CIDR=[${GREEN}$old_cidr${NC}] 间隔=[${GREEN}$old_int${NC}分]"
        read -p "是否重新配置? (y/n): " reconf
        if [[ "$reconf" != "y" ]]; then return; fi
    fi

    echo -e "\n请输入 IPv6 CIDR (例: 2001:db8:abcd::/64)"
    read -p "CIDR: " input_cidr
    if [[ ! "$input_cidr" =~ .*:.*\/[0-9]+ ]]; then echo -e "${RED}格式错误${NC}"; return; fi

    read -p "轮换间隔 (分钟): " input_interval
    if [[ ! "$input_interval" =~ ^[0-9]+$ ]]; then input_interval=60; fi

    mkdir -p "$CONF_DIR"
    echo "CIDR=$input_cidr" > "$ROTATOR_CONF"
    echo "INTERVAL=$input_interval" >> "$ROTATOR_CONF"

    generate_rotator_script
    systemctl enable xray-ipv6-rotate >/dev/null 2>&1
    systemctl restart xray-ipv6-rotate
    echo -e "${GREEN}✅ 轮换服务已启动${NC}"
    sleep 1
}

# --- 调试菜单 (Debug Menu) ---

debug_info_menu() {
    local dbg_port="未知"
    if [ -f "$CONF_FILE" ]; then
        dbg_port=$(grep "PORT_DEBUG" "$CONF_FILE" | cut -d= -f2)
    fi

    local key
    while true; do
        clear
        echo -e "${BLUE}=== Xray 调试与诊断 ===${NC}"
        echo -e "🔧 本地调试代理: socks5://127.0.0.1:${YELLOW}${dbg_port}${NC}"
        echo -e "----------------------------------------------------"
        
        echo -e "📡 [连通性测试 (通过本地代理)]"
        
        # IPv4 测试
        echo -ne "IPv4 出站: "
        local v4_res=$(curl -s -4 --max-time 3 -x socks5h://127.0.0.1:$dbg_port https://ipconfig.me 2>&1)
        if [[ "$v4_res" =~ ^[0-9]+\. ]]; then
            echo -e "${GREEN}$v4_res${NC}"
        else
            echo -e "${RED}失败 ($v4_res)${NC}"
        fi

        # IPv6 测试
        echo -ne "IPv6 出站: "
        local v6_res=$(curl -s -6 --max-time 5 -x socks5h://127.0.0.1:$dbg_port https://ipconfig.me 2>&1)
        if [[ "$v6_res" =~ : ]]; then
            echo -e "${GREEN}$v6_res${NC}"
        else
            echo -e "${RED}不可用${NC}"
            echo -e "   ➥ 原因可能: 1.CIDR未路由(On-link)需NDP代理 2.网关不支持AnyIP 3.本机无IPv6"
        fi
        
        echo -e "----------------------------------------------------"
        echo -e "⚙️  [配置文件]"
        echo -e "Bin: $XRAY_BIN"
        echo -e "Log: $LOG_ACCESS ($(du -h $LOG_ACCESS 2>/dev/null | cut -f1))"
        if [ -f "$ROTATOR_CONF" ]; then
            source "$ROTATOR_CONF"
            echo -e "Rotator: CIDR=$CIDR (Interval=${INTERVAL}m)"
        fi
        echo -e "----------------------------------------------------"
        echo -e "🔥 [NAT 规则 (SNAT)]"
        ip6tables -t nat -L POSTROUTING -n -v | grep -E "SNAT|mark" | head -n 3
        echo -e "----------------------------------------------------"
        echo -e "🛤️  [路由表 (Local)]"
        ip -6 route show table local | grep "dev lo" | head -n 3
        echo -e "----------------------------------------------------"
        echo -e "按 ${YELLOW}q${NC} 返回，按 ${GREEN}r${NC} 刷新"
        
        read -n 1 -s key
        if [[ "$key" == "q" ]]; then return; fi
    done
}

# --- 菜单逻辑 ---

ipv6_menu() {
    while true; do
        echo -e "\n=== IPv6 轮换配置 ==="
        check_status
        echo ""
        echo "1. 启用 / 修改 CIDR 配置"
        echo "2. 禁用 / 停止 轮换"
        echo "3. 查看轮换日志"
        echo "0. 返回主菜单"
        read -p "选择: " v6_choice
        case "$v6_choice" in
            1) configure_ipv6_rotate ;;
            2) systemctl stop xray-ipv6-rotate; systemctl disable xray-ipv6-rotate; echo -e "${YELLOW}已禁用${NC}" ;;
            3) if [ -f "$LOG_IPV6" ]; then echo -e "${BLUE}--- Log ---${NC}"; tail -n 10 "$LOG_IPV6"; else echo "无日志"; fi ;;
            0) return ;;
            *) echo -e "${RED}无效${NC}" ;;
        esac
    done
}

xray_maintenance_menu() {
    while true; do
        echo -e "\n=== Xray 维护 ==="
        echo "1. 启动 (Start)"
        echo "2. 停止 (Stop)"
        echo "3. 重启 (Restart)"
        echo "4. 自启 (Enable)"
        echo "5. 禁自启 (Disable)"
        echo "0. 返回"
        read -p "选择: " m_choice
        case "$m_choice" in
            1) systemctl start xray-proxya && echo "Done" ;;
            2) systemctl stop xray-proxya && echo "Stopped" ;;
            3) systemctl restart xray-proxya && echo "Restarted" ;;
            4) systemctl enable xray-proxya && echo "Enabled" ;;
            5) systemctl disable xray-proxya && echo "Disabled" ;;
            0) return ;;
            *) echo -e "${RED}无效${NC}" ;;
        esac
    done
}

install_xray() {
    echo -e "=== 安装向导 ==="
    echo -e "加密: VMess [${YELLOW}$VMESS_CIPHER${NC}] | SS [${YELLOW}$SS_CIPHER${NC}]"
    read -p "VMess 端口 (${vmessp:-8081}): " port_vm; PORT_VMESS=${port_vm:-${vmessp:-8081}}
    read -p "VLESS 端口 (${vlessp:-8082}): " port_vl; PORT_VLESS=${port_vl:-${vlessp:-8082}}
    read -p "SS    端口 (${ssocks:-8083}): " port_ss; PORT_SS=${port_ss:-${ssocks:-8083}}

    for p in $PORT_VMESS $PORT_VLESS $PORT_SS; do
        if ss -lnt | grep -q ":$p "; then echo -e "${RED}⚠️ $p 占用${NC}"; return; fi
    done

    install_deps
    download_core

    echo -e "${BLUE}🔑 生成密钥...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(openssl rand -hex 12)"
    PATH_VL="/$(openssl rand -hex 12)"
    PASS_SS=$(generate_random 24)
    PORT_DEBUG=$((RANDOM % 20000 + 40000))
    
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"decryption":' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"encryption":' | cut -d '"' -f 4)

    if [ -z "$DEC_KEY" ]; then echo -e "${RED}❌ 密钥失败${NC}"; return 1; fi

    mkdir -p "$CONF_DIR"
    cat > "$CONF_FILE" <<EOF
PORT_VMESS=$PORT_VMESS
PORT_VLESS=$PORT_VLESS
PORT_SS=$PORT_SS
PORT_DEBUG=$PORT_DEBUG
UUID=$UUID
PATH_VM=$PATH_VM
PATH_VL=$PATH_VL
PASS_SS=$PASS_SS
ENC_KEY=$ENC_KEY
DEC_KEY=$DEC_KEY
CFG_VMESS_CIPHER=$VMESS_CIPHER
CFG_SS_CIPHER=$SS_CIPHER
EOF

    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "$PORT_DEBUG"
    create_service
    echo -e "${GREEN}✅ 安装完成${NC}"
    show_links
}

format_ip() {
    local ip=$1
    if [[ "$ip" =~ .*:.* ]]; then echo "[$ip]"; else echo "$ip"; fi
}

print_config_group() {
    local ip_addr=$1; local label=$2; if [ -z "$ip_addr" ]; then return; fi
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
    echo -e "1️⃣  VMess: ${GREEN}$vmess_link${NC}"
    echo -e "2️⃣  VLESS: ${GREEN}$vless_link${NC}"
    echo -e "3️⃣  Shadowsocks: ${GREEN}$ss_link${NC}"
}

show_links() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}❌ 未安装${NC}"; return; fi
    source "$CONF_FILE"
    echo -e "🔑 UUID: ${YELLOW}$UUID${NC} | 📂 VLESS Path: $PATH_VL"
    
    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    local ipv6=$(curl -s -6 --max-time 2 https://ifconfig.co)
    if [ -n "$ipv4" ]; then print_config_group "$ipv4" "IPv4"; fi
    if [ -n "$ipv6" ]; then print_config_group "$ipv6" "IPv6"; fi
    if [ -z "$ipv4" ] && [ -z "$ipv6" ]; then echo -e "${RED}❌ 无法获取IP${NC}"; fi
}

change_ports() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    echo -e "当前: V=$PORT_VMESS, VL=$PORT_VLESS, SS=$PORT_SS"
    read -p "新 VMess (回车跳过): " new_vm
    read -p "新 VLESS (回车跳过): " new_vl
    read -p "新 SS    (回车跳过): " new_ss
    [[ ! -z "$new_vm" ]] && sed -i "s/^PORT_VMESS=.*/PORT_VMESS=$new_vm/" "$CONF_FILE"
    [[ ! -z "$new_vl" ]] && sed -i "s/^PORT_VLESS=.*/PORT_VLESS=$new_vl/" "$CONF_FILE"
    [[ ! -z "$new_ss" ]] && sed -i "s/^PORT_SS=.*/PORT_SS=$new_ss/" "$CONF_FILE"
    source "$CONF_FILE"
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_cipher=${CFG_SS_CIPHER:-$SS_CIPHER}
    local dbg_port=${PORT_DEBUG:-55555}
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$ss_cipher" "$dbg_port"
    systemctl restart xray-proxya
    echo -e "${GREEN}✅ 已重启${NC}"
}

uninstall_xray() {
    echo -e "${RED}⚠️  警告: 将完全删除 Xray 服务与配置。${NC}"
    read -p "确认卸载? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi
    systemctl stop xray-proxya xray-ipv6-rotate
    systemctl disable xray-proxya xray-ipv6-rotate
    rm "$SERVICE_FILE" "$ROTATOR_SERVICE" "$ROTATOR_BIN"
    rm -rf "$XRAY_DIR" "$CONF_DIR" "$LOG_ACCESS" "$LOG_ERROR" "$LOG_IPV6"
    systemctl daemon-reload
    echo -e "${GREEN}✅ 已卸载${NC}"
}

# --- 主菜单 ---
check_root
while true; do
    echo -e "\n${BLUE}Xray-Proxya Manager${NC}"
    check_status
    echo -e ""
    echo "1. 安装 / 重置"
    echo "2. 查看链接"
    echo "3. 修改端口"
    echo "4. Xray 维护 (启停)"
    echo "5. IPv6 轮换配置"
    echo "d. 调试与诊断 (Debug)"
    echo ""
    echo "9. 卸载"
    echo "0. 退出"
    read -p "选择: " choice

    case "$choice" in
        1) install_xray ;;
        2) show_links ;;
        3) change_ports ;;
        4) xray_maintenance_menu ;;
        5) ipv6_menu ;;
        d) debug_info_menu ;;
        9) uninstall_xray ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效${NC}" ;;
    esac
done
