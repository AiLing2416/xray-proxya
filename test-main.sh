#!/bin/bash

# ==================================================
# Xray-Proxya Manager (Beta)
# ==================================================

# --- 用户加密偏好 (在此修改) ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"

# --- 全局变量 ---
CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
XRAY_BIN="/usr/local/bin/xray-proxya-core/xray"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
JSON_FILE="$XRAY_DIR/config.json"
ROTATION_LOG="$CONF_DIR/rotation.log"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 基础工具函数 ---

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}❌ 错误: 需要 root 权限${NC}"
        exit 1
    fi
}

install_deps() {
    echo -e "${BLUE}📦 检查并安装依赖...${NC}"
    apt-get update -qq >/dev/null
    
    # 基础工具
    DEPS="curl jq unzip openssl iproute2"
    for dep in $DEPS; do
        if ! command -v $dep &> /dev/null; then
            echo -e "   - 安装 $dep..."
            apt-get install -y $dep >/dev/null 2>&1
        fi
    done

    # 关键依赖: Python3 (用于 CIDR 计算)
    if ! command -v python3 &> /dev/null; then
        echo -e "   - 安装 python3 (用于 IPv6 计算)..."
        apt-get install -y python3 >/dev/null 2>&1
    fi
}

# 自动探测默认网卡
detect_interface() {
    # 尝试通过默认路由获取
    local iface=$(ip route show default | awk '/default/ {print $5}' | head -n 1)
    
    # 如果没有默认路由(罕见)，尝试获取第一个非回环接口
    if [ -z "$iface" ]; then
        iface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | head -n 1)
    fi
    echo "$iface"
}

# 下载 Xray (兼容 IPv6 Only)
download_core() {
    echo -e "${BLUE}⬇️  获取 Xray-core (Beta)...${NC}"
    # 使用 curl -L 自动处理跳转，不强制 -4 或 -6，依赖系统 DNS
    LATEST_URL=$(curl -sL https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
    
    if [ -z "$LATEST_URL" ] || [ "$LATEST_URL" == "null" ]; then
        echo -e "${RED}❌ 下载链接获取失败，请检查网络或 GitHub 连通性${NC}"
        return 1
    fi

    systemctl stop xray-proxya 2>/dev/null
    mkdir -p "$XRAY_DIR"
    
    echo -e "   - 下载中..."
    curl -L -o /tmp/xray.zip "$LATEST_URL"
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ 下载失败${NC}"
        return 1
    fi

    unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
    rm /tmp/xray.zip
    chmod +x "$XRAY_BIN"
}

# Python 辅助: 在 CIDR 内生成随机 IP
python_gen_ip() {
    local cidr=$1
    python3 -c "
import ipaddress, random, sys
try:
    net = ipaddress.IPv6Network('$cidr', strict=False)
    # 排除网络地址和广播地址(如果有)
    num_hosts = net.num_addresses
    if num_hosts < 2:
        print('ERROR_TOO_SMALL')
        sys.exit(1)
    # 随机偏移量
    rand_int = random.randint(1, num_hosts - 1)
    new_ip = net.network_address + rand_int
    print(str(new_ip))
except Exception as e:
    print('ERROR_INVALID')
    sys.exit(1)
"
}

# --- 核心配置逻辑 ---

# 生成 config.json
# 参数: vmess_p, vless_p, ss_p, uuid, vm_path, vl_path, enc, dec, ss_pass, ss_method, rotate_ip(可选), priority(可选)
generate_config() {
    local vmess_p=$1; local vless_p=$2; local ss_p=$3
    local uuid=$4; local vm_path=$5; local vl_path=$6
    local enc_key=$7; local dec_key=$8
    local ss_pass=$9; local ss_method=${10}
    local rotate_ip=${11}
    local priority=${12:-"v4"} # v4 或 v6

    # 构建出站配置
    # Outbound-IPv4 (Freedom)
    local out_v4='{ "tag": "out-v4", "protocol": "freedom", "settings": { "domainStrategy": "UseIPv4" } }'
    
    # Outbound-IPv6 (Freedom, 可能带 sendThrough)
    local send_thru_field=""
    if [ ! -z "$rotate_ip" ]; then
        send_thru_field="\"sendThrough\": \"$rotate_ip\","
    fi
    local out_v6="{ \"tag\": \"out-v6\", \"protocol\": \"freedom\", \"settings\": { ${send_thru_field} \"domainStrategy\": \"UseIPv6\" } }"

    # 路由规则 (决定优先级)
    local rules=""
    if [ "$priority" == "v6" ]; then
        # v6 优先: 默认走 out-v6
        outbounds="[$out_v6, $out_v4]"
    else
        # v4 优先: 默认走 out-v4 (默认情况)
        outbounds="[$out_v4, $out_v6]"
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
      "streamSettings": { "network": "xhttp", "xhttpSettings": { "path": "$vl_path" } }
    },
    {
      "tag": "shadowsocks-in",
      "port": $ss_p,
      "protocol": "shadowsocks",
      "settings": { "method": "$ss_method", "password": "$ss_pass", "network": "tcp,udp" }
    },
    {
      "tag": "test-http",
      "port": 10086,
      "listen": "127.0.0.1",
      "protocol": "http"
    }
  ],
  "outbounds": $outbounds,
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": []
  }
}
EOF
}

# --- IPv6 轮换核心逻辑 ---

# 轮换执行函数 (被定时任务或测试调用)
# 返回值: 0 成功, 1 失败
rotate_execution() {
    source "$CONF_FILE"
    if [ -z "$IPV6_CIDR" ]; then echo "未配置 CIDR"; return 1; fi

    local iface=$(detect_interface)
    echo "使用接口: $iface"

    # 1. 生成新 IP
    local new_ip=$(python_gen_ip "$IPV6_CIDR")
    if [[ "$new_ip" == "ERROR"* ]]; then
        echo "IP 生成失败: $new_ip"
        return 1
    fi
    echo "生成 IP: $new_ip"

    # 2. 绑定新 IP
    ip -6 addr add "$new_ip" dev "$iface"
    if [ $? -ne 0 ]; then echo "绑定 IP 失败"; return 1; fi

    # 3. 更新配置
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" \
                    "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "${CFG_SS_CIPHER:-$SS_CIPHER}" \
                    "$new_ip" "${IPV6_PRIORITY:-v4}"

    # 4. 重启服务
    systemctl restart xray-proxya
    sleep 2

    # 5. 自检 (通过本地 HTTP 代理访问 checkip)
    # 尝试访问 ipconfig.me，只看 IPv6 结果
    local check_res=$(curl -x http://127.0.0.1:10086 -s -L --max-time 5 https://ifconfig.co)
    
    echo "自检结果: $check_res"

    if [[ "$check_res" == *"$new_ip"* ]]; then
        echo "✅ 轮换成功: $new_ip"
        
        # 清理旧 IP (如果有记录)
        if [ -f "$CONF_DIR/current_ipv6" ]; then
            local old_ip=$(cat "$CONF_DIR/current_ipv6")
            if [ ! -z "$old_ip" ] && [ "$old_ip" != "$new_ip" ]; then
                ip -6 addr del "$old_ip" dev "$iface" 2>/dev/null
            fi
        fi
        
        # 保存当前 IP
        echo "$new_ip" > "$CONF_DIR/current_ipv6"
        echo "$(date): Rotated to $new_ip" >> "$ROTATION_LOG"
        return 0
    else
        echo "❌ 自检失败 (出口 IP 不匹配或无法连接)"
        echo "$(date): Failed rotation to $new_ip" >> "$ROTATION_LOG"
        
        # 回滚
        ip -6 addr del "$new_ip" dev "$iface" 2>/dev/null
        # 恢复无绑定配置
        generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" \
                        "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "${CFG_SS_CIPHER:-$SS_CIPHER}" \
                        "" "${IPV6_PRIORITY:-v4}"
        systemctl restart xray-proxya
        return 1
    fi
}

# --- 菜单功能 ---

ipv6_rotation_menu() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}请先安装 Xray${NC}"; return; fi
    source "$CONF_FILE"
    
    local iface=$(detect_interface)
    
    echo -e "\n=== IPv6 轮换设置 (Beta) ==="
    echo -e "接口: ${YELLOW}$iface${NC}"
    echo -e "当前 IPv6 地址参考:"
    ip -6 addr show dev "$iface" scope global | awk '{print "   " $2}'
    echo -e "--------------------------------"
    
    echo -e "1. 启用/配置轮换"
    echo -e "2. 立即测试轮换"
    echo -e "3. 停止并禁用轮换"
    echo -e "0. 返回"
    read -p "选择: " r_choice

    case "$r_choice" in
        1)
            read -p "请输入 IPv6 CIDR (如 2001:db8::/64): " user_cidr
            # 简单验证
            local test_ip=$(python_gen_ip "$user_cidr")
            if [[ "$test_ip" == "ERROR"* ]]; then
                echo -e "${RED}无效的 CIDR 格式或范围太小${NC}"
                return
            fi
            
            echo -e "出站优先级:"
            echo -e "1) IPv4 优先 (特定情况走 IPv6)"
            echo -e "2) IPv6 优先 (默认走轮换 IP)"
            read -p "选择 [1/2]: " p_choice
            local pri="v4"
            if [ "$p_choice" == "2" ]; then pri="v6"; fi

            read -p "轮换间隔 (分钟): " interval
            if [[ ! "$interval" =~ ^[0-9]+$ ]]; then interval=60; fi

            # 保存配置
            sed -i '/IPV6_CIDR/d' "$CONF_FILE"
            sed -i '/IPV6_PRIORITY/d' "$CONF_FILE"
            echo "IPV6_CIDR=$user_cidr" >> "$CONF_FILE"
            echo "IPV6_PRIORITY=$pri" >> "$CONF_FILE"

            # 创建 Systemd Timer
            echo -e "${BLUE}配置定时任务...${NC}"
            cat > /etc/systemd/system/xray-rotate.service <<EOF
[Unit]
Description=Xray IPv6 Rotation Task

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xray-proxya --rotate
EOF
            cat > /etc/systemd/system/xray-rotate.timer <<EOF
[Unit]
Description=Run Xray IPv6 Rotation every $interval mins

[Timer]
OnBootSec=5min
OnUnitActiveSec=${interval}min
Unit=xray-rotate.service

[Install]
WantedBy=timers.target
EOF
            systemctl daemon-reload
            systemctl enable --now xray-rotate.timer
            echo -e "${GREEN}✅ 轮换已激活 (每 $interval 分钟)${NC}"
            
            read -p "是否立即执行一次测试? (y/n): " do_test
            if [ "$do_test" == "y" ]; then rotate_execution; fi
            ;;
        2)
            echo -e "${BLUE}开始测试... (可能会有短暂连接中断)${NC}"
            rotate_execution
            ;;
        3)
            systemctl disable --now xray-rotate.timer 2>/dev/null
            rm /etc/systemd/system/xray-rotate.service /etc/systemd/system/xray-rotate.timer 2>/dev/null
            systemctl daemon-reload
            
            # 清理残留 IP
            if [ -f "$CONF_DIR/current_ipv6" ]; then
                ip -6 addr del "$(cat "$CONF_DIR/current_ipv6")" dev "$iface" 2>/dev/null
                rm "$CONF_DIR/current_ipv6"
            fi
            
            # 恢复配置
            generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" \
                        "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "${CFG_SS_CIPHER:-$SS_CIPHER}" \
                        "" "${IPV6_PRIORITY:-v4}"
            systemctl restart xray-proxya
            echo -e "${GREEN}✅ 轮换已关闭${NC}"
            ;;
        *) return ;;
    esac
}

install_xray() {
    echo -e "=== 安装向导 (Beta) ==="
    
    # 端口配置
    read -p "VMess 端口 (${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (${vlessp:-8082}): " port_vl
    read -p "SS    端口 (${ssocks:-8083}): " port_ss
    
    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}

    for p in $PORT_VMESS $PORT_VLESS $PORT_SS; do
        if ss -lnt | grep -q ":$p "; then echo -e "${RED}端口 $p 占用${NC}"; return; fi
    done

    install_deps
    download_core

    echo -e "${BLUE}🔑 生成凭证...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(openssl rand -hex 12)"
    PATH_VL="/$(openssl rand -hex 12)"
    PASS_SS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
    
    # ML-KEM Key
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"decryption":' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"encryption":' | cut -d '"' -f 4)

    if [ -z "$DEC_KEY" ]; then echo -e "${RED}密钥生成失败${NC}"; return 1; fi

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
EOF

    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" \
                    "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER"

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

    echo -e "${GREEN}✅ 安装完成${NC}"
    show_links
}

show_links() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    
    echo -e "🔑 UUID: ${YELLOW}$UUID${NC}"
    echo -e "🔐 SS 密码: ${YELLOW}$PASS_SS${NC}"
    echo -e "📂 路径: $PATH_VM (VMess) | $PATH_VL (VLESS)"

    # 获取当前外部 IP
    local ipv4=$(curl -s -4 --max-time 3 https://api.ipify.org || echo "")
    local ipv6=$(curl -s -6 --max-time 3 https://api64.ipify.org || echo "")

    print_link() {
        local ip=$1; local ver=$2
        local fmt_ip=$ip
        if [[ "$ip" =~ .*:.* ]]; then fmt_ip="[$ip]"; fi
        
        local vm_json=$(jq -n --arg add "$ip" --arg port "$PORT_VMESS" --arg id "$UUID" --arg path "$PATH_VM" --arg scy "${CFG_VMESS_CIPHER:-$VMESS_CIPHER}" \
            '{v:"2", ps:("VMess-" + $scy), add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
        local vmess="vmess://$(echo -n "$vm_json" | base64 -w 0)"
        local vless="vless://$UUID@$fmt_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#VLESS-XHTTP-ENC"
        local ss_auth=$(echo -n "${CFG_SS_CIPHER:-$SS_CIPHER}:$PASS_SS" | base64 -w 0)
        local ss="ss://$ss_auth@$fmt_ip:$PORT_SS#SS-Xray"

        echo -e "\n${BLUE}--- $ver 配置 ($ip) ---${NC}"
        echo -e "1️⃣  VMess: ${GREEN}$vmess${NC}"
        echo -e "2️⃣  VLESS: ${GREEN}$vless${NC}"
        echo -e "3️⃣  Shadowsocks: ${GREEN}$ss${NC}"
    }

    if [ -n "$ipv4" ]; then print_link "$ipv4" "IPv4"; fi
    if [ -n "$ipv6" ]; then print_link "$ipv6" "IPv6"; fi
}

change_ports() {
    if [ ! -f "$CONF_FILE" ]; then echo "未安装"; return; fi
    source "$CONF_FILE"
    read -p "新 VMess (回车跳过): " n_vm
    read -p "新 VLESS (回车跳过): " n_vl
    read -p "新 SS    (回车跳过): " n_ss
    [[ ! -z "$n_vm" ]] && sed -i "s/^PORT_VMESS=.*/PORT_VMESS=$n_vm/" "$CONF_FILE"
    [[ ! -z "$n_vl" ]] && sed -i "s/^PORT_VLESS=.*/PORT_VLESS=$n_vl/" "$CONF_FILE"
    [[ ! -z "$n_ss" ]] && sed -i "s/^PORT_SS=.*/PORT_SS=$n_ss/" "$CONF_FILE"
    
    source "$CONF_FILE"
    # 获取当前 IP 状态（如果开启了轮换）
    local current_ip=""
    if [ -f "$CONF_DIR/current_ipv6" ]; then current_ip=$(cat "$CONF_DIR/current_ipv6"); fi
    
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" \
                    "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "${CFG_SS_CIPHER:-$SS_CIPHER}" \
                    "$current_ip" "${IPV6_PRIORITY:-v4}"
    
    systemctl restart xray-proxya
    echo -e "${GREEN}✅ 已更新${NC}"
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
        read -p "选择: " ch
        case "$ch" in
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
    read -p "确认卸载? (y/n): " y
    if [ "$y" != "y" ]; then return; fi
    systemctl stop xray-proxya
    systemctl disable xray-proxya xray-rotate.timer 2>/dev/null
    rm "$SERVICE_FILE" /etc/systemd/system/xray-rotate.service /etc/systemd/system/xray-rotate.timer 2>/dev/null
    rm -rf "$XRAY_DIR" "$CONF_DIR"
    systemctl daemon-reload
    echo -e "${GREEN}✅ 已卸载${NC}"
}

# --- 隐藏入口 (供 Timer 调用) ---
if [ "$1" == "--rotate" ]; then
    rotate_execution
    exit $?
fi

# --- 主入口 ---
check_root
echo -e "${BLUE}Xray-Proxya Manager (Beta)${NC}"
# check_status
if systemctl is-active --quiet xray-proxya; then
    echo -e "🟢 服务: ${GREEN}运行中${NC}"
else
    echo -e "🔴 服务: ${RED}停止${NC}"
fi

echo -e ""
echo "1. 安装 / 重置"
echo "2. 查看链接"
echo "3. 修改端口"
echo "4. 维护菜单"
echo "5. 卸载"
echo "6. IPv6 轮换设置 (Beta)"
echo "0. 退出"
read -p "选择: " main_ch

case "$main_ch" in
    1) install_xray ;;
    2) show_links ;;
    3) change_ports ;;
    4) maintenance_menu ;;
    5) uninstall_xray ;;
    6) ipv6_rotation_menu ;;
    0) exit 0 ;;
    *) echo "无效" ;;
esac