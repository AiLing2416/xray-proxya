#!/bin/bash

# ==================================================
# Xray-Proxya Manager (Beta)
# ==================================================

# --- 加密套件配置 ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"
# ------------------

CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
ROTATION_CONF="$CONF_DIR/rotation.env"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
XRAY_BIN="$XRAY_DIR/xray"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
JSON_FILE="$XRAY_DIR/config.json"
HTTP_TEST_PORT=10086

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

# 严格依赖检查与架构识别
check_env_and_deps() {
    echo -e "${BLUE}🔍 检查系统环境与依赖...${NC}"
    
    # 1. 自动识别网卡
    DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n 1)
    if [ -z "$DEFAULT_IFACE" ]; then
        # 尝试由 IPv6 路由获取
        DEFAULT_IFACE=$(ip -6 route show default | awk '/default/ {print $5}' | head -n 1)
    fi
    
    if [ -z "$DEFAULT_IFACE" ]; then
        echo -e "${RED}❌ 无法自动检测网络接口，请检查网络配置。${NC}"
        exit 1
    fi
    echo -e "   检测到主网卡: ${GREEN}$DEFAULT_IFACE${NC}"
    
    # 2. 打印现有 IPv6
    echo -e "   当前 IPv6 地址:"
    ip -6 addr show dev "$DEFAULT_IFACE" scope global | grep "inet6" | awk '{print "   - " $2}'

    # 3. 安装基础工具
    local deps=("curl" "jq" "unzip" "openssl")
    local install_list=""
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then install_list="$install_list $dep"; fi
    done
    
    # 4. 特别检查 Python3 (Debian Cloud-init 可能缺失)
    if ! command -v python3 &> /dev/null; then install_list="$install_list python3"; fi

    if [ -n "$install_list" ]; then
        echo -e "${YELLOW}📦 正在安装缺失依赖:$install_list ...${NC}"
        apt-get update -qq >/dev/null
        apt-get install -y $install_list >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ 依赖安装失败，脚本终止。${NC}"
            exit 1
        fi
    fi
}

# IPv6 Only 兼容下载逻辑
download_xray() {
    echo -e "${BLUE}⬇️  正在获取 Xray 最新版本...${NC}"
    
    # 1. 架构检测
    local arch=$(uname -m)
    local xray_arch=""
    case "$arch" in
        x86_64) xray_arch="64" ;;
        aarch64) xray_arch="arm64-v8a" ;;
        *) echo -e "${RED}❌ 不支持的架构: $arch${NC}"; return 1 ;;
    esac

    # 2. 获取版本号 (不使用 API，通过重定向 URL 获取，支持 IPv6)
    # GitHub Web 支持 IPv6，api.github.com 不支持
    local latest_url=$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/XTLS/Xray-core/releases/latest)
    local version_tag=$(basename "$latest_url")

    if [[ -z "$version_tag" || "$version_tag" == "latest" ]]; then
        echo -e "${RED}❌ 无法获取版本号，请检查网络。${NC}"
        return 1
    fi

    local download_link="https://github.com/XTLS/Xray-core/releases/download/${version_tag}/Xray-linux-${xray_arch}.zip"
    echo -e "   检测到版本: ${GREEN}$version_tag${NC} (架构: $xray_arch)"
    echo -e "   下载链接: $download_link"

    # 3. 下载与解压
    systemctl stop xray-proxya 2>/dev/null
    mkdir -p "$XRAY_DIR"
    
    if ! curl -L -o /tmp/xray.zip "$download_link"; then
        echo -e "${RED}❌ 下载失败。${NC}"
        return 1
    fi

    unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
    rm /tmp/xray.zip
    chmod +x "$XRAY_BIN"
    echo -e "${GREEN}✅ Xray Core 安装完成${NC}"
}

# Python 辅助生成随机 IP
python_gen_ip() {
    local cidr=$1
    python3 -c "
import ipaddress, random, sys
try:
    net = ipaddress.IPv6Network('$cidr', strict=False)
    # 排除子网路由任播地址等，简单起见在范围内随机
    # 限制随机范围防止溢出，生成 64位 interface ID 即可满足绝大多数情况
    rand_int = random.getrandbits(64)
    # 确保生成的 IP 在子网内
    ip_int = int(net.network_address) + (rand_int % int(net.num_addresses))
    print(ipaddress.IPv6Address(ip_int))
except Exception as e:
    print('ERROR')
"
}

# 生成配置文件 (双栈 + 自检支持)
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
    local ipv6_out=${11} # 如果有轮换 IP，传入此 IP，否则为空
    local priority=${12} # "4" or "6"

    # 路由规则构建
    local routing_rule=""
    if [ "$priority" == "6" ]; then
        # IPv6 优先：默认走 ipv6 出站，ipv4 回退
        routing_rule='"rules": [ { "type": "field", "outboundTag": "out-ipv6", "network": "udp,tcp" } ]'
    else
        # IPv4 优先 (默认)：默认走 ipv4
        routing_rule='"rules": [ { "type": "field", "outboundTag": "out-ipv4", "network": "udp,tcp" } ]'
    fi

    # IPv6 出站配置
    local v6_settings="{}"
    if [ -n "$ipv6_out" ]; then
        v6_settings="{ \"domainStrategy\": \"UseIPv6\", \"sendThrough\": \"$ipv6_out\" }"
    else
        v6_settings="{ \"domainStrategy\": \"UseIPv6\" }"
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
      "tag": "http-test",
      "listen": "127.0.0.1",
      "port": $HTTP_TEST_PORT,
      "protocol": "http"
    }
  ],
  "outbounds": [
    { "tag": "out-ipv4", "protocol": "freedom", "settings": { "domainStrategy": "UseIPv4" } },
    { "tag": "out-ipv6", "protocol": "freedom", "settings": $v6_settings }
  ],
  "routing": {
    $routing_rule
  }
}
EOF
}

# 核心：执行 IP 轮换与测试
rotate_ip_now() {
    if [ ! -f "$ROTATION_CONF" ] || [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}❌ 未配置轮换或基础配置丢失${NC}"; return 1
    fi
    source "$CONF_FILE"
    source "$ROTATION_CONF"

    echo -e "${BLUE}🔄 开始执行 IPv6 轮换...${NC}"

    # 1. 生成新 IP
    local NEW_IP=$(python_gen_ip "$ROT_CIDR")
    if [ "$NEW_IP" == "ERROR" ] || [ -z "$NEW_IP" ]; then
        echo -e "${RED}❌ IP 生成失败，检查 CIDR 格式。${NC}"; return 1
    fi
    echo -e "   生成 IP: $NEW_IP"

    # 2. 绑定到网卡
    if ! ip -6 addr add "$NEW_IP/${ROT_CIDR##*/}" dev "$ROT_IFACE"; then
        echo -e "${RED}❌ 绑定 IP 失败。${NC}"; return 1
    fi

    # 3. 更新 Xray 配置
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_cipher=${CFG_SS_CIPHER:-$SS_CIPHER}
    # 强制优先使用 IPv6 出站以测试
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$ss_cipher" "$NEW_IP" "$ROT_PRIORITY"
    systemctl restart xray-proxya

    # 4. 自检
    echo -e "   正在验证连通性 (curl -L https://ipconfig.me)..."
    sleep 2 # 等待服务就绪
    local TEST_IP=$(curl -x "http://127.0.0.1:$HTTP_TEST_PORT" -L -s --max-time 5 https://ipconfig.me)

    echo -e "   [测试结果] 目标: $NEW_IP | 实际: $TEST_IP"

    if [[ "$TEST_IP" == *"$NEW_IP"* ]]; then
        echo -e "${GREEN}✅ 验证通过！新 IP 已生效。${NC}"
        
        # 清理旧 IP
        if [ -n "$CURRENT_ROT_IP" ]; then
            ip -6 addr del "$CURRENT_ROT_IP/${ROT_CIDR##*/}" dev "$ROT_IFACE" 2>/dev/null
        fi
        
        # 保存状态
        sed -i '/CURRENT_ROT_IP=/d' "$ROTATION_CONF"
        echo "CURRENT_ROT_IP=$NEW_IP" >> "$ROTATION_CONF"
    else
        echo -e "${RED}❌ 验证失败！回滚配置...${NC}"
        # 回滚 Xray
        generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$ss_cipher" "$CURRENT_ROT_IP" "$ROT_PRIORITY"
        systemctl restart xray-proxya
        # 删除无效的 IP
        ip -6 addr del "$NEW_IP/${ROT_CIDR##*/}" dev "$ROT_IFACE" 2>/dev/null
    fi
}

# 轮换菜单
ipv6_rotation_menu() {
    check_env_and_deps
    
    echo -e "\n=== IPv6 动态轮换 (Beta) ==="
    echo -e "当前网卡: ${GREEN}$DEFAULT_IFACE${NC}"
    if [ -f "$ROTATION_CONF" ]; then
        source "$ROTATION_CONF"
        echo -e "状态: ${GREEN}已配置${NC} (CIDR: $ROT_CIDR, 间隔: ${ROT_INTERVAL}m, 优先: ipv$ROT_PRIORITY)"
    else
        echo -e "状态: ${YELLOW}未配置${NC}"
    fi
    echo "--------------------------"
    echo "1. 配置/更新 轮换策略"
    echo "2. 立即执行一次轮换 (测试)"
    echo "3. 停止并清除轮换"
    echo "0. 返回"
    read -p "选择: " r_choice

    case "$r_choice" in
        1)
            read -p "输入 CIDR (如 2001:db8::/64): " cidr_in
            # 简单验证
            local test_gen=$(python_gen_ip "$cidr_in")
            if [ "$test_gen" == "ERROR" ]; then echo -e "${RED}无效的 CIDR${NC}"; return; fi
            
            read -p "优先使用 IPv4 还是 IPv6? (4/6): " pri_in
            [[ "$pri_in" != "6" ]] && pri_in="4"
            
            read -p "轮换间隔 (分钟): " interval_in
            
            # 保存配置
            cat > "$ROTATION_CONF" <<EOF
ROT_IFACE=$DEFAULT_IFACE
ROT_CIDR=$cidr_in
ROT_PRIORITY=$pri_in
ROT_INTERVAL=$interval_in
EOF
            echo -e "${GREEN}配置已保存。请选择 [2] 进行测试并激活。${NC}"
            ;;
        2)
            rotate_ip_now
            ;;
        3)
            if [ -f "$ROTATION_CONF" ]; then
                source "$ROTATION_CONF"
                if [ -n "$CURRENT_ROT_IP" ]; then
                    ip -6 addr del "$CURRENT_ROT_IP/${ROT_CIDR##*/}" dev "$ROT_IFACE" 2>/dev/null
                fi
                rm "$ROTATION_CONF"
                # 恢复默认配置
                source "$CONF_FILE"
                local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
                local ss_cipher=${CFG_SS_CIPHER:-$SS_CIPHER}
                generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$ss_cipher" "" "4"
                systemctl restart xray-proxya
                echo -e "${GREEN}轮换已关闭，恢复默认 IPv4 优先。${NC}"
            fi
            ;;
    esac
}

# 安装逻辑
install_xray() {
    check_env_and_deps
    
    echo -e "=== 安装向导 (Beta) ==="
    read -p "VMess 端口 (默认 ${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (默认 ${vlessp:-8082}): " port_vl
    read -p "SS    端口 (默认 ${ssocks:-8083}): " port_ss
    
    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}

    for p in $PORT_VMESS $PORT_VLESS $PORT_SS; do
        if ss -lnt | grep -q ":$p "; then echo -e "${RED}⚠️  端口 $p 被占用${NC}"; return; fi
    done

    download_xray || return

    echo -e "${BLUE}🔑 生成密钥 (24位强密码)...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(openssl rand -hex 12)"
    PATH_VL="/$(openssl rand -hex 12)"
    # 生成 24字符 SS 密码
    PASS_SS=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 24)
    
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"decryption":' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"encryption":' | cut -d '"' -f 4)

    if [ -z "$DEC_KEY" ]; then echo -e "${RED}❌ 密钥生成失败${NC}"; return 1; fi

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

    # 初始安装，无轮换，默认 IPv4 优先
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "" "4"
    
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
    
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_cipher=${CFG_SS_CIPHER:-$SS_CIPHER}

    local vmess_json=$(jq -n --arg add "$ip_addr" --arg port "$PORT_VMESS" --arg id "$UUID" --arg path "$PATH_VM" --arg scy "$vm_cipher" \
      '{v:"2", ps:("VMess-"+$scy), add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
    local vmess_link="vmess://$(echo -n "$vmess_json" | base64 -w 0)"
    local vless_link="vless://$UUID@$fmt_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#VLESS-XHTTP-ENC"
    local ss_auth=$(echo -n "${ss_cipher}:$PASS_SS" | base64 -w 0)
    local ss_link="ss://$ss_auth@$fmt_ip:$PORT_SS#SS-Xray"

    echo -e "\n${BLUE}--- $label ($ip_addr) ---${NC}"
    echo -e "1️⃣  VMess ($vm_cipher):"
    echo -e "    ${GREEN}$vmess_link${NC}"
    echo -e "2️⃣  VLESS (XHTTP-ENC):"
    echo -e "    ${GREEN}$vless_link${NC}"
    echo -e "3️⃣  Shadowsocks ($ss_cipher):"
    echo -e "    ${GREEN}$ss_link${NC}"
}

show_links() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    
    echo -e "🔑 UUID: ${YELLOW}$UUID${NC}"
    echo -e "🔐 SS 密码: ${YELLOW}$PASS_SS${NC}"

    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    local ipv6=$(curl -s -6 --max-time 2 https://ifconfig.co)

    if [ -n "$ipv4" ]; then print_config_group "$ipv4" "IPv4 入口"; fi
    if [ -n "$ipv6" ]; then print_config_group "$ipv6" "IPv6 入口"; fi
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
    
    # 保持当前的轮换状态
    local cur_ip=""
    local cur_pri="4"
    if [ -f "$ROTATION_CONF" ]; then
        source "$ROTATION_CONF"
        cur_ip=$CURRENT_ROT_IP
        cur_pri=$ROT_PRIORITY
    fi
    local vm_cipher=${CFG_VMESS_CIPHER:-$VMESS_CIPHER}
    local ss_cipher=${CFG_SS_CIPHER:-$SS_CIPHER}

    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$ss_cipher" "$cur_ip" "$cur_pri"
    systemctl restart xray-proxya
    echo -e "${GREEN}✅ 端口已更新${NC}"
}

maintenance_menu() {
    while true; do
        echo -e "\n=== 维护 ==="
        echo "1. 启动 (Start)"
        echo "2. 停止 (Stop)"
        echo "3. 重启 (Restart)"
        echo "4. 开启自启 (Enable)"
        echo "5. 关闭自启 (Disable)"
        echo "0. 返回"
        read -p "选择: " m_choice
        case "$m_choice" in
            1) systemctl start xray-proxya && echo "Done" ;;
            2) systemctl stop xray-proxya && echo "Done" ;;
            3) systemctl restart xray-proxya && echo "Done" ;;
            4) systemctl enable xray-proxya && echo "Done" ;;
            5) systemctl disable xray-proxya && echo "Done" ;;
            0) return ;;
            *) echo "无效" ;;
        esac
    done
}

uninstall_xray() {
    read -p "确认卸载? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi
    systemctl stop xray-proxya
    systemctl disable xray-proxya
    rm "$SERVICE_FILE"
    rm -rf "$XRAY_DIR"
    rm -rf "$CONF_DIR"
    systemctl daemon-reload
    echo -e "${GREEN}✅ 已卸载${NC}"
}

# 命令行参数支持 (用于定时任务)
if [ "$1" == "rotate" ]; then
    rotate_ip_now
    exit 0
fi

check_root
echo -e "${BLUE}Xray-Proxya Manager (Beta)${NC}"
if systemctl is-active --quiet xray-proxya; then
    echo -e "🟢 运行中"
else
    echo -e "🔴 未运行"
fi

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
    6) ipv6_rotation_menu ;;
    0) exit 0 ;;
    *) echo "无效" ;;
esac
