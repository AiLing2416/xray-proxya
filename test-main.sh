#!/bin/bash

# ==================================================
# Xray-Proxya Manager (Beta v4 - Complex Net Fix)
# ==================================================

# --- 用户配置变量 ---
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
ROTATION_SCRIPT="$XRAY_DIR/rotate_ipv6.sh"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

check_root() {
    if [ "$EUID" -ne 0 ]; then echo -e "${RED}❌ 需要 root 权限${NC}"; exit 1; fi
}

check_deps() {
    local deps=("curl" "jq" "openssl" "python3" "ip")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo -e "${YELLOW}正在安装依赖: $dep ...${NC}"
            apt-get update -qq && apt-get install -y $dep >/dev/null 2>&1
        fi
    done
}

# --- 核心修复: 智能网络探测 ---

get_phy_iface() {
    # 逻辑: 列出所有接口 -> 排除 docker/vpn/lo -> 找有全球 IPv6 的 -> 取第一个
    # 在你的环境中，这将跳过 warp/wg0/docker0，选中 eth0
    PHY_IFACE=$(ip -o link show up | awk -F': ' '{print $2}' | \
        grep -vE '^(lo|docker|br-|veth|wg|warp|tun|ppp)' | \
        head -n 1)
    
    # 如果没找到，尝试找任何非 lo 的接口
    if [ -z "$PHY_IFACE" ]; then
        PHY_IFACE=$(ip -o link show up | awk -F': ' '{print $2}' | grep -v '^lo' | head -n 1)
    fi
}

get_net_info() {
    get_phy_iface
    
    # 获取物理网卡上的原生 IP (用于轮换绑定的基准)
    # 你的 eth0 没有 IPv4，所以这里 V4 可能是空的，这是正常的
    NATIVE_IPV6=$(ip -6 addr show dev "$PHY_IFACE" scope global | grep inet6 | awk '{print $2}' | head -n 1)
    NATIVE_IPV4=$(ip -4 addr show dev "$PHY_IFACE" | grep inet | awk '{print $2}' | head -n 1)
    
    # 获取出口 IP (用于展示给用户)
    # 因为有 WARP，出口 IP 可能与网卡 IP 不同
    PUB_IPV4=$(curl -s -4 --max-time 2 https://ipconfig.me || echo "无IPv4出口")
    PUB_IPV6=$(curl -s -6 --max-time 2 https://ifconfig.co || echo "无IPv6出口")
}

show_dashboard() {
    get_net_info
    clear
    echo -e "${BLUE}==================================================${NC}"
    echo -e "           Xray-Proxya 面板 (复杂网络版)"
    echo -e "${BLUE}==================================================${NC}"
    
    echo -e "📡 物理接口 (用于轮换): ${CYAN}$PHY_IFACE${NC}"
    echo -e "   本地 IPv6: ${YELLOW}${NATIVE_IPV6:-无}${NC}"
    echo -e "   本地 IPv4: ${YELLOW}${NATIVE_IPV4:-无 (IPv6 Only Host)}${NC}"
    echo -e "   -------------------------------------------"
    echo -e "🌍 实际出口 (WARP/NAT):"
    echo -e "   IPv4: ${GREEN}$PUB_IPV4${NC}"
    echo -e "   IPv6: ${GREEN}$PUB_IPV6${NC}"
    
    echo -e "\n📊 服务状态:"
    
    if systemctl is-active --quiet xray-proxya; then
        echo -e "   Xray Core:     [ ${GREEN}运行中${NC} ]"
    else
        echo -e "   Xray Core:     [ ${RED}已停止${NC} ]"
    fi
    
    if systemctl is-active --quiet xray-rotate.timer; then
        NEXT_RUN=$(systemctl list-timers xray-rotate.timer --no-pager | awk '/xray-rotate.timer/ {print $3, $4}')
        echo -e "   IPv6 轮换任务: [ ${GREEN}已激活${NC} ] (下次: $NEXT_RUN)"
    else
        echo -e "   IPv6 轮换任务: [ ${CYAN}未启用${NC} ]"
    fi
    
    echo -e "${BLUE}==================================================${NC}"
}

# --- 核心功能函数 ---

install_core() {
    if [ -f "$XRAY_BIN" ]; then return 0; fi
    echo -e "${BLUE}⬇️  准备 Xray Core...${NC}"
    
    # 你的环境 github api 必须走 IPv6 (eth0) 或 WARP
    # 这里不做强制指定，依赖系统路由
    if ! curl -s -I --connect-timeout 5 https://api.github.com >/dev/null; then
        echo -e "${RED}⚠️  无法连接 GitHub API${NC}"
        echo -e "请手动上传 'xray' 文件到: ${YELLOW}$XRAY_DIR${NC}"
        read -p "上传并赋予 +x 后按回车..."
        if [ ! -f "$XRAY_BIN" ]; then echo "未找到文件"; exit 1; fi
        chmod +x "$XRAY_BIN"
    else
        LATEST_URL=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
        mkdir -p "$XRAY_DIR"
        curl -L -o /tmp/xray.zip "$LATEST_URL"
        unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
        rm /tmp/xray.zip
        chmod +x "$XRAY_BIN"
    fi
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
      "tag": "test-in", "port": 10086, "listen": "127.0.0.1", "protocol": "http", "settings": {} }
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

setup_rotation() {
    echo -e "\n=== IPv6 轮换设置 (复杂网络优化版) ==="
    get_net_info
    
    echo -e "物理网卡: ${GREEN}$PHY_IFACE${NC}"
    if [ -z "$NATIVE_IPV6" ]; then
        echo -e "${RED}⚠️  警告: 在 $PHY_IFACE 上未检测到全球单播 IPv6 地址。${NC}"
        echo -e "轮换功能依赖于物理网卡上的原生 IPv6 子网。"
    else
        echo -e "参考 IP:  $NATIVE_IPV6"
    fi
    
    echo -e "${YELLOW}请务必输入归属于 $PHY_IFACE 的 CIDR。不要输入 WARP 的地址。${NC}"
    read -p "输入 CIDR (如 2001:db8::/64): " user_cidr
    
    # 简单校验
    if ! python3 -c "import ipaddress; ipaddress.IPv6Network('$user_cidr', strict=False)" 2>/dev/null; then
        echo -e "${RED}❌ CIDR 格式无效${NC}"; return
    fi
    
    echo -e "优先策略: [1] IPv4 (WARP) 优先  [2] IPv6 轮换优先"
    read -p "选择: " pri_choice
    local pri_val="ipv4"
    [[ "$pri_choice" == "2" ]] && pri_val="ipv6"

    read -p "轮换间隔 (分钟，默认 60): " interval
    [[ ! "$interval" =~ ^[0-9]+$ ]] && interval=60

    # 生成轮换脚本
    cat > "$ROTATION_SCRIPT" <<EOF
#!/bin/bash
source $CONF_DIR/rotation.env
XRAY_CFG="$JSON_FILE"
LOG_FILE="/var/log/xray-proxya-rotation.log"

log() { echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> "\$LOG_FILE"; }

# 1. 生成 IP
NEW_IP=\$(python3 -c "import ipaddress, random; net=ipaddress.IPv6Network('$user_cidr', strict=False); print(ipaddress.IPv6Address(random.randint(int(n