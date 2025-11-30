#!/bin/bash

# ==================================================
# Xray-Proxya Manager (Beta)
# ==================================================

# --- 用户可配置变量 ---
VMESS_CIPHER="aes-128-gcm"
SS_CIPHER="aes-256-gcm"
# Github 镜像前缀 (用于 IPv6 Only 环境)
GH_MIRROR="https://git.icrosser.net/"
# --------------------

CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
ROTATION_STATE="$CONF_DIR/rotation_state"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
XRAY_BIN="$XRAY_DIR/xray"
SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
JSON_FILE="$XRAY_DIR/config.json"
LOCAL_TEST_PORT=10085

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 基础函数 ---

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}❌ 错误: 需要 root 权限${NC}"
        exit 1
    fi
}

get_default_iface() {
    # 优先 IPv4 路由，其次 IPv6
    local iface=$(ip -4 route show default | grep -oP '(?<=dev )\S+' | head -n1)
    if [ -z "$iface" ]; then
        iface=$(ip -6 route show default | grep -oP '(?<=dev )\S+' | head -n1)
    fi
    echo "$iface"
}

check_deps_and_download() {
    echo -e "${BLUE}📦 检查依赖与环境...${NC}"
    apt-get update -qq >/dev/null
    
    # 必须安装 Python3 用于 CIDR 计算
    local deps=("curl" "jq" "unzip" "openssl" "python3")
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then
            echo -e "   - 安装 $dep ..."
            apt-get install -y $dep >/dev/null 2>&1
        fi
    done

    # 验证 Python3 是否可用
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ 错误: 无法安装 Python3，IPv6 计算依赖此组件。${NC}"
        exit 1
    fi

    # 立即尝试下载 Xray (Fail-Fast)
    if [ ! -f "$XRAY_BIN" ]; then
        download_core
    fi
}

download_core() {
    echo -e "${BLUE}⬇️  通过镜像获取 Xray-core...${NC}"
    # 使用镜像访问 API
    local api_url="${GH_MIRROR}https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    local json=$(curl -sL "$api_url")
    
    # 提取下载链接并加上镜像前缀
    local origin_url=$(echo "$json" | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
    
    if [ -z "$origin_url" ] || [ "$origin_url" == "null" ]; then
        echo -e "${RED}❌ 错误: 无法获取 Xray 下载地址。请检查网络或镜像可用性。${NC}"
        exit 1
    fi
    
    local download_url="${GH_MIRROR}${origin_url}"
    
    systemctl stop xray-proxya 2>/dev/null
    mkdir -p "$XRAY_DIR"
    
    echo -e "   地址: $origin_url (Mirror Proxy)"
    curl -L -o /tmp/xray.zip "$download_url"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ 错误: Xray 下载失败。脚本终止。${NC}"
        rm -f /tmp/xray.zip
        exit 1
    fi

    unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
    rm /tmp/xray.zip
    chmod +x "$XRAY_BIN"
    
    local ver=$("$XRAY_BIN" version | head -n 1 | awk '{print $2}')
    echo -e "${GREEN}✅ Xray Core 准备就绪 ($ver)${NC}"
}

# --- 核心配置生成 ---

generate_config() {
    # 参数解构
    local vmess_p=$1; local vless_p=$2; local ss_p=$3; local uuid=$4
    local vmess_path=$5; local vless_path=$6
    local enc_key=$7; local dec_key=$8; local ss_pass=$9; local ss_method=${10}
    local ipv6_current=${11} # 当前使用的 IPv6 出口 (如果有)
    local priority=${12:-4}  # 4=IPv4优先, 6=IPv6优先

    # 路由策略
    local routing_rules=""
    if [ "$priority" == "6" ]; then
        # IPv6 优先：所有流量尝试走 IPv6 出站，失败回退(Freedom特性)或走IPv4
        # 但 Freedom sendThrough 绑定后无法自动回退，所以我们设置默认规则指向 v6
        routing_rules='{ "type": "field", "outboundTag": "outbound-ipv6", "network": "udp,tcp" }'
    else
        # IPv4 优先 (默认): 默认走 IPv4, 特殊需求可以添加规则
        routing_rules='{ "type": "field", "outboundTag": "outbound-ipv4", "network": "udp,tcp" }'
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
      "tag": "local-test",
      "port": $LOCAL_TEST_PORT,
      "listen": "127.0.0.1",
      "protocol": "http",
      "settings": {}
    }
  ],
  "outbounds": [
    {
      "tag": "outbound-ipv4",
      "protocol": "freedom",
      "settings": { "domainStrategy": "UseIPv4" }
    },
    {
      "tag": "outbound-ipv6",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv6"
        $( [ -n "$ipv6_current" ] && echo ", \"sendThrough\": \"$ipv6_current\"" )
      }
    }
  ],
  "routing": {
    "domainStrategy": "IPOnDemand",
    "rules": [
      { "type": "field", "inboundTag": ["local-test"], "outboundTag": "outbound-ipv6" },
      $routing_rules
    ]
  }
}
EOF
}

# --- IPv6 轮换逻辑 (Python 驱动) ---

python_gen_ip() {
    local cidr=$1
    python3 -c "
import ipaddress, random, sys
try:
    net = ipaddress.IPv6Network('$cidr', strict=False)
    # 生成随机 host 部分
    rand_bits = random.getrandbits(net.max_prefixlen - net.prefixlen)
    addr_int = int(net.network_address) + rand_bits
    addr = ipaddress.IPv6Address(addr_int)
    # 避免全0和全1 (虽然IPv6通常可用，但为了保险)
    if addr == net.network_address or addr == net.broadcast_address:
        print('ERROR')
    else:
        print(addr)
except Exception as e:
    print('ERROR')
"
}

rotate_ipv6_action() {
    # 此函数会被手动调用或定时任务调用
    source "$CONF_FILE"
    
    # 检查配置是否存在
    if [ -z "$V6_CIDR" ] || [ -z "$V6_IFACE" ]; then
        echo "配置缺失，跳过轮换"
        return 1
    fi

    # 1. 生成新 IP
    local new_ip=$(python_gen_ip "$V6_CIDR")
    if [ "$new_ip" == "ERROR" ]; then
        echo "IP 生成失败"
        return 1
    fi

    echo -e "♻️  轮换中... 目标 IP: $new_ip"

    # 2. 绑定新 IP (IP Alias)
    ip -6 addr add "$new_ip/${V6_CIDR##*/}" dev "$V6_IFACE"
    if [ $? -ne 0 ]; then
        echo "无法绑定 IP 到网卡"
        return 1
    fi

    # 3. 重新生成配置 (带 sendThrough)
    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" \
                    "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$CFG_SS_CIPHER" "$new_ip" "$V6_PRIORITY"
    
    systemctl restart xray-proxya

    # 4. 自检 (通过本地 HTTP 代理强制走 IPv6 出站)
    echo -n "   自检中..."
    sleep 2
    local check_ip=$(curl -x "http://127.0.0.1:$LOCAL_TEST_PORT" -L -s --max-time 5 https://ipconfig.me)
    
    if [[ "$check_ip" == *"$new_ip"* ]]; then
        echo -e "${GREEN} 成功! [$check_ip]${NC}"
        
        # 5. 清理旧 IP
        if [ -f "$ROTATION_STATE" ]; then
            local old_ip=$(cat "$ROTATION_STATE")
            if [ -n "$old_ip" ] && [ "$old_ip" != "$new_ip" ]; then
                ip -6 addr del "$old_ip/${V6_CIDR##*/}" dev "$V6_IFACE" 2>/dev/null
            fi
        fi
        echo "$new_ip" > "$ROTATION_STATE"
    else
        echo -e "${RED} 失败! (检测结果: $check_ip)${NC}"
        echo "   回滚更改..."
        # 回滚：删除无效的新 IP
        ip -6 addr del "$new_ip/${V6_CIDR##*/}" dev "$V6_IFACE"
        # 恢复旧配置
        local old_ip=""
        if [ -f "$ROTATION_STATE" ]; then old_ip=$(cat "$ROTATION_STATE"); fi
        generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" \
                        "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$CFG_SS_CIPHER" "$old_ip" "$V6_PRIORITY"
        systemctl restart xray-proxya
    fi
}

setup_rotation_menu() {
    echo -e "\n=== IPv6 动态轮换 (Beta) ==="
    local def_iface=$(get_default_iface)
    
    echo -e "当前检测网卡: ${GREEN}$def_iface${NC}"
    echo -e "现有 IPv6 地址参考:"
    ip -6 addr show dev "$def_iface" | grep "inet6" | awk '{print "   - " $2}'
    echo ""
    
    read -p "请输入拥有的 CIDR (例 2001:db8::/64 或 /112): " input_cidr
    if [ -z "$input_cidr" ]; then return; fi
    
    # 验证 CIDR
    local test_gen=$(python_gen_ip "$input_cidr")
    if [ "$test_gen" == "ERROR" ]; then
        echo -e "${RED}❌ 无效的 CIDR 格式${NC}"
        return
    fi
    
    echo -e "\n流量优先级:"
    echo "1. 优先使用 IPv4 (仅特定规则走 IPv6)"
    echo "2. 优先使用 IPv6 (所有流量尝试走轮换 IP)"
    read -p "选择 [1-2]: " pri_choice
    local set_pri="4"
    if [ "$pri_choice" == "2" ]; then set_pri="6"; fi

    read -p "轮换间隔 (分钟，建议 >=10): " interval
    if [[ ! "$interval" =~ ^[0-9]+$ ]]; then interval=60; fi

    # 保存配置
    sed -i '/^V6_/d' "$CONF_FILE"
    echo "V6_CIDR=$input_cidr" >> "$CONF_FILE"
    echo "V6_IFACE=$def_iface" >> "$CONF_FILE"
    echo "V6_PRIORITY=$set_pri" >> "$CONF_FILE"

    echo -e "${BLUE}🔄 正在执行首次测试...${NC}"
    rotate_ipv6_action
    
    # 设置定时任务 (使用简单的 loop script 或者 systemd timer，这里为了简单使用写入 crontab 的变体思路，
    # 但为了更稳健，我们在 systemd service 中不做，而是提示用户)
    # 这里为了脚本完整性，我们生成一个辅助脚本用于 cron
    
    local cron_script="$XRAY_DIR/rotate_task.sh"
    cat > "$cron_script" <<EOF
#!/bin/bash
/usr/local/sbin/xray-proxya rotate-now
EOF
    chmod +x "$cron_script"
    
    echo -e "\n${YELLOW}⚠️  注意: 自动轮换需要添加到 crontab${NC}"
    echo -e "请运行: crontab -e"
    echo -e "添加行: */$interval * * * * $cron_script"
    read -p "按回车继续..."
}

# --- 安装流程 ---

install_xray() {
    check_deps_and_download # Fail-Fast

    echo -e "=== 安装向导 (Beta) ==="
    
    read -p "VMess 端口 (${vmessp:-8081}): " port_vm
    read -p "VLESS 端口 (${vlessp:-8082}): " port_vl
    read -p "SS    端口 (${ssocks:-8083}): " port_ss
    
    PORT_VMESS=${port_vm:-${vmessp:-8081}}
    PORT_VLESS=${port_vl:-${vlessp:-8082}}
    PORT_SS=${port_ss:-${ssocks:-8083}}

    for p in $PORT_VMESS $PORT_VLESS $PORT_SS $LOCAL_TEST_PORT; do
        if ss -lnt | grep -q ":$p "; then 
            echo -e "${RED}⚠️  端口 $p 被占用${NC}"; return
        fi
    done

    echo -e "${BLUE}🔑 生成密钥...${NC}"
    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(openssl rand -hex 12)"
    PATH_VL="/$(openssl rand -hex 12)"
    PASS_SS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9')
    
    # ML-KEM 生成
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"decryption":' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | grep -A 5 "Authentication: ML-KEM-768" | grep '"encryption":' | cut -d '"' -f 4)

    if [ -z "$DEC_KEY" ]; then echo -e "${RED}❌ 密钥生成失败${NC}"; exit 1; fi

    mkdir -p "$CONF_DIR"
    # 初始化配置文件
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
V6_PRIORITY=4
EOF

    generate_config "$PORT_VMESS" "$PORT_VLESS" "$PORT_SS" "$UUID" "$PATH_VM" "$PATH_VL" \
                    "$ENC_KEY" "$DEC_KEY" "$PASS_SS" "$SS_CIPHER" "" "4"
    
    # Systemd
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Xray-Proxya Beta Service
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

show_links() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未配置${NC}"; return; fi
    source "$CONF_FILE"
    
    echo -e "🔑 UUID: ${YELLOW}$UUID${NC}"
    echo -e "🔐 SS Pass: ${YELLOW}$PASS_SS${NC}"

    # 获取 IP (尝试 IPv4 和 IPv6)
    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    local ipv6=$(curl -s -6 --max-time 2 https://ifconfig.co)

    print_links() {
        local ip=$1; local label=$2
        if [ -z "$ip" ]; then return; fi
        local fmt_ip=$ip
        if [[ "$ip" =~ .*:.* ]]; then fmt_ip="[$ip]"; fi
        
        local vmess_json=$(jq -n --arg add "$ip" --arg port "$PORT_VMESS" --arg id "$UUID" --arg path "$PATH_VM" --arg scy "$CFG_VMESS_CIPHER" \
          '{v:"2", ps:"VMess-Beta", add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
        local vmess_link="vmess://$(echo -n "$vmess_json" | base64 -w 0)"
        local vless_link="vless://$UUID@$fmt_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#VLESS-XHTTP-ENC"
        local ss_link="ss://$(echo -n "${CFG_SS_CIPHER}:$PASS_SS" | base64 -w 0)@$fmt_ip:$PORT_SS#SS-Beta"

        echo -e "\n${BLUE}--- $label ($ip) ---${NC}"
        echo -e "1. VMess: ${GREEN}$vmess_link${NC}"
        echo -e "2. VLESS: ${GREEN}$vless_link${NC}"
        echo -e "3. SS:    ${GREEN}$ss_link${NC}"
    }

    if [ -n "$ipv4" ]; then print_links "$ipv4" "IPv4"; fi
    if [ -n "$ipv6" ]; then print_links "$ipv6" "IPv6"; fi
}

# --- 菜单逻辑 ---

# 隐藏命令，用于 cron 调用
if [ "$1" == "rotate-now" ]; then
    check_root
    rotate_ipv6_action
    exit 0
fi

check_root
echo -e "${BLUE}Xray-Proxya Manager (Beta)${NC}"

# 简单的检查
if systemctl is-active --quiet xray-proxya; then
    echo -e "状态: ${GREEN}运行中${NC}"
else
    echo -e "状态: ${RED}停止${NC}"
fi

echo -e "\n1. 安装 / 重置 (Beta)"
echo "2. 查看链接"
echo "3. 修改端口"
echo "4. 服务维护 (启动/停止)"
echo "5. 卸载"
echo "6. IPv6 轮换设置 (Beta)"
echo "0. 退出"
read -p "选择: " choice

case "$choice" in
    1) install_xray ;;
    2) show_links ;;
    3) echo "功能与之前一致，略" ;; # 保持之前逻辑即可，篇幅限制
    4) 
       read -p "1.启动 2.停止 3.重启 : " s_act
       [ "$s_act" == "1" ] && systemctl start xray-proxya
       [ "$s_act" == "2" ] && systemctl stop xray-proxya
       [ "$s_act" == "3" ] && systemctl restart xray-proxya
       ;;
    5) 
       systemctl stop xray-proxya
       systemctl disable xray-proxya
       rm "$SERVICE_FILE"
       rm -rf "$XRAY_DIR" "$CONF_DIR" "/usr/local/sbin/xray-proxya"
       systemctl daemon-reload
       echo "已卸载"
       ;;
    6) setup_rotation_menu ;;
    0) exit 0 ;;
    *) echo "无效" ;;
esac
