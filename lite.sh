#!/bin/bash

# ==================================================
# Xray-Proxya Manager [LITE]
# Supports: Debian/Ubuntu & Alpine (OpenRC)
# ==================================================

# --- 默认配置变量 ---
DEFAULT_PORT_VLESS_KEM=8081
DEFAULT_PORT_REALITY=8443
DEFAULT_PORT_SS=8082
SERVICE_AUTO_RESTART="true"

# 为 true 时覆盖下方所有性能参数, 由 Xray 核心自行管理资源
AUTO_CONFIG="true"

# 内存与资源管理 (防止 OOM)
# HIGH_PERFORMANCE_MODE: true 为高性能(高并发)模式, false 为低功耗(小内存)模式
HIGH_PERFORMANCE_MODE="false"
# MEM_LIMIT: Go 运行时强制回收内存的目标 (建议设为总 RAM 的 60-80%)
MEM_LIMIT="96MiB"
# BUFFER_SIZE: 每条连接的缓冲区大小 (KB), 越小越省内存, 但极限速度会下降
# 算法: 最大连接数 ≈ (MEM_LIMIT - 50MB) / (BUFFER_SIZE * 2)
BUFFER_SIZE=16
# CONN_IDLE: 空闲连接超时自动断开 (秒), 建议 1800 (30分钟) 以保持长连接稳定
CONN_IDLE=1800

# 加密算法
VMESS_CIPHER="chacha20-poly1305"
SS_CIPHER="aes-256-gcm"

# Reality 配置
REALITY_DEST="apple.com:443"
REALITY_SNI="apple.com"

# -----------------

CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
CUSTOM_OUT_FILE="$CONF_DIR/custom_outbound.json"
XRAY_BIN="/usr/local/bin/xray-proxya-core/xray"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
JSON_FILE="$XRAY_DIR/config.json"

# 系统检测
IS_OPENRC=0
if [ -f /etc/alpine-release ] && command -v rc-service >/dev/null 2>&1; then
    IS_OPENRC=1
fi

if [ $IS_OPENRC -eq 1 ]; then
    SERVICE_FILE="/etc/init.d/xray-proxya"
else
    SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
fi

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

install_deps() {
    echo -e "${BLUE}📦 安装/检查依赖...${NC}"
    if [ -f /etc/alpine-release ]; then
        apk update
        apk add curl jq openssl bash coreutils gcompat iproute2 grep libgcc libstdc++ sed gawk unzip dialog ncurses tzdata
    else
        apt-get update -qq >/dev/null
        apt-get install -y curl jq unzip openssl dialog ncurses-bin >/dev/null 2>&1
    fi
}

check_port_occupied() {
    local port=$1
    if command -v ss >/dev/null 2>&1; then
        if ss -lnt | grep -q ":$port "; then return 0; fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -lnt | grep -q ":$port "; then return 0; fi
    fi
    return 1
}

# --- 服务管理 ---

sys_enable() {
    [ $IS_OPENRC -eq 1 ] && rc-update add xray-proxya default >/dev/null 2>&1 || systemctl enable xray-proxya >/dev/null 2>&1
}
sys_disable() {
    [ $IS_OPENRC -eq 1 ] && rc-update del xray-proxya default >/dev/null 2>&1 || systemctl disable xray-proxya >/dev/null 2>&1
}
sys_start() {
    [ $IS_OPENRC -eq 1 ] && rc-service xray-proxya start || systemctl start xray-proxya
}
sys_stop() {
    [ $IS_OPENRC -eq 1 ] && rc-service xray-proxya stop || systemctl stop xray-proxya
}
sys_restart() {
    [ $IS_OPENRC -eq 1 ] && rc-service xray-proxya restart || systemctl restart xray-proxya
}
sys_reload_daemon() {
    [ $IS_OPENRC -eq 0 ] && systemctl daemon-reload
}
check_status() {
    if [ $IS_OPENRC -eq 1 ]; then
        if rc-service xray-proxya status 2>/dev/null | grep -q "started"; then
            echo -e "🟢 服务状态: ${GREEN}运行中 (OpenRC)${NC}"
        else
            echo -e "🔴 服务状态: ${RED}未运行${NC}"
        fi
    else
        if systemctl is-active --quiet xray-proxya; then
            echo -e "🟢 服务状态: ${GREEN}运行中 (Systemd)${NC}"
        else
            echo -e "🔴 服务状态: ${RED}未运行${NC}"
        fi
    fi
}

# --- 核心逻辑 ---

generate_random() {
    openssl rand -base64 $(( $1 * 2 )) | tr -dc 'a-zA-Z0-9' | head -c $1
}

download_core() {
    if [ -f "$XRAY_BIN" ]; then return; fi
    echo -e "${BLUE}⬇️  获取 Xray-core...${NC}"
    LATEST_URL=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
    if [ -z "$LATEST_URL" ]; then echo -e "${RED}❌ 下载失败${NC}"; return 1; fi
    sys_stop 2>/dev/null
    mkdir -p "$XRAY_DIR"
    curl -L -o /tmp/xray.zip "$LATEST_URL"
    unzip -o /tmp/xray.zip -d "$XRAY_DIR" >/dev/null 2>&1
    rm /tmp/xray.zip
    chmod +x "$XRAY_BIN"
}

url_decode() {
    local url_encoded="${1//+/ }"
    printf '%b' "${url_encoded//%/\\x}"
}

decode_base64() {
    local str="$1"
    local mod=$((${#str} % 4))
    if [ $mod -eq 3 ]; then str="${str}="; elif [ $mod -eq 2 ]; then str="${str}=="; elif [ $mod -eq 1 ]; then str="${str}==="; fi
    echo "$str" | base64 -d 2>/dev/null || echo "$str" | base64 -d -i 2>/dev/null
}

parse_link_to_json() {
    local link="$1"
    # VLESS
    if [[ "$link" == vless://* ]]; then
        local tmp="${link#vless://}"
        local uuid="${tmp%%@*}"
        tmp="${tmp#*@}"
        local address_port="${tmp%%\?*}"
        local address="${address_port%:*}"
        local port="${address_port##*:}"
        local query="${link#*\?}"
        query="${query%%\#*}"
        
        local type=$(echo "$query" | sed -n 's/.*type=\([^&]*\).*/\1/p'); [ -z "$type" ] && type="tcp"
        local security=$(echo "$query" | sed -n 's/.*security=\([^&]*\).*/\1/p'); [ -z "$security" ] && security="none"
        local path=$(url_decode "$(echo "$query" | sed -n 's/.*path=\([^&]*\).*/\1/p')")
        local sni=$(url_decode "$(echo "$query" | sed -n 's/.*sni=\([^&]*\).*/\1/p')")

        jq -n -c \
            --arg address "$address" --arg port "$port" --arg uuid "$uuid" \
            --arg type "$type" --arg security "$security" --arg sni "$sni" --arg path "$path" \
            '{
                tag: "custom-out", protocol: "vless",
                settings: { vnext: [{ address: $address, port: ($port | tonumber), users: [{ id: $uuid }] }] },
                streamSettings: {
                    network: $type, security: $security,
                    tlsSettings: { serverName: $sni },
                    ($type + "Settings"): { path: $path }
                }
            }'
        return 0
    fi
    # Shadowsocks
    if [[ "$link" == ss://* ]]; then
        local raw="${link#ss://}"; raw="${raw%%\#*}"
        raw="${raw%%\?*}"
        local decoded=$(decode_base64 "$raw")
        local method=""; local password=""; local address=""; local port=""
        if [[ "$decoded" == *:*@*:* ]]; then
            local auth="${decoded%%@*}"; local addr_full="${decoded#*@}"
            method="${auth%%:*}"; password="${auth#*:}"
            address="${addr_full%%:*}"; port="${addr_full##*:}"
        elif [[ "$raw" == *@* ]]; then
            local b64_auth="${raw%%@*}"; local addr_full="${raw#*@}"
            local auth=$(decode_base64 "$b64_auth")
            method="${auth%%:*}"; password="${auth#*:}"
            address="${addr_full%%:*}"; port="${addr_full##*:}"
        fi
        [ -z "$method" ] || [ -z "$address" ] && return 1
        jq -n -c --arg a "$address" --arg p "$port" --arg m "$method" --arg pass "$password" \
            '{tag: "custom-out", protocol: "shadowsocks", settings: { servers: [{ address: $a, port: ($p | tonumber), method: $m, password: $pass }] } }'
        return 0
    fi
    # Socks
    if [[ "$link" == socks://* ]]; then
        local raw="${link#socks://}"; raw="${raw%%\#*}"
        raw="${raw%%\?*}"
        local user=""; local pass=""; local addr_port=""
        if [[ "$raw" == *@* ]]; then
             local auth_b64="${raw%%@*}"; addr_port="${raw#*@}"
             local decoded=$(decode_base64 "$auth_b64")
             user="${decoded%%:*}"; pass="${decoded#*:}"
        else addr_port="$raw"; fi
        local address="${addr_port%%:*}"; local port="${addr_port##*:}"
        jq -n -c --arg a "$address" --arg p "$port" --arg u "$user" --arg pass "$pass" \
            '{tag: "custom-out", protocol: "socks", settings: { servers: [{ address: $a, port: ($p | tonumber), users: (if $u != "" then [{user: $u, pass: $pass}] else [] end) }] } }'
        return 0
    fi
    # WireGuard (Link Format)
    if [[ "$link" == wireguard://* ]]; then
        local tmp="${link#wireguard://}"
        local priv_enc="${tmp%%@*}"; tmp="${tmp#*@}"
        local end_addr_port="${tmp%%\?*}"; local end_addr="${end_addr_port%:*}"; local end_port="${end_addr_port##*:}"
        local query="${link#*\?}"
        local pub=$(url_decode "$(echo "$query" | sed -n 's/.*publickey=\([^&#]*\).*/\1/p')")
        local local_addr=$(url_decode "$(echo "$query" | sed -n 's/.*address=\([^&#]*\).*/\1/p')")
        local reserved=$(url_decode "$(echo "$query" | sed -n 's/.*reserved=\([^&#]*\).*/\1/p')")
        local mtu=$(echo "$query" | sed -n 's/.*mtu=\([^&#]*\).*/\1/p'); [ -z "$mtu" ] && mtu=1280
        jq -n -c --arg pub "$pub" --arg priv "$(url_decode "$priv_enc")" --arg addr "$end_addr" --arg port "$end_port" --arg local "$local_addr" --arg res "$reserved" --arg mtu "$mtu" \
            '{
                tag: "custom-out", 
                protocol: "wireguard", 
                settings: { 
                    secretKey: $priv, 
                    address: ($local | split(",")), 
                    reserved: (if $res != "" then ($res | split(",") | map(tonumber)) else null end),
                    peers: [{ publicKey: $pub, endpoint: ($addr + ":" + $port), keepAlive: 25 }], 
                    mtu: ($mtu | tonumber) 
                } 
            } | del(..|nulls)'
        return 0
    fi
    return 1
}

parse_http_proxy() {
    local input="$1"
    if [[ "$input" != *@* ]]; then return 1; fi
    local addr_port="${input##*@}"
    local host="${addr_port%:*}"; local port="${addr_port##*:}"
    local auth="${input%@$addr_port}"
    if [[ "$auth" != *:* ]]; then return 1; fi
    local user="${auth%%:*}"; local pass="${auth#*:}"
    jq -n -c --arg a "$host" --arg p "$port" --arg u "$user" --arg pass "$pass" \
        '{tag: "custom-out", protocol: "http", settings: { servers: [{ address: $a, port: ($p | tonumber), users: [{user: $u, pass: $pass}] }] } }'
}

reinstall_core() {
    echo -e "${BLUE}🔄 正在重装 Xray 核心...${NC}"
    sys_stop 2>/dev/null; rm -rf "$XRAY_DIR"
    if download_core; then
        sys_start; echo -e "${GREEN}✅ 核心重装完成并已重启${NC}"
    else
        echo -e "${RED}❌ 重装失败${NC}"
    fi
}

test_custom_outbound() {
    echo -e "\n=== 连通性测试 (随机端口模式) ==="
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    
    # 随机生成测试端口并更新配置
    PORT_TEST=$((RANDOM % 50000 + 10000))
    PORT_API=$((RANDOM % 50000 + 10000))
    sed -i "s/^PORT_TEST=.*/PORT_TEST=$PORT_TEST/" "$CONF_FILE"
    sed -i "s/^PORT_API=.*/PORT_API=$PORT_API/" "$CONF_FILE"
    echo -e "${BLUE}🔄 正在应用随机测试端口 ($PORT_TEST)...${NC}"
    generate_config; sys_restart
    
    local target_user="direct"
    local target_alias="[直接出站]"
    if [ -f "$CUSTOM_OUT_FILE" ] && [ -s "$CUSTOM_OUT_FILE" ]; then
        target_user="custom"
        target_alias="[自定义出站]"
    fi

    echo -e "正在测试 $target_alias ..."
    local start_time=$(date +%s%N)
    local http_code=$(curl -I -s -o /dev/null -w "%{http_code}" --max-time 10 --proxy-user "$target_user:test" --proxy "socks5h://127.0.0.1:$PORT_TEST" "https://www.google.com")
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 ))

    if [[ "$http_code" =~ ^(200|301|302) ]]; then
        echo -e "${GREEN}✅ 测试通过! (HTTP $http_code)${NC} 耗时: ${duration}ms"
    else
        echo -e "${RED}❌ 测试失败 (HTTP $http_code)${NC}"
    fi
    read -p "按回车继续..."
}

custom_outbound_menu() {
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}❌ 错误: 请先执行 '1. 安装 / 重置' 以生成基本配置。${NC}"
        sleep 2; return
    fi
    while true; do
        echo -e "\n=== 自定义出站 (Lite 单路) ==="
        echo "1. 通过链接导入 (SS, Socks5, VLESS, WireGuard)"
        echo "2. 导入 HTTP 代理 (user:pass@host:port)"
        echo "3. 清除当前出站"
        echo "q. 返回"
        read -p "选择: " choice_sub
        
        local parsed_json=""
        case "$choice_sub" in
            1)
                echo -e "${YELLOW}支持链接: SS, Socks5, VLESS, WireGuard${NC}"
                read -p "请粘贴链接: " link_str
                if [ -n "$link_str" ]; then
                    parsed_json=$(parse_link_to_json "$link_str")
                    [ $? -ne 0 ] && { echo -e "${RED}❌ 解析失败${NC}"; sleep 1; continue; }
                fi
                ;;
            2)
                echo -e "\n--- HTTP 代理导入 ---"
                echo -e "${YELLOW}格式: user:pass@host:port${NC}"
                read -p "请输入: " proxy_str
                if [ -n "$proxy_str" ]; then
                    parsed_json=$(parse_http_proxy "$proxy_str")
                    [ $? -ne 0 ] && { echo -e "${RED}❌ 格式错误${NC}"; sleep 1; continue; }
                fi
                ;;
            3)
                rm -f "$CUSTOM_OUT_FILE"
                echo -e "${GREEN}✅ 已清除自定义出站${NC}"
                source "$CONF_FILE"; generate_config; sys_restart; return
                ;;
            q|Q) return ;;
            *) continue ;;
        esac

        if [ -n "$parsed_json" ] && [ "$parsed_json" != "null" ]; then
            echo "$parsed_json" > "$CUSTOM_OUT_FILE"
            echo -e "${GREEN}✅ 配置已解析并保存${NC}"
            source "$CONF_FILE"
            if [ -z "$UUID_CUSTOM" ]; then
                export UUID_CUSTOM=$("$XRAY_BIN" uuid)
                echo "UUID_CUSTOM=$UUID_CUSTOM" >> "$CONF_FILE"
            fi
            generate_config; sys_restart
            echo -e "${GREEN}服务已重启，规则已生效${NC}"; return
        fi
    done
}

generate_config() {
    # 确保必要目录存在
    mkdir -p "$CONF_DIR" "$XRAY_DIR"
    if [ ! -f "$CUSTOM_OUT_FILE" ] || [ ! -s "$CUSTOM_OUT_FILE" ]; then echo "[]" > "$CUSTOM_OUT_FILE"; fi

    source "$CONF_FILE"

    # 自动探测网络栈
    local has_ipv4=0
    local has_ipv6=0
    if ip -4 route show default 2>/dev/null | grep -q "."; then has_ipv4=1; fi
    if ip -6 route show default 2>/dev/null | grep -q "."; then has_ipv6=1; fi
    
    local dns_strategy="UseIP"
    if [ $has_ipv4 -eq 1 ] && [ $has_ipv6 -eq 0 ]; then
        dns_strategy="UseIPv4"
    elif [ $has_ipv4 -eq 0 ] && [ $has_ipv6 -eq 1 ]; then
        dns_strategy="UseIPv6"
    fi
    local co_args=("--argjson" "custom_outbound" "[]")
    [ -f "$CUSTOM_OUT_FILE" ] && [ -s "$CUSTOM_OUT_FILE" ] && co_args=("--slurpfile" "custom_outbound" "$CUSTOM_OUT_FILE")

    jq -n \
        "${co_args[@]}" \
        --arg port_vless "$PORT_VLESS" --arg dec_key "$DEC_KEY" --arg path_vl "$PATH_VL" \
        --arg port_reality "$PORT_REALITY" --arg reality_dest "$REALITY_DEST" --arg reality_sni "$REALITY_SNI" --arg reality_pk "$REALITY_PK" --arg reality_sid "$REALITY_SID" --arg path_reality "$PATH_REALITY" \
        --arg port_ss "$PORT_SS" --arg ss_cipher "$SS_CIPHER" --arg pass_ss "$PASS_SS" \
        --arg port_test "${PORT_TEST:-10000}" --arg port_api "${PORT_API:-10001}" \
        --arg uuid "$UUID" --arg uuid_custom "$UUID_CUSTOM" \
        --arg buffer_size "${BUFFER_SIZE:-16}" --arg conn_idle "${CONN_IDLE:-1800}" \
        --arg auto_config "${AUTO_CONFIG:-false}" \
        --arg dns_strategy "$dns_strategy" \
        --arg direct_outbound "${DIRECT_OUTBOUND:-true}" \
    '
    ($custom_outbound | flatten(1)) as $co |
    ($buffer_size | tonumber * 1024) as $buf_bytes |
    ($conn_idle | tonumber) as $idle |
    {
        log: { loglevel: "warning" },
        dns: {
            servers: ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "2606:4700:4700::1111"],
            queryStrategy: $dns_strategy
        },
        policy: (if $auto_config == "true" then {} else {
            levels: {
                "0": { handshake: 4, connIdle: $idle, uplinkOnly: 2, downlinkOnly: 4, bufferSize: ($buf_bytes / 1024) }
            },
            system: { statsOutboundUplink: true, statsOutboundDownlink: true }
        } end),
        inbounds: [
            {
                tag: "vless-enc-in", port: ($port_vless | tonumber), protocol: "vless",
                settings: { 
                    clients: (
                        (if $direct_outbound == "true" then [{ id: $uuid, email: "direct" }] else [] end)
                        + (if $uuid_custom != "" then [{ id: $uuid_custom, email: "custom" }] else [] end)
                    ),
                    decryption: $dec_key 
                },
                streamSettings: { network: "xhttp", xhttpSettings: { path: $path_vl } }
            },
            {
                tag: "vless-reality-in", port: ($port_reality | tonumber), protocol: "vless",
                settings: { 
                    clients: (
                        (if $direct_outbound == "true" then [{ id: $uuid, email: "direct" }] else [] end)
                        + (if $uuid_custom != "" then [{ id: $uuid_custom, email: "custom" }] else [] end)
                    ),
                    decryption: "none" 
                },
                streamSettings: {
                    network: "xhttp", security: "reality",
                    realitySettings: { show: false, dest: $reality_dest, xver: 0, serverNames: [$reality_sni], privateKey: $reality_pk, shortIds: [$reality_sid] },
                    xhttpSettings: { path: $path_reality }
                }
            },
            {
                tag: "shadowsocks-in", port: ($port_ss | tonumber), protocol: "shadowsocks",
                settings: { method: $ss_cipher, password: $pass_ss, network: "tcp,udp" }
            },
            {
                tag: "test-in-socks", listen: "127.0.0.1", port: ($port_test | tonumber), protocol: "socks",
                settings: { 
                    auth: "password", 
                    accounts: (
                        (if $direct_outbound == "true" then [{user: "direct", pass: "test"}] else [] end)
                        + [{user: "custom", pass: "test"}]
                    ),
                    udp: true 
                }
            },
            {
                tag: "api-in", listen: "127.0.0.1", port: ($port_api | tonumber), protocol: "dokodemo-door",
                settings: { address: "127.0.0.1" }
            }
        ],
        outbounds: ( 
            [{ tag: "direct", protocol: "freedom" }, { tag: "blocked", protocol: "blackhole" }] 
            + $co 
        ),
        routing: {
            domainStrategy: "IPIfNonMatch",
            rules: [
                (if $direct_outbound == "true" then 
                    { type: "field", user: ["direct"], outboundTag: "direct" } 
                 else 
                    { type: "field", user: ["direct"], outboundTag: "blocked" } 
                 end),
                { type: "field", user: ["custom"], outboundTag: "custom-out" }
            ]
        }
    }' > "$JSON_FILE"
}

create_service() {
    source "$CONF_FILE"
    local mem_env=""; [ "$AUTO_CONFIG" != "true" ] && [ -n "$MEM_LIMIT" ] && mem_env="GOMEMLIMIT=$MEM_LIMIT"
    local ulimit_val=1024; [ "$AUTO_CONFIG" == "true" ] && ulimit_val=1024 || { [ "$HIGH_PERFORMANCE_MODE" == "true" ] && ulimit_val=30000 || ulimit_val=2048; }

    if [ $IS_OPENRC -eq 1 ]; then
        if [ "$SERVICE_AUTO_RESTART" == "true" ]; then
            cat > "$SERVICE_FILE" <<-EOF
#!/sbin/openrc-run
name="xray-proxya"
description="Xray-Proxya Service (Lite)"
supervisor="supervise-daemon"
command="$XRAY_BIN"
command_args="run -c $JSON_FILE"
command_env="$mem_env"
pidfile="/run/xray-proxya.pid"
rc_ulimit="-n $ulimit_val"
respawn_delay=5
respawn_max=0
depend() { need net; after firewall; }
EOF
        else
            cat > "$SERVICE_FILE" <<-EOF
#!/sbin/openrc-run
name="xray-proxya"
description="Xray-Proxya Service (Lite)"
command="$XRAY_BIN"
command_args="run -c $JSON_FILE"
command_env="$mem_env"
command_background=true
pidfile="/run/xray-proxya.pid"
rc_ulimit="-n $ulimit_val"
depend() { need net; after firewall; }
EOF
        fi
        chmod +x "$SERVICE_FILE"
    else
        local restart_conf=""; [ "$SERVICE_AUTO_RESTART" == "true" ] && restart_conf="Restart=on-failure\nRestartSec=5s"
        cat > "$SERVICE_FILE" <<-EOF
[Unit]
Description=Xray-Proxya Service (Lite)
After=network.target
[Service]
User=root
Environment=$mem_env
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$XRAY_BIN run -c $JSON_FILE
$(echo -e "$restart_conf")
LimitNOFILE=$ulimit_val
[Install]
WantedBy=multi-user.target
EOF
    fi
    sys_reload_daemon; sys_enable; sys_restart
}

install_xray() {
    echo -e "=== 安装向导 (Lite 版) ==="
    read -p "VLess-XHTTP-KEM768 (抗量子) 端口 (默认 $DEFAULT_PORT_VLESS_KEM): " port_vl
    read -p "VLess-XHTTP-Reality (TLS抗量子) 端口 (默认 $DEFAULT_PORT_REALITY): " port_rea
    read -p "Shadowsocks-$SS_CIPHER 端口 (默认 $DEFAULT_PORT_SS): " port_ss
    PORT_VLESS=${port_vl:-$DEFAULT_PORT_VLESS_KEM}
    PORT_REALITY=${port_rea:-$DEFAULT_PORT_REALITY}
    PORT_SS=${port_ss:-$DEFAULT_PORT_SS}
    for p in $PORT_VLESS $PORT_REALITY $PORT_SS; do
        if check_port_occupied $p; then echo -e "${RED}⚠️ 端口 $p 被占用${NC}"; return; fi
    done
    install_deps; download_core
    echo -e "${BLUE}🔑 生成配置与密钥...${NC}"
    if ! "$XRAY_BIN" version >/dev/null 2>&1; then echo -e "${RED}❌ Xray 无法运行!${NC}"; return 1; fi
    UUID=$("$XRAY_BIN" uuid); PATH_VL="/$(generate_random 12)"; PATH_REALITY="/$(generate_random 12)"; PASS_SS=$(generate_random 24)
    RAW_REALITY_OUT=$("$XRAY_BIN" x25519 2>&1)
    REALITY_PK=$(echo "$RAW_REALITY_OUT" | grep -i "Private" | awk '{print $NF}' | tr -d ' \r')
    REALITY_PUB=$(echo "$RAW_REALITY_OUT" | grep -i "Public" | awk '{print $NF}' | tr -d ' \r')
    if [ -z "$REALITY_PK" ] || [ ${#REALITY_PK} -lt 40 ]; then REALITY_PK=$(echo "$RAW_REALITY_OUT" | grep "PrivateKey" | awk -F ": " '{print $NF}' | tr -d ' \r'); fi
    if [ -z "$REALITY_PUB" ] || [ ${#REALITY_PUB} -lt 40 ]; then REALITY_PUB=$(echo "$RAW_REALITY_OUT" | grep "Password" | awk -F ": " '{print $NF}' | tr -d ' \r'); fi
    REALITY_SID=$(openssl rand -hex 4)
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc 2>&1)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | awk '/Authentication: ML-KEM-768/{flag=1} flag && /"decryption":/{print $0; exit}' | cut -d '"' -f 4)
    ENC_KEY=$(echo "$RAW_ENC_OUT" | awk '/Authentication: ML-KEM-768/{flag=1} flag && /"encryption":/{print $0; exit}' | cut -d '"' -f 4)
    if [ -z "$REALITY_PUB" ] || [ -z "$REALITY_PK" ]; then echo -e "${RED}❌ Reality 密钥失败${NC}"; return 1; fi
    if [ -z "$DEC_KEY" ]; then echo -e "${RED}❌ ML-KEM 密钥失败${NC}"; return 1; fi
    PORT_TEST=$((RANDOM % 50000 + 10000)); PORT_API=$((RANDOM % 50000 + 10000))
    mkdir -p "$CONF_DIR"; rm -f "$CUSTOM_OUT_FILE"
    cat > "$CONF_FILE" <<-EOF
PORT_VLESS=$PORT_VLESS
PORT_REALITY=$PORT_REALITY
PORT_SS=$PORT_SS
PORT_TEST=$PORT_TEST
PORT_API=$PORT_API
UUID=$UUID
PATH_VL=$PATH_VL
PATH_REALITY=$PATH_REALITY
PASS_SS=$PASS_SS
ENC_KEY=$ENC_KEY
DEC_KEY=$DEC_KEY
REALITY_PK=$REALITY_PK
REALITY_PUB=$REALITY_PUB
REALITY_SID=$REALITY_SID
REALITY_SNI=$REALITY_SNI
REALITY_DEST=$REALITY_DEST
AUTO_CONFIG=$AUTO_CONFIG
HIGH_PERFORMANCE_MODE=$HIGH_PERFORMANCE_MODE
MEM_LIMIT=$MEM_LIMIT
BUFFER_SIZE=$BUFFER_SIZE
CONN_IDLE=$CONN_IDLE
EOF
    generate_config; create_service
    
    echo -e "${BLUE}📦 下载并部署维护脚本...${NC}"
    local maintenance_url="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/maintain.sh"
    local maintenance_dst="/usr/local/bin/xray-proxya-maintenance"
    if curl -sSfL -o "$maintenance_dst" "$maintenance_url"; then
        chmod +x "$maintenance_dst"
        echo -e "${GREEN}✅ 维护脚本已就绪${NC}"
    else
        echo -e "${YELLOW}⚠️  维护脚本下载失败，定时维护功能将受限${NC}"
    fi

    echo -e "${GREEN}✅ 安装完成${NC}"; show_links_menu
}

# --- 链接展示 ---

format_ip() { [[ "$1" =~ .*:.* ]] && echo "[$1]" || echo "$1"; }

print_link_group() {
    local ip=$1; local label=$2; local target_uuid=$3; local desc=$4
    if [ -z "$ip" ]; then return; fi
    local f_ip=$(format_ip "$ip")
    local ps_vl="VLess-XHTTP-KEM768-${PORT_VLESS}"; [ "$desc" == "Custom" ] && ps_vl="转发-$ps_vl"
    local vl_l="vless://$target_uuid@$f_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#$ps_vl"
    local ps_rea="VLess-XHTTP-Reality-${PORT_REALITY}"; [ "$desc" == "Custom" ] && ps_rea="转发-$ps_rea"
    local rea_l="vless://$target_uuid@$f_ip:$PORT_REALITY?security=reality&encryption=none&pbk=$REALITY_PUB&fp=chrome&type=xhttp&serviceName=&path=$PATH_REALITY&sni=$REALITY_SNI&sid=$REALITY_SID&spx=%2F#$ps_rea"
    local ss_l=""
    if [ "$desc" == "Direct" ]; then
        local ps_ss="SS-TCPUDP-${SS_CIPHER}-${PORT_SS}"; local ss_auth=$(echo -n "${SS_CIPHER}:$PASS_SS" | base64 -w 0)
        ss_l="ss://$ss_auth@$f_ip:$PORT_SS#$ps_ss"
    fi
    echo -e "\n${BLUE}--- $label ($ip) ---${NC}"
    echo -e "1️⃣  VLESS (ML-KEM768):\n    ${GREEN}$vl_l${NC}"
    echo -e "2️⃣  VLESS (Reality-TLS):\n    ${GREEN}$rea_l${NC}"
    [ ! -z "$ss_l" ] && echo -e "3️⃣  Shadowsocks (${SS_CIPHER}):\n    ${GREEN}$ss_l${NC}"
}

show_links_logic() {
    local target_uuid=$1; local desc_tag=$2
    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    local ipv6=$(curl -s -6 --max-time 2 https://ifconfig.co)
    if [ -n "$ipv4" ]; then print_link_group "$ipv4" "IPv4" "$target_uuid" "$desc_tag"; fi
    if [ -n "$ipv6" ]; then print_link_group "$ipv6" "IPv6" "$target_uuid" "$desc_tag"; fi
    if [ -z "$ipv4" ] && [ -z "$ipv6" ]; then echo -e "${RED}❌ 无法获取 IP${NC}"; fi
}

show_links_menu() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}❌ 未配置${NC}"; return; fi
    source "$CONF_FILE"
    if [ ! -f "$CUSTOM_OUT_FILE" ]; then
        echo -e "\n=== 链接信息 (直接出站) ==="
        show_links_logic "$UUID" "Direct"; return
    fi
    echo -e "\n=== 选择要查看的链接类型 ==="
    echo "1. 直接出站 (本机 IP)"
    echo "2. 自定义出站 (转发流量至 SS, Socks5, HTTP, WG...)"
    echo -e "\nq. 返回"
    read -p "选择: " sl_choice
    case "$sl_choice" in
        1) show_links_logic "$UUID" "Direct" ;;
        2) [ -z "$UUID_CUSTOM" ] && { echo -e "${RED}错误${NC}"; return; }; show_links_logic "$UUID_CUSTOM" "Custom" ;;
        q|Q) return ;;
        *) echo -e "${RED}无效${NC}" ;;
    esac
}

change_ports() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    echo -e "当前配置:\n1. VLESS(KEM): $PORT_VLESS\n2. Reality   : $PORT_REALITY\n3. SS        : $PORT_SS"
    read -p "新 VLESS(KEM) 端口 (回车跳过): " new_vl
    read -p "新 Reality 端口 (回车跳过): " new_rea
    read -p "新 SS 端口 (回车跳过): " new_ss
    [[ ! -z "$new_vl" ]] && sed -i "s/^PORT_VLESS=.*/PORT_VLESS=$new_vl/" "$CONF_FILE"
    [[ ! -z "$new_rea" ]] && sed -i "s/^PORT_REALITY=.*/PORT_REALITY=$new_rea/" "$CONF_FILE"
    [[ ! -z "$new_ss" ]] && sed -i "s/^PORT_SS=.*/PORT_SS=$new_ss/" "$CONF_FILE"
    source "$CONF_FILE"; generate_config; sys_restart
    echo -e "${GREEN}✅ 已更新并重启${NC}"
}

service_menu() {
    while true; do
        echo -e "\n=== 服务操作 ==="
        check_status
        echo "1. 启动"
        echo "2. 停止"
        echo "3. 重启"
        echo "4. 开机自启"
        echo "5. 取消自启"
        echo ""
        echo "q. 返回上级"
        read -p "选择: " s_choice
        case "$s_choice" in
            1) sys_start ;; 2) sys_stop ;; 3) sys_restart ;; 4) sys_enable ;; 5) sys_disable ;;
            q|Q) return ;; *) echo "❌" ;;
        esac
    done
}

auto_maintenance_menu() {
    local maintenance_script="/usr/local/bin/xray-proxya-maintenance"
    while true; do
        local timezone=$(timedatectl 2>/dev/null | grep "Time zone" | awk '{print $3}' || cat /etc/timezone 2>/dev/null || echo "Unknown")
        local current_time=$(date '+%Y-%m-%d %H:%M:%S')
        echo -e "\n=== 自动化维护 ==="
        echo -e "| 时区: ${BLUE}${timezone}${NC} | 时间: ${BLUE}${current_time}${NC} |"
        echo ""
        echo "1. 添加 Crontab 示例"
        echo "2. 查看当前定时任务"
        echo "3. 移除所有定时任务"
        echo "4. 编辑 Crontab"
        echo ""
        echo "q. 返回上级"
        read -p "选择: " am_choice
        case "$am_choice" in
            1)
                echo -e "\n${YELLOW}正在添加 Crontab 示例...${NC}"
                if crontab -l 2>/dev/null | grep -q "Xray-Proxya 自动化维护示例"; then
                    echo -e "${YELLOW}⚠️  已存在示例，是否覆盖？(y/N)${NC}"
                    read -p "选择: " overwrite
                    if [[ "$overwrite" != "y" && "$overwrite" != "Y" ]]; then continue; fi
                    crontab -l 2>/dev/null | sed '/# ======================================/,/# ======================================/d' | sed '/xray-proxya-auto-/d' | crontab -
                fi
                (crontab -l 2>/dev/null; cat <<'CRON_EXAMPLE'
# ======================================
# Xray-Proxya 自动化维护示例
# ======================================
# 定时重启服务 (示例: 每天凌晨 4 点)
# 0 4 * * * /usr/local/bin/xray-proxya-maintenance restart # xray-proxya-auto-restart
#
# 定时清理日志 (示例: 每周日凌晨 3 点)
# 0 3 * * 0 /usr/local/bin/xray-proxya-maintenance clean-logs # xray-proxya-auto-clean
#
# 定时更新内核 (示例: 每周一凌晨 2 点)
# 0 2 * * 1 /usr/local/bin/xray-proxya-maintenance update-core # xray-proxya-auto-update
# ======================================
CRON_EXAMPLE
) | crontab -
                echo -e "${GREEN}✅ 已添加示例${NC}"
                ;;
            2)
                echo -e "\n${BLUE}=== 当前 Crontab 任务 ===${NC}"
                crontab -l 2>/dev/null | grep -E "(xray-proxya-auto-|Xray-Proxya 自动化维护)" || echo "无相关任务"
                ;;
            3)
                echo -e "\n${YELLOW}确认移除所有 Xray-Proxya 相关任务？(y/N)${NC}"
                read -p "确认: " cf; [[ "$cf" == "y" || "$cf" == "Y" ]] && { crontab -l 2>/dev/null | sed '/# ======================================/,/# ======================================/d' | grep -v "xray-proxya-auto-" | crontab -; echo -e "${GREEN}✅ 已移除${NC}"; }
                ;;
            4) crontab -e ;;
            q|Q) return ;; *) echo "❌" ;;
        esac
    done
}

clear_config() {
    echo -e "${YELLOW}⚠️  警告: 将停止服务并删除所有配置。${NC}"
    read -p "确认清除? (y/N): " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        sys_stop 2>/dev/null; rm -rf "$CONF_DIR"
        echo -e "${GREEN}✅ 配置已清除${NC}"
    fi
}

toggle_direct_listening() {
    source "$CONF_FILE"
    if [ "${DIRECT_OUTBOUND:-true}" == "true" ]; then
        DIRECT_OUTBOUND="false"
    else
        DIRECT_OUTBOUND="true"
    fi
    if grep -q "DIRECT_OUTBOUND=" "$CONF_FILE"; then
        sed -i "s/DIRECT_OUTBOUND=.*/DIRECT_OUTBOUND=$DIRECT_OUTBOUND/" "$CONF_FILE"
    else
        echo "DIRECT_OUTBOUND=$DIRECT_OUTBOUND" >> "$CONF_FILE"
    fi

    generate_config
    sys_restart
    echo -e "${GREEN}✅ 已切换直接出站监听状态为: $DIRECT_OUTBOUND${NC}"
    sleep 1
}

maintenance_menu() {
    while true; do
        source "$CONF_FILE" 2>/dev/null
        local direct_status="开启"
        [ "${DIRECT_OUTBOUND:-true}" == "false" ] && direct_status="关闭"

        echo -e "\n=== 维护 ==="
        echo "1. 服务操作 (启动/停止/重启...)"
        echo "2. 自动化维护 (定时任务)"
        echo -e "3. 直接出站监听: [${BLUE}${direct_status}${NC}] (切换)"
        echo ""
        echo "0. 清除配置"
        echo ""
        echo "q. 返回"
        read -p "选择: " m_choice
        case "$m_choice" in
            1) service_menu ;;
            2) auto_maintenance_menu ;;
            3) toggle_direct_listening ;;
            0) clear_config ;;
            q|Q) return ;;
            *) echo "❌" ;;
        esac
    done
}

uninstall_xray() {
    echo -e "${YELLOW}⚠️  警告: 将停止服务并删除配置。${NC}"
    read -p "确认卸载? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi
    sys_stop 2>/dev/null; sys_disable 2>/dev/null
    rm -f "$SERVICE_FILE"; rm -rf "$CONF_DIR"
    sys_reload_daemon; echo -e "${GREEN}✅ 服务与配置已移除。${NC}"
    read -p "是否同时删除 Xray 核心文件 ($XRAY_DIR)? (y/N): " del_core
    if [[ "$del_core" == "y" ]]; then rm -rf "$XRAY_DIR"; echo -e "${GREEN}✅ 核心文件已移除。${NC}"; fi
}
apply_refresh() {
    echo -e "${BLUE}🔄 正在从脚本头部同步变量并重载服务...${NC}"
    [ -n "$AUTO_CONFIG" ] && sed -i "s/^AUTO_CONFIG=.*/AUTO_CONFIG=$AUTO_CONFIG/" "$CONF_FILE"
    [ -n "$HIGH_PERFORMANCE_MODE" ] && sed -i "s/^HIGH_PERFORMANCE_MODE=.*/HIGH_PERFORMANCE_MODE=$HIGH_PERFORMANCE_MODE/" "$CONF_FILE"
    [ -n "$MEM_LIMIT" ] && sed -i "s/^MEM_LIMIT=.*/MEM_LIMIT=$MEM_LIMIT/" "$CONF_FILE"
    [ -n "$BUFFER_SIZE" ] && sed -i "s/^BUFFER_SIZE=.*/BUFFER_SIZE=$BUFFER_SIZE/" "$CONF_FILE"
    [ -n "$CONN_IDLE" ] && sed -i "s/^CONN_IDLE=.*/CONN_IDLE=$CONN_IDLE/" "$CONF_FILE"
    source "$CONF_FILE"; generate_config; create_service
    echo -e "${GREEN}✅ 配置已刷新并重启${NC}"; sleep 1
}


check_root
while true; do
    echo -e "\n${BLUE}Xray-Proxya Lite 管理${NC}"
    check_status
    echo "1. 安装 / 重置"
    echo "2. 查看链接"
    echo "3. 修改端口"
    echo "4. 维护菜单"
    echo "5. 自定义出站"
    echo "6. 测试自定义出站"
    echo "7. 刷新配置"
    echo ""
    echo "9. 重装内核"
    echo "0. 卸载"
    echo "q. 退出"
    read -p "选择: " choice
    case "$choice" in
        1) install_xray ;;
        2) show_links_menu ;;
        3) change_ports ;;
        4) maintenance_menu ;;
        5) custom_outbound_menu ;;
        6) test_custom_outbound ;;
        7) apply_refresh ;;
        9) reinstall_core ;;
        0) uninstall_xray ;;
        q|Q) exit 0 ;;
        *) echo -e "${RED}无效${NC}" ;;
    esac
done
