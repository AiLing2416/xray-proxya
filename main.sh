#!/bin/bash

# ==================================================
# Xray-Proxya Manager [MAIN]
# Supports: Debian/Ubuntu & Alpine (OpenRC)
# ==================================================

# --- 默认配置变量 ---
DEFAULT_PORT_VMESS=8081
DEFAULT_PORT_VLESS_KEM=8082
DEFAULT_PORT_REALITY=8443
DEFAULT_PORT_SS=8083
DEFAULT_GEN_LEN=16
SERVICE_AUTO_RESTART="true"

# 为 true 时覆盖下方所有性能参数, 由 Xray 核心自行管理资源
AUTO_CONFIG="true"

# 内存与资源管理 (防止 OOM)
# HIGH_PERFORMANCE_MODE: true 为高性能(高并发)模式, false 为低功耗(小内存)模式
HIGH_PERFORMANCE_MODE="false"
# MEM_LIMIT: Go 运行时强制回收内存的目标 (建议设为总 RAM 的 60-80%)
MEM_LIMIT="320MiB"
# BUFFER_SIZE: 每条连接的缓冲区大小 (KB), 越小越省内存, 但极限速度会下降
# 算法: 最大连接数 ≈ (MEM_LIMIT - 50MB) / (BUFFER_SIZE * 2)
BUFFER_SIZE=16
# CONN_IDLE: 空闲连接超时自动断开 (秒), 建议 1800 (30分钟) 以保持长连接稳定
CONN_IDLE=1800

# 日志配置
DEFAULT_ENABLE_LOG=true
DEFAULT_LOG_DIR="/var/log/xray-proxya"
DEFAULT_LOG_FILE="xray.log"

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

get_runtime_formatted() {
    local pid=$1
    if [ -z "$pid" ]; then return; fi
    
    local runtime_str=""
    
    if [ -f "/proc/uptime" ] && [ -f "/proc/$pid/stat" ]; then
        local uptime=$(awk '{print $1}' /proc/uptime)
        local start_ticks=$(awk '{print $22}' "/proc/$pid/stat")
        local clk_tck=$(getconf CLK_TCK 2>/dev/null || echo 100)
        runtime_str=$(awk -v up="$uptime" -v st="$start_ticks" -v clk="$clk_tck" 'BEGIN {
            run_sec = int(up - (st / clk));
            d = int(run_sec / 86400);
            h = int((run_sec % 86400) / 3600);
            m = int((run_sec % 3600) / 60);
            printf "%dd/%dh/%dm", d, h, m
        }')
    fi

    if [ -z "$runtime_str" ] && command -v ps >/dev/null 2>&1; then
         local etime=$(ps -o etime= -p "$pid" 2>/dev/null | tr -d ' ')
         if [ -n "$etime" ]; then
             runtime_str="running($etime)"
         fi
    fi
    
    echo "$runtime_str"
}



check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}❌ 错误: 需要 root 权限${NC}"
        exit 1
    fi
}

install_deps() {
    echo -e "${BLUE}📦 安装/检查依赖...${NC}"
    if [ -f /etc/alpine-release ]; then
        echo "正在运行 apk update..."
        apk update
        echo "正在安装依赖..."
        apk add curl jq openssl bash coreutils gcompat iproute2 grep libgcc libstdc++ sed gawk unzip dialog ncurses tzdata
    else
        apt-get update
        apt-get install -y curl jq unzip openssl dialog ncurses-bin
    fi
}

show_scroll_log() {
    local title="$1"
    local command="$2"
    
    if ! command -v tput >/dev/null 2>&1; then
        eval "$command"
        return $?
    fi

    local log_file=$(mktemp)
    
    echo -e "${BLUE}=== $title ===${NC}"
    for i in {1..5}; do echo ""; done
    
    eval "$command" >"$log_file" 2>&1 &
    local pid=$!
    
    while kill -0 $pid 2>/dev/null; do
        tput cuu 5
        tput ed
        tail -n 5 "$log_file"
        sleep 0.2
    done
    wait $pid
    local ret=$?
    
    if [ $ret -ne 0 ]; then
        tput cuu 5
        tput ed
        echo -e "${RED}❌ $title 失败，详细日志如下:${NC}"
        cat "$log_file"
        rm "$log_file"
        return $ret
    else
        tput cuu 5
        tput ed
        echo -e "${GREEN}✅ $title 完成${NC}"
        rm "$log_file"
        return 0
    fi
}

check_port_occupied() {
    local port=$1
    local output=""
    local pid=""
    if command -v ss >/dev/null 2>&1; then
        output=$(ss -lntp 2>/dev/null | grep ":$port ")
    elif command -v netstat >/dev/null 2>&1; then
        output=$(netstat -lntp 2>/dev/null | grep ":$port ")
    fi

    if [ -n "$output" ]; then
        
        if echo "$output" | grep -q "pid="; then
            pid=$(echo "$output" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
        elif echo "$output" | grep -q "/"; then
            pid=$(echo "$output" | sed -n 's/[^0-9]*\([0-9]*\)\/.*/\1/p' | awk '{print $NF}') # netstat format often at end
        fi

        if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
            local exe_link=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
            if [[ "$exe_link" == "$XRAY_BIN" ]]; then
                return 1
            fi
        fi
        return 0
    fi
    return 1
}

validate_port() {
    local port=$1
    local default=$2
    if [ -z "$port" ]; then
        echo "$default"
        return 0
    fi
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo -e "${RED}❌ 错误: 端口必须是 1-65535 之间的数字${NC}" >&2
        return 1
    fi
    echo "$port"
    return 0
}

human_readable() {
    local bytes=$1
    if [ -z "$bytes" ] || ! [[ "$bytes" =~ ^[0-9]+$ ]]; then echo "0 B"; return; fi
    if [ $bytes -lt 1024 ]; then echo "${bytes} B"
    elif [ $bytes -lt 1048576 ]; then echo "$(( (bytes * 100) / 1024 ))" | sed 's/..$/.&/' | awk '{printf "%.2f KB", $0}'
    elif [ $bytes -lt 1073741824 ]; then echo "$(( (bytes * 100) / 1048576 ))" | sed 's/..$/.&/' | awk '{printf "%.2f MB", $0}'
    else echo "$(( (bytes * 100) / 1073741824 ))" | sed 's/..$/.&/' | awk '{printf "%.2f GB", $0}'
    fi
}

get_xray_stats() {
    local port_api=$1
    if [ -z "$port_api" ]; then return; fi
    
    # 连接数统计
    local conn_count=$(ss -nt 2>/dev/null | grep -c "ESTAB")
    [ -z "$conn_count" ] && conn_count=0
    
    # 1. 统计所有入站流量 (Inbounds)
    local in_up=0
    local in_down=0
    local tags=("vmess-in" "vless-enc-in" "vless-reality-in" "shadowsocks-in")
    
    for tag in "${tags[@]}"; do
        local u=$("$XRAY_BIN" api stats --server=127.0.0.1:$port_api -name "inbound>>>${tag}>>>traffic>>>uplink" 2>/dev/null | grep "value" | awk '{print $2}')
        local d=$("$XRAY_BIN" api stats --server=127.0.0.1:$port_api -name "inbound>>>${tag}>>>traffic>>>downlink" 2>/dev/null | grep "value" | awk '{print $2}')
        [ -n "$u" ] && in_up=$((in_up + u))
        [ -n "$d" ] && in_down=$((in_down + d))
    done
    
    # 2. 统计自定义出站流量 (Custom Outbound)
    local out_up=0
    local out_down=0
    local custom_status="不适用"
    local has_custom=0
    
    if [ -f "$CUSTOM_OUT_FILE" ] && [ -s "$CUSTOM_OUT_FILE" ] && [ "$(cat "$CUSTOM_OUT_FILE")" != "[]" ]; then
        has_custom=1
        custom_status="0 B"
        local cu=$("$XRAY_BIN" api stats --server=127.0.0.1:$port_api -name "outbound>>>custom-out>>>traffic>>>uplink" 2>/dev/null | grep "value" | awk '{print $2}')
        local cd=$("$XRAY_BIN" api stats --server=127.0.0.1:$port_api -name "outbound>>>custom-out>>>traffic>>>downlink" 2>/dev/null | grep "value" | awk '{print $2}')
        
        [ -n "$cu" ] && out_up=$((out_up + cu))
        [ -n "$cd" ] && out_down=$((out_down + cd))
        
        local custom_total=$((out_up + out_down))
        if [ $custom_total -gt 0 ]; then
             custom_status=$(human_readable $custom_total)
        fi
    fi
    
    # 3. 计算总用量 (入站 + 出站)
    local total_bytes=$((in_up + in_down + out_up + out_down))
    local h_total=$(human_readable $total_bytes)
    
    echo "| 连接数: $conn_count | 总用量: $h_total | 自定义出站: $custom_status |"
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
    local pid=""
    
    if [ -f "/var/run/xray-proxya.pid" ]; then
        pid=$(cat /var/run/xray-proxya.pid)
    elif command -v pgrep >/dev/null; then
        pid=$(pgrep -f "xray-proxya-core/xray")
    fi
    
    local is_running=0
    if [ $IS_OPENRC -eq 1 ]; then
        if rc-service xray-proxya status 2>/dev/null | grep -q "started"; then is_running=1; fi
    else
        if systemctl is-active --quiet xray-proxya; then is_running=1; fi
    fi
    
    if [ $is_running -eq 1 ]; then
        local runtime=""
        if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
             runtime="($(get_runtime_formatted "$pid"))"
        fi
        echo -e "🟢 服务状态: ${GREEN}运行中${NC} $runtime"
    else
        echo -e "🔴 服务状态: ${RED}未运行${NC}"
    fi
    
    if [ $is_running -eq 1 ] && [ -f "$CONF_FILE" ]; then
        local api_port=$(grep "PORT_API=" "$CONF_FILE" | cut -d= -f2)
        if [ -n "$api_port" ]; then
             echo -e "$(get_xray_stats "$api_port")"
        fi
    fi
}

# --- 核心逻辑 ---

generate_random() {
    openssl rand -base64 $(( $1 * 2 )) | tr -dc 'a-zA-Z0-9' | head -c $1
}

download_core() {
    if [ -f "$XRAY_BIN" ]; then return 0; fi
    echo -e "${BLUE}⬇️  获取 Xray-core...${NC}"
    
    local api_response=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest)
    local download_url=""

    if command -v jq >/dev/null 2>&1; then
        download_url=$(echo "$api_response" | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url')
    fi

    # 回退方案: 如果 jq 失败或未安装, 使用 grep/cut 解析
    if [ -z "$download_url" ] || [ "$download_url" == "null" ]; then
        echo -e "${YELLOW}⚠️  jq 解析失败，尝试使用 grep 回退...${NC}"
        download_url=$(echo "$api_response" | grep -o '"browser_download_url": *"[^"]*Xray-linux-64.zip"' | head -n 1 | cut -d '"' -f 4)
    fi

    if [ -z "$download_url" ]; then
        echo -e "${RED}❌ 无法获取下载链接。GitHub API 可能受限或网络不通。${NC}"
        return 1
    fi

    echo -e "下载链接: $download_url"
    
    sys_stop 2>/dev/null
    mkdir -p "$XRAY_DIR"
    
    local tmp_file=$(mktemp)
    if curl -L -o "$tmp_file" "$download_url"; then
        echo "解压中..."
        if unzip -o "$tmp_file" -d "$XRAY_DIR" >/dev/null 2>&1; then
            rm "$tmp_file"
            chmod +x "$XRAY_BIN"
            return 0
        else
            echo -e "${RED}❌ 解压失败 (unzip error)${NC}"
            rm "$tmp_file"
            return 1
        fi
    else
        echo -e "${RED}❌ 下载失败 (curl error)${NC}"
        rm -f "$tmp_file"
        return 1
    fi
}

reinstall_core() {
    echo -e "${BLUE}🔄 正在重装 Xray 核心...${NC}"
    sys_stop 2>/dev/null
    rm -rf "$XRAY_DIR"
    
    if show_scroll_log "核心下载与安装" download_core; then
        sys_start
        echo -e "${GREEN}✅ 核心重装完成并已重启服务。${NC}"
    else
        echo -e "${RED}❌ 重装失败${NC}"
    fi
}

decode_base64() {
    local str="$1"
    local mod=$((${#str} % 4))
    if [ $mod -eq 3 ]; then
        str="${str}="
    elif [ $mod -eq 2 ]; then
        str="${str}=="
    elif [ $mod -eq 1 ]; then
        str="${str}==="
    fi
    echo "$str" | base64 -d 2>/dev/null || echo "$str" | base64 -d -i 2>/dev/null
}

url_decode() {
    local url_encoded="${1//+/ }"
    printf '%b' "${url_encoded//%/\\x}"
}

parse_link_to_json() {
    local link="$1"
    # VMess
    if [[ "$link" == vmess://* ]]; then
        local b64="${link#vmess://}"
        local json_str=$(decode_base64 "$b64")
        if [ -z "$json_str" ]; then return 1; fi
        echo "$json_str" | jq -c '{
            tag: "custom-out",
            protocol: "vmess",
            settings: {
                vnext: [{
                    address: .add,
                    port: (.port | tonumber),
                    users: [{ id: .id }]
                }]
            },
            streamSettings: {
                network: .net,
                security: .tls,
                wsSettings: {
                    path: .path,
                    headers: { Host: .host }
                }
            }
        }'
        return 0
    fi
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
        
        local type=$(echo "$query" | sed -n 's/.*type=\([^&]*\).*/\1/p')
        [ -z "$type" ] && type="tcp"
        type=$(url_decode "$type")
        
        local security=$(echo "$query" | sed -n 's/.*security=\([^&]*\).*/\1/p')
        [ -z "$security" ] && security="none"
        security=$(url_decode "$security")
        
        local path_enc=$(echo "$query" | sed -n 's/.*path=\([^&]*\).*/\1/p')
        local path=$(url_decode "$path_enc")
        
        local sni_enc=$(echo "$query" | sed -n 's/.*sni=\([^&]*\).*/\1/p')
        local sni=$(url_decode "$sni_enc")
        
        local flow=$(echo "$query" | sed -n 's/.*flow=\([^&]*\).*/\1/p')
        flow=$(url_decode "$flow")
        
        local pbk=$(echo "$query" | sed -n 's/.*pbk=\([^&]*\).*/\1/p')
        pbk=$(url_decode "$pbk")
        
        local fp=$(echo "$query" | sed -n 's/.*fp=\([^&]*\).*/\1/p')
        fp=$(url_decode "$fp")
        
        local sid=$(echo "$query" | sed -n 's/.*sid=\([^&]*\).*/\1/p')
        sid=$(url_decode "$sid")
        
        local spx=$(echo "$query" | sed -n 's/.*spx=\([^&]*\).*/\1/p')
        spx=$(url_decode "$spx")
        
        local encryption=$(echo "$query" | sed -n 's/.*encryption=\([^&]*\).*/\1/p')
        encryption=$(url_decode "$encryption")
        [ -z "$encryption" ] && encryption="none"
        
        # [Fix] Vision flow is only supported on TCP
        if [[ "$type" != "tcp" ]]; then
            flow=""
        fi

        jq -n -c \
            --arg address "$address" \
            --arg port "$port" \
            --arg uuid "$uuid" \
            --arg type "$type" \
            --arg security "$security" \
            --arg sni "$sni" \
            --arg path "$path" \
            --arg flow "$flow" \
            --arg pbk "$pbk" \
            --arg fp "$fp" \
            --arg sid "$sid" \
            --arg spx "$spx" \
            --arg encryption "$encryption" \
            '{
                tag: "custom-out",
                protocol: "vless",
                settings: {
                    vnext: [{
                        address: $address,
                        port: ($port | tonumber),
                        users: ([{ 
                            id: $uuid,
                            encryption: $encryption
                        } + (if $flow != "" then {flow: $flow} else {} end)])
                    }]
                },
                streamSettings: {
                    network: $type,
                    security: $security,
                    (if $security == "reality" then "realitySettings" else "tlsSettings" end): (
                        if $security == "reality" then ({
                            show: false,
                            fingerprint: $fp,
                            serverName: $sni,
                            publicKey: $pbk,
                            shortId: $sid
                        } + (if $spx != "" then {spiderX: $spx} else {} end)) else {
                            serverName: $sni
                        } end
                    ),
                    ($type + "Settings"): { path: $path }
                }
            }'
        return 0
    fi
    # SS
    if [[ "$link" == ss://* ]]; then
        local raw="${link#ss://}"
        raw="${raw%%\#*}"
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
        if [ -z "$method" ] || [ -z "$address" ]; then return 1; fi
        
        jq -n -c \
            --arg address "$address" \
            --arg port "$port" \
            --arg method "$method" \
            --arg password "$password" \
            '{
                tag: "custom-out",
                protocol: "shadowsocks",
                settings: {
                    servers: [{
                        address: $address,
                        port: ($port | tonumber),
                        method: $method,
                        password: $password
                    }]
                }
            }'
        return 0
    fi
    # WireGuard
    # wireguard://<Priv>@<EndpointIP>:<EndpointPort>?publickey=<Pub>&reserved=<Res>&address=<LocalIP/Mask>&mtu=<MTU>
    if [[ "$link" == wireguard://* ]]; then
        local tmp="${link#wireguard://}"
        local priv_enc="${tmp%%@*}"
        tmp="${tmp#*@}"
        local end_addr_port="${tmp%%\?*}"
        local end_addr="${end_addr_port%:*}"
        local end_port="${end_addr_port##*:}"
        
        local query="${link#*\?}"
        local pub_enc=$(echo "$query" | sed -n 's/.*publickey=\([^&#]*\).*/\1/p')
        local addr_enc=$(echo "$query" | sed -n 's/.*address=\([^&#]*\).*/\1/p')
        local res_enc=$(echo "$query" | sed -n 's/.*reserved=\([^&#]*\).*/\1/p')
        local mtu=$(echo "$query" | sed -n 's/.*mtu=\([^&#]*\).*/\1/p')
        [ -z "$mtu" ] && mtu=1280
        
        local priv_key=$(url_decode "$priv_enc")
        local pub_key=$(url_decode "$pub_enc")
        local local_addr=$(url_decode "$addr_enc")
        local reserved=$(url_decode "$res_enc")

        if [ -z "$pub_key" ] || [ -z "$priv_key" ] || [ -z "$end_addr" ]; then return 1; fi

        jq -n -c \
            --arg pub "$pub_key" \
            --arg priv "$priv_key" \
            --arg addr "$end_addr" \
            --arg port "$end_port" \
            --arg local "$local_addr" \
            --arg res "$reserved" \
            --arg mtu "$mtu" \
            '{
                tag: "custom-out",
                protocol: "wireguard",
                settings: {
                    secretKey: $priv,
                    address: ($local | split(",")),
                    reserved: (if $res != "" then ($res | split(",") | map(tonumber)) else null end),
                    peers: [{
                        publicKey: $pub,
                        endpoint: ($addr + ":" + $port),
                        keepAlive: 25
                    }],
                    mtu: ($mtu | tonumber)
                }
            } | del(..|nulls)'
        return 0
    fi

    # SOCKS5 (socks://user:pass@host:port#tag)
    if [[ "$link" == socks://* ]]; then
        local raw="${link#socks://}"
        raw="${raw%%\#*}" # Strip tag
        raw="${raw%%\?*}" # Strip query
        
        local user=""
        local pass=""
        local addr_port=""
        
        if [[ "$raw" == *@* ]]; then
             local auth_b64="${raw%%@*}"
             addr_port="${raw#*@}"
             local decoded=$(decode_base64 "$auth_b64")
             if [[ "$decoded" == *:* ]]; then
                 user="${decoded%%:*}"
                 pass="${decoded#*:}"
             fi
        else
             addr_port="$raw"
        fi
        
        local address="${addr_port%%:*}"
        local port="${addr_port##*:}"
        
        if [ -z "$address" ] || [ -z "$port" ]; then return 1; fi
        
        jq -n -c \
            --arg addr "$address" \
            --arg port "$port" \
            --arg user "$user" \
            --arg pass "$pass" \
            '{
                tag: "custom-out",
                protocol: "socks",
                settings: {
                    servers: [{
                        address: $addr,
                        port: ($port | tonumber),
                        users: (if $user != "" then [{user: $user, pass: $pass, level: 0}] else [] end)
                    }]
                }
            }'
        return 0
    fi
    return 1
}

parse_http_proxy() {
    local input="$1"    
    if [[ "$input" != *@* ]]; then return 1; fi    
    local addr_port="${input##*@}"
    local host="${addr_port%:*}"
    local port="${addr_port##*:}"
    local auth="${input%@$addr_port}"
    
    if [[ "$auth" != *:* ]]; then return 1; fi
    
    local user="${auth%%:*}"
    local pass="${auth#*:}"
    
    jq -n -c \
        --arg host "$host" \
        --arg port "$port" \
        --arg user "$user" \
        --arg pass "$pass" \
    '{
        tag: "custom-out",
        protocol: "http",
        settings: {
            servers: [{
                address: $host,
                port: ($port | tonumber),
                users: [{ user: $user, pass: $pass }]
            }]
        }
    }'
}

parse_wg_conf() {
    local conf_content="$1"
    if [ -z "$conf_content" ]; then 
        conf_content=$(cat)
    fi
    
    local private_key=$(echo "$conf_content" | grep -i "^PrivateKey" | cut -d'=' -f2- | tr -d ' \r\t')
    local address_line=$(echo "$conf_content" | grep -i "^Address" | cut -d'=' -f2- | tr -d ' \r\t')
    
    local public_key=$(echo "$conf_content" | grep -i "^PublicKey" | cut -d'=' -f2- | tr -d ' \r\t')
    local endpoint=$(echo "$conf_content" | grep -i "^Endpoint" | cut -d'=' -f2- | tr -d ' \r\t')
    local preshared_key=$(echo "$conf_content" | grep -i "^PresharedKey" | cut -d'=' -f2- | tr -d ' \r\t')
    
    local reserved_line=$(echo "$conf_content" | grep -i "^Reserved" | cut -d'=' -f2- | tr -d ' \r\t')
    
    if [ -z "$private_key" ] || [ -z "$public_key" ] || [ -z "$endpoint" ]; then
        return 1
    fi
    
    local addr_json=$(echo "$address_line" | awk -F, '{printf "["; for(i=1;i<=NF;i++) printf "\"%s\"%s", $i, (i==NF?"":","); printf "]"}')
    local res_json="null"
    if [ -n "$reserved_line" ]; then
        res_json=$(echo "$reserved_line" | awk -F, '{printf "["; for(i=1;i<=NF;i++) printf "%s%s", $i, (i==NF?"":","); printf "]"}')
    fi
    
    local host="${endpoint%:*}"
    local port="${endpoint##*:}"
    
    jq -n -c \
        --arg pk "$private_key" \
        --arg pub "$public_key" \
        --arg host "$host" \
        --arg port "$port" \
        --argjson addr "$addr_json" \
        --argjson res "$res_json" \
        --arg psk "$preshared_key" \
    '{
        tag: "custom-out",
        protocol: "wireguard",
        settings: {
            secretKey: $pk,
            address: $addr,
            reserved: $res,
            peers: [{
                publicKey: $pub,
                endpoint: ($host + ":" + $port),
                preSharedKey: (if $psk != "" then $psk else null end)
            }]
        }
    } | del(..|nulls)'
}

migrate_custom_config() {
    if [ ! -f "$CUSTOM_OUT_FILE" ]; then return; fi
    if [ ! -s "$CUSTOM_OUT_FILE" ] || [ "$(cat "$CUSTOM_OUT_FILE")" == "[]" ]; then echo "[]" > "$CUSTOM_OUT_FILE"; return; fi
    
    local first_char=$(jq -r 'type' "$CUSTOM_OUT_FILE" 2>/dev/null)
    if [ "$first_char" != "array" ]; then
        echo -e "${YELLOW}检测到旧版配置，正在迁移...${NC}"
        source "$CONF_FILE"
        local u_custom="${UUID_CUSTOM:-$(cat /proc/sys/kernel/random/uuid)}"
        jq -n --arg uuid "$u_custom" --slurpfile old "$CUSTOM_OUT_FILE" \
            '[{ alias: "outbound1", uuid: $uuid, config: ($old[0] | .tag="custom-out-outbound1") }]' > "$CUSTOM_OUT_FILE"
        echo -e "${GREEN}✅ 迁移完成${NC}"
    fi
}

test_custom_outbound() {
    echo -e "\n=== 连通性测试 (SOCKS5 Auth) ==="
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装或配置文件丢失${NC}"; return; fi
    source "$CONF_FILE"
    
    if [ -z "$PORT_TEST" ]; then
        echo -e "${YELLOW}⚠️  未找到测试端口配置${NC}"
        return
    fi
    
    local url="https://www.google.com"
    local config_count=0
    if [ -f "$CUSTOM_OUT_FILE" ] && [ -s "$CUSTOM_OUT_FILE" ] && [ "$(cat "$CUSTOM_OUT_FILE")" != "[]" ]; then
         config_count=$(jq 'length' "$CUSTOM_OUT_FILE" 2>/dev/null || echo 0)
    fi
    
    local target_user=""
    local target_alias=""
    
    if [ "$config_count" -eq 0 ]; then
        echo -e "${YELLOW}没有检测到自定义出站配置。将测试直接出站。${NC}"
        target_user="direct"
        target_alias="[直接出站]"
    elif [ "$config_count" -eq 1 ]; then
        local alias=$(jq -r '.[0].alias' "$CUSTOM_OUT_FILE")
        target_user="custom-$alias"
        target_alias="[$alias]"
        echo -e "检测到单个配置: ${GREEN}$alias${NC}"
    else
        echo "请选择要测试的出站:"
        echo "0. 直接出站 (Direct)"
        jq -r 'to_entries[] | "\(.key + 1). [\(.value.alias)]"' "$CUSTOM_OUT_FILE"
        echo ""
        read -p "选择: " t_choice
        
        if [[ "$t_choice" == "0" ]]; then
            target_user="direct"
            target_alias="[直接出站]"
        elif [[ "$t_choice" =~ ^[1-9][0-9]*$ ]] && [ "$t_choice" -le "$config_count" ]; then
            local idx=$((t_choice - 1))
            local alias=$(jq -r ".[$idx].alias" "$CUSTOM_OUT_FILE")
            target_user="custom-$alias"
            target_alias="[$alias]"
        else
            echo -e "${RED}无效选择${NC}"
            return
        fi
    fi
    
    echo -e "\n正在测试 $target_alias ..."
    echo -e "${BLUE}Cmd: curl -I --proxy-user $target_user:*** ...${NC}"
    
    local start_time=$(date +%s%N)
    local http_code=$(curl -I -s -o /dev/null -w "%{http_code}" --max-time 10 --proxy-user "$target_user:test" --proxy "socks5h://127.0.0.1:$PORT_TEST" "$url")
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 ))
    
    if [[ "$http_code" =~ ^(200|301|302) ]]; then
        echo -e "${GREEN}✅ 测试通过! (HTTP $http_code)${NC}"
        echo -e "耗时: ${duration}ms"
    else
        echo -e "${RED}❌ 测试失败 (HTTP $http_code)${NC}"
        echo -e "可能原因: 节点不可用 / 认证失败 / DNS解析超时"
    fi
    read -p "按回车继续..."
}

custom_outbound_menu() {
    migrate_custom_config
    
    while true; do
        if [ ! -f "$CUSTOM_OUT_FILE" ]; then echo "[]" > "$CUSTOM_OUT_FILE"; fi
        
        echo -e "\n=== 自定义出站管理 ==="
        echo -e "${YELLOW}支持最多 9 个出站配置${NC}"
        
        local count=$(jq 'length' "$CUSTOM_OUT_FILE" 2>/dev/null || echo 0)
        
        if [ "$count" -gt 0 ]; then
            jq -r 'to_entries[] | "\(.key + 1). [\(.value.alias)] (UUID: ...\(.value.uuid | tostring | .[-6:]))"' "$CUSTOM_OUT_FILE"
        else
            echo "   (暂无配置)"
        fi
        
        echo ""
        if [ "$count" -lt 9 ]; then
            echo "0. 添加新出站"
        fi
        echo ""
        echo "q. 返回"
        read -p "选择: " choice
        
        case "$choice" in
            0)
                if [ "$count" -lt 9 ]; then
                    add_new_custom_outbound
                else
                    echo -e "${RED}已达到最大数量限制${NC}"
                fi
                ;;
            [1-9])
                if [ "$choice" -le "$count" ]; then
                    manage_single_outbound "$((choice-1))"
                else
                    echo -e "${RED}无效选择${NC}"
                fi
                ;;
            q|Q) return ;;
            *) echo -e "${RED}无效选择${NC}" ;;
        esac
    done
}

add_new_custom_outbound() {
    echo -e "\n=== 添加新出站 ==="
    read -p "请输入别名 (Alias, 仅限字母数字): " alias
    if [[ ! "$alias" =~ ^[a-zA-Z0-9]+$ ]]; then echo -e "${RED}别名无效${NC}"; return; fi
    
    if jq -e --arg a "$alias" '.[] | select(.alias == $a)' "$CUSTOM_OUT_FILE" >/dev/null; then
        echo -e "${RED}别名已存在${NC}"; return
    fi
    
    echo -e "\n请选择导入方式:"
    echo "1. 粘贴分享链接 (VMess/VLESS/SS/SOCKS/WG-URI)"
    echo "2. HTTP 代理账号导入 (格式: Username:Password@Host:Port)"
    echo "3. WireGuard 配置文件导入 (多行文本)"
    echo "q. 返回"
    read -p "选择: " method
    
    local parsed_json=""
    local ret_code=0
    
    case "$method" in
        1)
            echo -e "${YELLOW}支持链接: VMess(ws), VLESS(tcp/xhttp), SS, SOCKS5, WG${NC}"
            read -p "请粘贴链接: " link_str
            [ -z "$link_str" ] && return
            parsed_json=$(parse_link_to_json "$link_str")
            ret_code=$?
            ;;
        2)
            echo -e "${YELLOW}格式: Username:Password@Host:Port (无需 Base64)${NC}"
            echo -e "例如: user:pass@1.2.3.4:8080"
            echo -e "提示: 密码可包含特殊字符 (除最后分割用的 @)"
            read -p "请输入: " proxy_str
            [ -z "$proxy_str" ] && return
            parsed_json=$(parse_http_proxy "$proxy_str")
            ret_code=$?
            ;;
        3)
            echo -e "${YELLOW}请粘贴 WireGuard 配置文件内容 (完成后按 Ctrl+D):${NC}"
            local wg_content=$(cat)
            parsed_json=$(parse_wg_conf "$wg_content")
            ret_code=$?
            ;;
        q|Q) return ;;
        *) echo -e "${RED}无效选择${NC}"; return ;;
    esac

    if [ $ret_code -ne 0 ] || [ -z "$parsed_json" ] || [ "$parsed_json" == "null" ]; then 
        echo -e "${RED}❌ 解析失败或不支持该格式${NC}"
        return
    fi
    
    local new_uuid=$("$XRAY_BIN" uuid)
    local tag_name="custom-out-$alias"
    
    local tmp=$(mktemp)
    jq --arg alias "$alias" --arg uuid "$new_uuid" --arg tag "$tag_name" --argjson newconf "$parsed_json" \
       '. + [{ alias: $alias, uuid: $uuid, config: ($newconf | .tag=$tag) }]' \
       "$CUSTOM_OUT_FILE" > "$tmp" && mv "$tmp" "$CUSTOM_OUT_FILE"
       
    echo -e "${GREEN}✅ 添加成功${NC}"
    apply_config_changes
}

manage_single_outbound() {
    local idx=$1
    local alias=$(jq -r ".[$idx].alias" "$CUSTOM_OUT_FILE")
    
    while true; do
        echo -e "\n=== 管理出站: $alias ==="
        echo "1. 查看连接信息"
        echo "2. 删除此出站"
        echo ""
        echo "q. 返回"
        read -p "选择: " m_choice
        
        case "$m_choice" in
            1)
                print_custom_link "$idx"
                read -p "按回车继续..."
                ;;
            2)
                read -p "确定删除 $alias ? (y/N): " confirm
                if [[ "$confirm" == "y" ]]; then
                    local tmp=$(mktemp)
                    jq "del(.[$idx])" "$CUSTOM_OUT_FILE" > "$tmp" && mv "$tmp" "$CUSTOM_OUT_FILE"
                    echo -e "${GREEN}✅ 已删除${NC}"
                    apply_config_changes
                    return
                fi
                ;;
            q|Q) return ;;
            *) echo "❌" ;;
        esac
    done
}

apply_config_changes() {
    generate_config
    sys_restart
    echo -e "${GREEN}配置已更新并重启服务${NC}"
}

print_custom_link() {
    local idx=$1
    local item=$(jq ".[$idx]" "$CUSTOM_OUT_FILE")
    local uuid=$(echo "$item" | jq -r ".uuid")
    local alias=$(echo "$item" | jq -r ".alias")
    
    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    if [ -n "$ipv4" ]; then
        print_link_group "$ipv4" "Custom-$alias" "$uuid" "Custom"
    else
        echo -e "${RED}无法获取 IP${NC}"
    fi
}

generate_config() {
    # 确保配置目录和核心目录存在
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

    if [ -z "$PORT_TEST" ]; then
        while :; do
            local rnd_port=$((RANDOM % 55000 + 10000))
            if ! check_port_occupied $rnd_port; then
                PORT_TEST=$rnd_port
                break
            fi
        done
        echo "PORT_TEST=$PORT_TEST" >> "$CONF_FILE"
    fi
    
    if [ -z "$PORT_API" ]; then
        while :; do
            local rnd_port=$((RANDOM % 55000 + 10000))
            if ! check_port_occupied $rnd_port && [ "$rnd_port" != "$PORT_TEST" ]; then
                PORT_API=$rnd_port
                break
            fi
        done
        echo "PORT_API=$PORT_API" >> "$CONF_FILE"
    fi

    # 日志参数默认值
    local enable_log="${ENABLE_LOG:-$DEFAULT_ENABLE_LOG}"
    local log_dir="${LOG_DIR:-$DEFAULT_LOG_DIR}"
    local log_file="${DEFAULT_LOG_FILE}"
    
    if [ "$enable_log" == "true" ]; then
        if [ ! -d "$log_dir" ]; then mkdir -p "$log_dir"; fi
    fi

    local co_args=()
    if [ -f "$CUSTOM_OUT_FILE" ] && [ -s "$CUSTOM_OUT_FILE" ] && [ "$(cat "$CUSTOM_OUT_FILE")" != "[]" ]; then
         co_args=("--slurpfile" "custom_list" "$CUSTOM_OUT_FILE")
    else
         co_args=("--argjson" "custom_list" "[]")
    fi

    jq -n \
        "${co_args[@]}" \
        --arg log_level "warning" \
        --arg enable_log "$enable_log" \
        --arg log_path "$log_dir/$log_file" \
        --arg port_vmess "$PORT_VMESS" \
        --arg path_vm "$PATH_VM" \
        --arg port_vless "$PORT_VLESS" \
        --arg dec_key "$DEC_KEY" \
        --arg path_vl "$PATH_VL" \
        --arg port_reality "$PORT_REALITY" \
        --arg reality_dest "$REALITY_DEST" \
        --arg reality_sni "$REALITY_SNI" \
        --arg reality_pk "$REALITY_PK" \
        --arg reality_sid "$REALITY_SID" \
        --arg path_reality "$PATH_REALITY" \
        --arg port_ss "$PORT_SS" \
        --arg ss_cipher "$SS_CIPHER" \
        --arg pass_ss "$PASS_SS" \
        --arg uuid "$UUID" \
        --arg port_test "$PORT_TEST" \
        --arg port_api "$PORT_API" \
        --arg buffer_size "${BUFFER_SIZE:-16}" \
        --arg conn_idle "${CONN_IDLE:-1800}" \
        --arg auto_config "${AUTO_CONFIG:-false}" \
        --arg dns_strategy "$dns_strategy" \
    '
    ($custom_list | flatten(1)) as $cl |
    ($buffer_size | tonumber * 1024) as $buf_bytes |
    ($conn_idle | tonumber) as $idle |
    
    # Generate clients list for inbounds
    # Structure: { id: uuid, email: "custom-"+alias, level: 0 }
    (if ($cl | length > 0) then 
        ($cl | map({ id: .uuid, email: ("custom-" + .alias), level: 0 })) 
     else [] end) as $custom_clients |
     
    # Generate outbound objects
    # Structure: .config
    (if ($cl | length > 0) then 
        ($cl | map(.config)) 
     else [] end) as $custom_outbounds |
     
    # Generate routing rules
    # Structure: { type: "field", user: ["custom-"+alias], outboundTag: .config.tag }
    (if ($cl | length > 0) then 
        ($cl | map({ type: "field", user: ["custom-" + .alias], outboundTag: .config.tag })) 
     else [] end) as $custom_rules |

    {
        log: (if $enable_log == "true" then { loglevel: $log_level, access: $log_path, error: $log_path } else { loglevel: "none" } end),
        dns: {
            servers: ["8.8.8.8", "1.1.1.1", "8.8.4.4", "2001:4860:4860::8888", "2606:4700:4700::1111"],
            queryStrategy: $dns_strategy
        },
        api: {
            tag: "api",
            services: [ "StatsService" ]
        },
        stats: {},
        policy: (if $auto_config == "true" then {} else {
            levels: {
                "0": { handshake: 4, connIdle: $idle, uplinkOnly: 2, downlinkOnly: 4, bufferSize: ($buf_bytes / 1024), statsUserUplink: true, statsUserDownlink: true }
            },
            system: {
                statsInboundUplink: true,
                statsInboundDownlink: true,
                statsOutboundUplink: true,
                statsOutboundDownlink: true
            }
        } end),
        inbounds: [
            {
                tag: "vmess-in",
                port: ($port_vmess | tonumber),
                protocol: "vmess",
                settings: {
                    clients: ([
                        { id: $uuid, email: "direct", level: 0 }
                    ] + $custom_clients)
                },
                streamSettings: {
                    network: "ws",
                    wsSettings: { path: $path_vm }
                }
            },
            {
                tag: "vless-enc-in",
                port: ($port_vless | tonumber),
                protocol: "vless",
                settings: {
                     clients: ([
                        { id: $uuid, email: "direct", level: 0 }
                    ] + $custom_clients),
                    decryption: $dec_key
                },
                streamSettings: {
                    network: "xhttp",
                    xhttpSettings: { path: $path_vl }
                }
            },
            {
                tag: "vless-reality-in",
                port: ($port_reality | tonumber),
                protocol: "vless",
                settings: {
                     clients: ([
                        { id: $uuid, email: "direct", level: 0 }
                    ] + $custom_clients),
                    decryption: "none"
                },
                streamSettings: {
                    network: "xhttp",
                    security: "reality",
                    realitySettings: {
                        show: false,
                        dest: $reality_dest,
                        xver: 0,
                        serverNames: [$reality_sni],
                        privateKey: $reality_pk,
                        shortIds: [$reality_sid]
                    },
                    xhttpSettings: { path: $path_reality }
                }
            },
            {
                tag: "shadowsocks-in",
                port: ($port_ss | tonumber),
                protocol: "shadowsocks",
                settings: {
                    method: $ss_cipher,
                    password: $pass_ss,
                    network: "tcp,udp"
                }
            },
            {
                tag: "test-in-socks",
                listen: "127.0.0.1",
                port: ($port_test | tonumber),
                protocol: "socks",
                settings: { 
                    auth: "password", 
                    accounts: ([{user: "direct", pass: "test"}] + ($custom_clients | map({user: .email, pass: "test"}))),
                    udp: true 
                }
            },
            {
               tag: "api-in",
               listen: "127.0.0.1",
               port: ($port_api | tonumber),
               protocol: "dokodemo-door",
               settings: { address: "127.0.0.1" }
            }
        ],
        outbounds: ([
            { tag: "direct", protocol: "freedom" },
            { tag: "blocked", protocol: "blackhole" }
        ] + $custom_outbounds),
        routing: {
            domainStrategy: "IPIfNonMatch",
            rules: ([
                { type: "field", user: ["direct"], outboundTag: "direct" },
                { type: "field", inboundTag: ["api-in"], outboundTag: "api" }
            ] + $custom_rules + [
                { type: "field", inboundTag: ["test-in-socks"], outboundTag: "direct" }
            ])
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
description="Xray-Proxya Service"
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
description="Xray-Proxya Service"
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
Description=Xray-Proxya Service
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
    sys_reload_daemon
    sys_enable
    sys_restart
}

install_xray() {
    echo -e "=== 安装向导 ==="
    
    read -p "VMess-WS-$VMESS_CIPHER 入站端口 (默认 $DEFAULT_PORT_VMESS): " port_vm
    read -p "VLess-XHTTP-KEM768 (抗量子) 端口 (默认 $DEFAULT_PORT_VLESS_KEM): " port_vl
    read -p "VLess-XHTTP-Reality (TLS抗量子) 端口 (默认 $DEFAULT_PORT_REALITY): " port_rea
    read -p "Shadowsocks-$SS_CIPHER 端口 (默认 $DEFAULT_PORT_SS): " port_ss
    
    PORT_VMESS=$(validate_port "$port_vm" "$DEFAULT_PORT_VMESS") || return 1
    PORT_VLESS=$(validate_port "$port_vl" "$DEFAULT_PORT_VLESS_KEM") || return 1
    PORT_REALITY=$(validate_port "$port_rea" "$DEFAULT_PORT_REALITY") || return 1
    PORT_SS=$(validate_port "$port_ss" "$DEFAULT_PORT_SS") || return 1

    for p in $PORT_VMESS $PORT_VLESS $PORT_REALITY $PORT_SS; do
        if check_port_occupied $p; then echo -e "${RED}⚠️ 端口 $p 被占用${NC}"; return; fi
    done

    install_deps
    
    if ! show_scroll_log "Xray 核心下载" download_core; then
        echo -e "${RED}❌ 核心文件下载或安装失败，终止流程。${NC}"
        return 1
    fi

    echo -e "${BLUE}🔑 生成配置与密钥...${NC}"
    
    if ! "$XRAY_BIN" version >/dev/null 2>&1; then
        echo -e "${RED}❌ Xray 无法运行!${NC} (可能缺少依赖)"
        echo -e "Debug: $($XRAY_BIN version 2>&1)"
        return 1
    fi

    UUID=$("$XRAY_BIN" uuid)
    PATH_VM="/$(generate_random $DEFAULT_GEN_LEN)"
    PATH_VL="/$(generate_random $DEFAULT_GEN_LEN)"
    PATH_REALITY="/$(generate_random $DEFAULT_GEN_LEN)"
    PASS_SS=$(generate_random $DEFAULT_GEN_LEN)
    
    RAW_REALITY_OUT=$("$XRAY_BIN" x25519 2>&1)
    RAW_REALITY_OUT=$("$XRAY_BIN" x25519 2>&1)
    REALITY_PK=$(echo "$RAW_REALITY_OUT" | awk -F: 'tolower($0) ~ /private/ {gsub(/[ \r\t]/, "", $NF); print $NF; exit}')
    REALITY_PUB=$(echo "$RAW_REALITY_OUT" | awk -F: 'tolower($0) ~ /public|password/ {gsub(/[ \r\t]/, "", $NF); print $NF; exit}')

    REALITY_SID=$(openssl rand -hex 4)
    
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc 2>&1)
    RAW_ENC_OUT=$("$XRAY_BIN" vlessenc 2>&1)
    DEC_KEY=$(echo "$RAW_ENC_OUT" | awk -F'"' '/Authentication: ML-KEM-768/{flag=1} flag && /"decryption":/{print $4; exit}')
    ENC_KEY=$(echo "$RAW_ENC_OUT" | awk -F'"' '/Authentication: ML-KEM-768/{flag=1} flag && /"encryption":/{print $4; exit}')

    if [ -z "$REALITY_PUB" ] || [ -z "$REALITY_PK" ]; then
        echo -e "${RED}❌ Reality 密钥生成失败${NC}"
        echo -e "Debug Output:\n$RAW_REALITY_OUT"
        return 1
    fi

    if [ -z "$DEC_KEY" ]; then
        echo -e "${RED}❌ ML-KEM 密钥生成失败${NC}"
        echo -e "Debug Output:\n$RAW_ENC_OUT"
        return 1
    fi

    mkdir -p "$CONF_DIR"
    mkdir -p "$CONF_DIR"
    mkdir -p "$CONF_DIR"
    if [ ! -f "$CUSTOM_OUT_FILE" ]; then echo "[]" > "$CUSTOM_OUT_FILE"; fi
    
    cat > "$CONF_FILE" <<-EOF
PORT_VMESS=$PORT_VMESS
PORT_VLESS=$PORT_VLESS
PORT_REALITY=$PORT_REALITY
PORT_SS=$PORT_SS
UUID=$UUID
PATH_VM=$PATH_VM
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
ENABLE_LOG=$DEFAULT_ENABLE_LOG
LOG_DIR=$DEFAULT_LOG_DIR
AUTO_CONFIG=$AUTO_CONFIG
HIGH_PERFORMANCE_MODE=$HIGH_PERFORMANCE_MODE
MEM_LIMIT=$MEM_LIMIT
BUFFER_SIZE=$BUFFER_SIZE
CONN_IDLE=$CONN_IDLE
EOF
    generate_config
    
    if ! "$XRAY_BIN" run -test -c "$JSON_FILE" >/dev/null 2>&1; then
        echo -e "${RED}❌ 配置文件验证失败!${NC}"
        "$XRAY_BIN" run -test -c "$JSON_FILE"
        return 1
    fi

    create_service
    
    echo -e "${BLUE}📦 下载并部署维护脚本...${NC}"
    local maintenance_url="https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/maintain.sh"
    local maintenance_dst="/usr/local/bin/xray-proxya-maintenance"
    
    if curl -sSfL -o "$maintenance_dst" "$maintenance_url"; then
        chmod +x "$maintenance_dst"
        echo -e "${GREEN}✅ 维护脚本已下载并部署到: $maintenance_dst${NC}"
    else
        echo -e "${YELLOW}⚠️  维护脚本下载失败${NC}"
        echo -e "${YELLOW}   自动化维护功能可能不可用${NC}"
    fi
    
    echo -e "${GREEN}✅ 安装完成${NC}"
    
    echo -e "\n=== 链接信息 ==="
    show_links_logic "$UUID" "Direct"
}

# --- 链接展示 ---

format_ip() { [[ "$1" =~ .*:.* ]] && echo "[$1]" || echo "$1"; }

print_link_group() {
    local ip=$1; local label=$2; local target_uuid=$3; local desc=$4
    if [ -z "$ip" ]; then return; fi
    if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! [[ "$ip" =~ : ]]; then
        echo -e "${YELLOW}⚠️  跳过无效 IP: $ip${NC}"
        return
    fi
    local f_ip=$(format_ip "$ip")
    
    local ps_vm="VMess-WS-${VMESS_CIPHER}-${PORT_VMESS}"
    [ "$desc" == "Custom" ] && ps_vm="转发-$ps_vm"
    local vm_j=$(jq -n --arg add "$ip" --arg port "$PORT_VMESS" --arg id "$target_uuid" --arg path "$PATH_VM" --arg scy "$VMESS_CIPHER" --arg ps "$ps_vm" \
      '{v:"2", ps:$ps, add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
    local vm_l="vmess://$(echo -n "$vm_j" | base64 -w 0)"
    
    local ps_vl="VLess-XHTTP-KEM768-${PORT_VLESS}"
    [ "$desc" == "Custom" ] && ps_vl="转发-$ps_vl"
    local vl_l="vless://$target_uuid@$f_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#$ps_vl"
    
    local ps_rea="VLess-XHTTP-Reality-${PORT_REALITY}"
    [ "$desc" == "Custom" ] && ps_rea="转发-$ps_rea"
    local rea_l="vless://$target_uuid@$f_ip:$PORT_REALITY?security=reality&encryption=none&pbk=$REALITY_PUB&fp=chrome&type=xhttp&serviceName=&path=$PATH_REALITY&sni=$REALITY_SNI&sid=$REALITY_SID&spx=%2F#$ps_rea"

    local ss_l=""
    if [ "$desc" == "Direct" ]; then
        local ps_ss="SS-TCPUDP-${SS_CIPHER}-${PORT_SS}"
        local ss_auth=$(echo -n "${SS_CIPHER}:$PASS_SS" | base64 -w 0)
        ss_l="ss://$ss_auth@$f_ip:$PORT_SS#$ps_ss"
    fi

    echo -e "\n${BLUE}--- $label ($ip) ---${NC}"
    echo -e "1️⃣  VMess (${VMESS_CIPHER}):\n    ${GREEN}$vm_l${NC}"
    echo -e "2️⃣  VLESS (ML-KEM768):\n    ${GREEN}$vl_l${NC}"
    echo -e "3️⃣  VLESS (Reality-TLS):\n    ${GREEN}$rea_l${NC}"
    [ ! -z "$ss_l" ] && echo -e "4️⃣  Shadowsocks (${SS_CIPHER}):\n    ${GREEN}$ss_l${NC}"
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
    
    echo -e "\n=== 链接信息 (直接出站) ==="
    show_links_logic "$UUID" "Direct"
    
    if [ -f "$CUSTOM_OUT_FILE" ] && [ -s "$CUSTOM_OUT_FILE" ] && [ "$(cat "$CUSTOM_OUT_FILE")" != "[]" ]; then
         echo -e "\n${YELLOW}提示: 自定义出站链接已移至 [5. 自定义出站] 菜单中单独管理${NC}"
    fi
    read -p "按回车继续..."
}



change_ports() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    source "$CONF_FILE"
    echo -e "当前配置:"
    echo "1. VMess     : $PORT_VMESS"
    echo "2. VLESS(KEM): $PORT_VLESS"
    echo "3. Reality   : $PORT_REALITY"
    echo "4. SS        : $PORT_SS"
    
    read -p "新 VMess 端口 (回车跳过): " new_vm
    read -p "新 VLESS(KEM) 端口 (回车跳过): " new_vl
    read -p "新 Reality 端口 (回车跳过): " new_rea
    read -p "新 SS 端口 (回车跳过): " new_ss
    
    [[ ! -z "$new_vm" ]] && sed -i "s/^PORT_VMESS=.*/PORT_VMESS=$new_vm/" "$CONF_FILE"
    [[ ! -z "$new_vl" ]] && sed -i "s/^PORT_VLESS=.*/PORT_VLESS=$new_vl/" "$CONF_FILE"
    [[ ! -z "$new_rea" ]] && sed -i "s/^PORT_REALITY=.*/PORT_REALITY=$new_rea/" "$CONF_FILE"
    [[ ! -z "$new_ss" ]] && sed -i "s/^PORT_SS=.*/PORT_SS=$new_ss/" "$CONF_FILE"
    
    source "$CONF_FILE"
    generate_config
    sys_restart
    echo -e "${GREEN}✅ 已更新并重启${NC}"
}

clear_config() {
    echo -e "${YELLOW}⚠️  警告: 将清除所有配置 (端口、UUID、自定义出站等)${NC}"
    read -p "确认清除? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi
    
    sys_stop 2>/dev/null
    rm -rf "$CONF_DIR"
    
    echo -e "${GREEN}✅ 配置已清除。如需使用请重新运行安装/重置。${NC}"
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
            1) sys_start && echo "✅" ;;
            2) sys_stop && echo "✅" ;;
            3) sys_restart && echo "✅" ;;
            4) sys_enable && echo "✅" ;;
            5) sys_disable && echo "✅" ;;
            q|Q) return ;;
            *) echo "❌" ;;
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
        echo "1. 添加 Crontab 示例（注释形式，需手动编辑启用）"
        echo "2. 查看当前定时任务"
        echo "3. 移除所有本脚本相关的定时任务"
        echo "4. 编辑 Crontab（打开编辑器）"
        echo ""
        echo "q. 返回上级"
        read -p "选择: " am_choice
        
        case "$am_choice" in
            1)
                echo -e "\n${YELLOW}正在添加 Crontab 示例...${NC}"
                
                if crontab -l 2>/dev/null | grep -q "Xray-Proxya 自动化维护示例"; then
                    echo -e "${YELLOW}⚠️  检测到已存在示例，是否覆盖？(y/N)${NC}"
                    read -p "选择: " overwrite
                    if [[ "$overwrite" != "y" && "$overwrite" != "Y" ]]; then
                        echo -e "${BLUE}已取消${NC}"
                        continue
                    fi
                    crontab -l 2>/dev/null | sed '/# ======================================/,/# ======================================/d' | sed '/xray-proxya-auto-/d' | crontab -
                fi
                
                (crontab -l 2>/dev/null; cat <<'CRON_EXAMPLE'
# ======================================
# Xray-Proxya 自动化维护示例
# ======================================
# 使用说明：
#   1. 取消注释（删除行首 #）以启用对应任务
#   2. 根据需要修改时间（格式: 分 时 日 月 周）
#   3. 示例: "0 4 * * *" = 每天凌晨4点
#
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
                
                echo -e "${GREEN}✅ Crontab 示例已添加${NC}"
                echo -e "${YELLOW}提示: 使用选项 4 打开编辑器，取消注释并修改时间后保存即可启用任务${NC}"
                ;;
            2)
                echo -e "\n${BLUE}=== 当前 Crontab 任务 ===${NC}"
                local tasks=$(crontab -l 2>/dev/null | grep -E "(xray-proxya-auto-|Xray-Proxya 自动化维护)" || echo "")
                
                if [ -z "$tasks" ]; then
                    echo "无相关任务"
                else
                    echo "$tasks"
                fi
                ;;
            3)
                echo -e "\n${YELLOW}⚠️  将移除所有 Xray-Proxya 相关的 Crontab 任务（包括示例）${NC}"
                read -p "确认移除？(y/N): " confirm_remove
                
                if [[ "$confirm_remove" == "y" || "$confirm_remove" == "Y" ]]; then
                    crontab -l 2>/dev/null | \
                        sed '/# ======================================/,/# ======================================/d' | \
                        grep -v "xray-proxya-auto-" | \
                        crontab -
                    
                    echo -e "${GREEN}✅ 已移除相关任务${NC}"
                else
                    echo -e "${BLUE}已取消${NC}"
                fi
                ;;
            4)
                echo -e "\n${BLUE}正在打开 Crontab 编辑器...${NC}"
                echo -e "${YELLOW}提示: 取消注释（删除 # ）并修改时间后保存即可启用任务${NC}"
                sleep 1
                crontab -e
                ;;
            q|Q)
                return
                ;;
            *)
                echo -e "${RED}❌ 无效选择${NC}"
                ;;
        esac
    done
}

maintenance_menu() {
    while true; do
        echo -e "\n=== 维护 ==="
        echo "1. 服务操作 (启动/停止/重启...)"
        echo "2. 自动化维护 (定时任务)"
        echo "3. 清除配置"
        echo ""
        echo "q. 返回"
        read -p "选择: " m_choice
        case "$m_choice" in
            1) service_menu ;;
            2) auto_maintenance_menu ;;
            3) clear_config ;;
            q|Q) return ;;
            *) echo "❌" ;;
        esac
    done
}

uninstall_xray() {
    echo -e "${YELLOW}⚠️  警告: 将停止服务并删除配置。${NC}"
    read -p "确认卸载? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi
    sys_stop 2>/dev/null
    sys_disable 2>/dev/null
    rm "$SERVICE_FILE"
    rm -rf "$CONF_DIR"
    sys_reload_daemon
    echo -e "${GREEN}✅ 服务与配置已移除。${NC}"
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

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_root
    
    if [ -f "$CONF_FILE" ]; then
        source "$CONF_FILE"
        if [ -z "$PORT_API" ]; then
             echo -e "${YELLOW}检测到配置文件缺少 API 端口，正在自动更新以支持流量统计...${NC}"
             generate_config
             sys_restart 2>/dev/null
        fi
    fi

    while true; do
        echo -e "\n${BLUE}Xray-Proxya 管理${NC}"
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
fi
