#!/bin/bash

# ==================================================
# Xray-Proxya Client [CLIENT]
# Supports: Debian/Ubuntu & Alpine (OpenRC)
# ==================================================

# --- 默认配置变量 ---
DEFAULT_GEN_LEN=16
SERVICE_AUTO_RESTART="true"



# 日志配置
DEFAULT_ENABLE_LOG=true
DEFAULT_LOG_DIR="/var/log/xray-proxya"
DEFAULT_LOG_FILE="xray.log"

# TUN/TProxy 透明代理配置
# TUN_TPROXY_MODE: "off" | "tun" | "tproxy" | "both"
# 默认: "both" (如果启用)
TUN_TPROXY_MODE="both"
# LOCAL_LISTENER_MODE: "true" (代理本机+网关) | "false" (仅网关)
LOCAL_LISTENER_MODE="false"
# TPROXY_PORT: TProxy 入站端口
TPROXY_PORT=12345
# TUN_TPROXY_TARGET: 0=Direct, 1+ = Custom Outbound Index
TUN_TPROXY_TARGET=0

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
            if (run_sec < 0) run_sec = 0;
            d = int(run_sec / 86400);
            h = int((run_sec % 86400) / 3600);
            m = int((run_sec % 3600) / 60);
            s = int(run_sec % 60);
            if (d > 0) printf "%dd/%dh/%dm", d, h, m;
            else if (h > 0) printf "%dh/%dm", h, m;
            else if (m > 0) printf "%dm/%ds", m, s;
            else printf "%ds", s;
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
    
    # Try to get PID from pidfile first (OpenRC uses this)
    if [ -f "/run/xray-proxya.pid" ]; then
        pid=$(cat /run/xray-proxya.pid 2>/dev/null)
    fi
    
    # Fallback to pgrep if no PID from pidfile (systemd doesn't use pidfile)
    if [ -z "$pid" ] || [ ! -d "/proc/$pid" ]; then
        if command -v pgrep >/dev/null; then
            pid=$(pgrep -f "xray-proxya-core/xray" | head -n1)
        fi
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
        local local_addr_raw=$(url_decode "$addr_enc")
        local local_addr="${local_addr_raw%%/*}"  # Strip CIDR
        local reserved=$(url_decode "$res_enc")
        if [ -z "$mtu" ]; then mtu=1280; fi
        
        # Reserved handling: if present in URI, use it. If not, check if we need a default? 
        # Usually URI params are explicit. If missing, we treat as null.
        # But if the user wants "defaults like reserved", maybe they mean [0,0,0]?
        # Most client implementations leave it null unless specified.
        # We will follow the config file logic: if present, use it; otherwise null.
        
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
                    reserved: (if $res != null then ($res | split(",") | map(tonumber)) else null end),
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
    
    local mtu=$(echo "$conf_content" | grep -i "^MTU" | cut -d'=' -f2- | tr -d ' \r\t')
    [ -z "$mtu" ] && mtu=1280

    if [ -z "$private_key" ] || [ -z "$public_key" ] || [ -z "$endpoint" ]; then
        return 1
    fi
    
    # Strip CIDR from addresses (e.g., 10.0.0.2/32 -> 10.0.0.2)
    # Handle comma-separated list
    local addr_cleaned=$(echo "$address_line" | awk -F, '{
        for(i=1;i<=NF;i++) {
            split($i, a, "/"); 
            printf "%s%s", a[1], (i==NF?"":",") 
        }
    }')
    
    local addr_json=$(echo "$addr_cleaned" | awk -F, '{printf "["; for(i=1;i<=NF;i++) printf "\"%s\"%s", $i, (i==NF?"":","); printf "]"}')
    local res_json="null"
    if [ -n "$reserved_line" ]; then
        res_json=$(echo "$reserved_line" | awk -F, '{printf "["; for(i=1;i<=NF;i++) printf "%s%s", $i, (i==NF?"":","); printf "]"}')
    else
        # If user wants a default for reserved, we could set [0,0,0], but Xray standard is null if unused.
        # User requested "defaults like reserved". Let's assume if it makes sense.
        # However, purely guessing reserved bytes is dangerous. Only WARP uses specific ones.
        # We will keep it null unless explicitly asked to force [0,0,0].
        # User said "缺省补全, 比如 reserved". Maybe they mean providing a default structure?
        # Let's stick to null if missing, to avoid breaking standard WG.
        res_json="null"
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
        --arg mtu "$mtu" \
    '{
        tag: "custom-out",
        protocol: "wireguard",
        settings: {
            secretKey: $pk,
            address: $addr,
            address: $addr,
            reserved: (if $res != null then ($res | split(",") | map(tonumber)) else null end),
            peers: [{
                publicKey: $pub,
                endpoint: ($host + ":" + $port),
                preSharedKey: (if $psk != "" then $psk else null end)
            }],
            mtu: ($mtu | tonumber)
        }
    } | del(..|nulls)'
}

parse_interface_bind() {
    local iface="$1"
    local bind_addr="$2"
    if [ -z "$iface" ]; then return 1; fi
    
    jq -n -c --arg iface "$iface" --arg addr "$bind_addr" \
    '{
        tag: "custom-out",
        protocol: "freedom",
        sendThrough: (if $addr != "" then $addr else null end),
        settings: {},
        streamSettings: {
            sockopt: {
                interface: $iface,
                mark: 255
            }
        }
    } | del(..|nulls)'
}

migrate_custom_config() {
    [ ! -f "$CUSTOM_OUT_FILE" ] && return
    if [ ! -s "$CUSTOM_OUT_FILE" ]; then echo "[]" > "$CUSTOM_OUT_FILE"; return; fi
    
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
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}❌ 错误: 请先执行 '1. 安装 / 重置' 以生成基本配置。${NC}"
        sleep 2; return
    fi
    migrate_custom_config
    
    while true; do
        if [ ! -s "$CUSTOM_OUT_FILE" ] || ! grep -q "[^[:space:]]" "$CUSTOM_OUT_FILE" 2>/dev/null; then echo "[]" > "$CUSTOM_OUT_FILE"; fi
        
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
    echo "4. 绑定本地网络接口 (Interface Bind)"
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
        4)
            echo -e "${YELLOW}请输入要绑定的本地接口名称 (例如: wg0, tun1, eth1):${NC}"
            read -p "接口名: " iface_name
            [ -z "$iface_name" ] && return
            echo -e "${YELLOW}请输入要绑定的本地 IP (可选, 留空则系统自动选择):${NC}"
            echo -e "提示: WireGuard 场景建议填入在该网卡上的本地 IP (如: 10.5.0.2)"
            read -p "绑定 IP: " local_ip
            parsed_json=$(parse_interface_bind "$iface_name" "$local_ip")
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
    cp "$CUSTOM_OUT_FILE" "${CUSTOM_OUT_FILE}.bak"
    if jq --arg alias "$alias" --arg uuid "$new_uuid" --arg tag "$tag_name" --argjson newconf "$parsed_json" \
       '. + [{ alias: $alias, uuid: $uuid, config: ($newconf | .tag=$tag) }]' \
       "$CUSTOM_OUT_FILE" > "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
        mv "$tmp" "$CUSTOM_OUT_FILE"
        if apply_config_changes; then
            echo -e "${GREEN}✅ 添加成功${NC}"
            rm -f "${CUSTOM_OUT_FILE}.bak"
        else
            echo -e "${RED}❌ 配置生效失败，正在回滚...${NC}"
            mv "${CUSTOM_OUT_FILE}.bak" "$CUSTOM_OUT_FILE"
            apply_config_changes
        fi
    else
        rm -f "$tmp"
        rm -f "${CUSTOM_OUT_FILE}.bak"
        echo -e "${RED}❌ 保存配置失败，请检查链接格式${NC}"
    fi
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
                    cp "$CUSTOM_OUT_FILE" "${CUSTOM_OUT_FILE}.bak"
                    if jq "del(.[$idx])" "$CUSTOM_OUT_FILE" > "$tmp" && mv "$tmp" "$CUSTOM_OUT_FILE"; then
                        if apply_config_changes; then
                            echo -e "${GREEN}✅ 已删除${NC}"
                            rm -f "${CUSTOM_OUT_FILE}.bak"
                            return
                        else
                            echo -e "${RED}❌ 配置生效失败，正在回滚...${NC}"
                            mv "${CUSTOM_OUT_FILE}.bak" "$CUSTOM_OUT_FILE"
                            apply_config_changes
                        fi
                    else
                         rm -f "${CUSTOM_OUT_FILE}.bak"
                         echo -e "${RED}❌ 删除失败${NC}"
                    fi
                fi
                ;;
            q|Q) return ;;
            *) echo "❌" ;;
        esac
    done
}

apply_config_changes() {
    if generate_config; then
        sys_restart
        echo -e "${GREEN}配置已更新并重启服务${NC}"
        return 0
    else
        echo -e "${RED}❌ 配置文件生成失败 (jq error)${NC}"
        return 1
    fi
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
        --arg dns_strategy "$dns_strategy" \
        --arg direct_outbound "${DIRECT_OUTBOUND:-true}" \
        --arg tun_tproxy_mode "${TUN_TPROXY_MODE:-off}" \
        --arg local_listener_mode "${LOCAL_LISTENER_MODE:-false}" \
        --arg tproxy_port "${TPROXY_PORT:-12345}" \
        --arg tun_tproxy_target "${TUN_TPROXY_TARGET:-0}" \
    '
    ($custom_list | flatten(1)) as $cl |
    
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
     
    # Determine TUN/TProxy target outbound tag
    ($tun_tproxy_target | tonumber) as $tt_target_idx |
    (if $tt_target_idx == 0 then "direct"
     elif ($cl | length) >= $tt_target_idx then
        ($cl[$tt_target_idx - 1].config.tag)
     else "direct" end) as $tt_outbound_tag |

    [
        {
            "tag": "api-in",
            "listen": "127.0.0.1",
            "port": ($port_api | tonumber),
            "protocol": "dokodemo-door",
            "settings": { "address": "127.0.0.1" }
        },
        {
            "tag": "test-in-socks",
            "listen": "127.0.0.1",
            "port": ($port_test | tonumber),
            "protocol": "socks",
            "settings": { 
                "auth": "password", 
                "accounts": (
                    (if $direct_outbound == "true" then [{ "user": "direct", "pass": "test" }] else [] end)
                    + ($custom_clients | map({ "user": .email, "pass": "test" }))
                ),
                "udp": true 
            }
        }
    ] as $inbound_std |

    (if ($tun_tproxy_mode == "tun" or $tun_tproxy_mode == "both") then [{
        "tag": "tun-in",
        "protocol": "tun",
        "settings": {
            "name": "tun0",
            "mtu": 1500,
            "userLevel": 0
        },
        "sniffing": {
            "enabled": true,
            "destOverride": ["http", "tls"]
        }
    }] else [] end) as $inbound_tun |

    (if ($tun_tproxy_mode == "tproxy" or $tun_tproxy_mode == "both") then [{
        "tag": "tproxy-in",
        "port": ($tproxy_port | tonumber),
        "protocol": "dokodemo-door",
        "settings": {
            "network": "tcp,udp",
            "followRedirect": true
        },
        "sniffing": {
            "enabled": true,
            "destOverride": ["http", "tls", "quic"]
        },
        "streamSettings": {
            "sockopt": {
                "tproxy": "tproxy"
            }
        }
    }] else [] end) as $inbound_tproxy |

    # --- Construct Final Config ---
    {
        "log": {
            "access": $log_path,
            "error": $log_path,
            "loglevel": $log_level
        },
        "api": {
            "tag": "api",
            "services": ["HandlerService", "LoggerService", "StatsService"]
        },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": true,
                    "statsUserDownlink": true
                }
            },
            "system": {
                "statsInboundUplink": true,
                "statsInboundDownlink": true,
                "statsOutboundUplink": true,
                "statsOutboundDownlink": true
            }
        },
        "inbounds": ($inbound_std + $inbound_tun + $inbound_tproxy),
        "outbounds": ([
            { "protocol": "freedom", "tag": "direct", "streamSettings": { "sockopt": { "mark": 255 } } },
            { "tag": "blocked", "protocol": "blackhole" }
        ] + $custom_outbounds),
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": ([
                { "type": "field", "inboundTag": ["api-in"], "outboundTag": "api" },
                (if $tun_tproxy_mode != "off" then
                    { "type": "field", "inboundTag": ["tun-in", "tproxy-in"], "outboundTag": $tt_outbound_tag }
                 else empty end),
                { "type": "field", "inboundTag": ["test-in-socks"], "outboundTag": (if $direct_outbound == "true" then "direct" else "blocked" end) }
            ] + $custom_rules)
        }
    }' > "$JSON_FILE"
}

create_service() {
    source "$CONF_FILE"

    if [ $IS_OPENRC -eq 1 ]; then
        if [ "$SERVICE_AUTO_RESTART" == "true" ]; then
            cat > "$SERVICE_FILE" <<-EOF
#!/sbin/openrc-run
name="xray-proxya"
description="Xray-Proxya Service"
supervisor="supervise-daemon"
command="$XRAY_BIN"
command_args="run -c $JSON_FILE"
pidfile="/run/xray-proxya.pid"
rc_ulimit="-n 2048"
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
command_background=true
pidfile="/run/xray-proxya.pid"
rc_ulimit="-n 2048"
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
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$XRAY_BIN run -c $JSON_FILE
$(echo -e "$restart_conf")
LimitNOFILE=2048
[Install]
WantedBy=multi-user.target
EOF
    fi
    sys_reload_daemon
    sys_enable
    sys_restart
}

install_xray() {
    echo -e "=== 安装向导 (客户端模式) ==="
    
    install_deps
    
    if ! show_scroll_log "Xray 核心下载" download_core; then
        echo -e "${RED}❌ 核心文件下载或安装失败，终止流程。${NC}"
        return 1
    fi

    mkdir -p "$CONF_DIR"
    if [ ! -f "$CUSTOM_OUT_FILE" ]; then echo "[]" > "$CUSTOM_OUT_FILE"; fi
    
    cat > "$CONF_FILE" <<-EOF
ENABLE_LOG=$DEFAULT_ENABLE_LOG
LOG_DIR=$DEFAULT_LOG_DIR
TUN_TPROXY_MODE="both"
LOCAL_LISTENER_MODE="false"
TPROXY_PORT=12345
TUN_TPROXY_TARGET=0
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
    
    # 初始应用防火墙规则 (如果开启)
    setup_firewall_rules
    
    echo -e "${GREEN}✅ 安装完成${NC}"
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
            3) generate_config; sys_restart && echo "✅" ;;
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

tun_tproxy_menu() {
    while true; do
        source "$CONF_FILE" 2>/dev/null
        local current_mode="${TUN_TPROXY_MODE:-off}"
        local local_mode="${LOCAL_LISTENER_MODE:-false}"
        
        local mode_status="禁用"
        case "$current_mode" in
            tun) mode_status="TUN 模式" ;;
            tproxy) mode_status="TProxy 模式" ;;
            both) mode_status="TUN + TProxy" ;;
        esac
        
        local listener_status="仅网关 (转发)"
        [ "$local_mode" == "true" ] && listener_status="本机 + 网关"
        
        # 获取当前目标名称
        local target_name="直连 (Direct)"
        local target_idx="${TUN_TPROXY_TARGET:-0}"
        if [ "$target_idx" -gt 0 ]; then
             if [ -f "$CUSTOM_OUT_FILE" ] && [ -s "$CUSTOM_OUT_FILE" ]; then
                 local t_tag=$(jq -r ".[$((target_idx-1))].config.tag" "$CUSTOM_OUT_FILE" 2>/dev/null)
                 [ -n "$t_tag" ] && [ "$t_tag" != "null" ] && target_name="自定义: $t_tag" || target_name="未知 (索引失效)"
             else
                 target_name="未知 (无自定义配置)"
             fi
        fi

        echo -e "\n=== TUN/TProxy 管理 ==="
        echo -e "当前模式: ${BLUE}${mode_status}${NC} $tproxy_warn"
        echo -e "监听范围: ${BLUE}${listener_status}${NC}"
        echo -e "出口目标: ${BLUE}${target_name}${NC}"
        echo ""
        echo "1. 设置模式: 禁用 (Off)"
        echo "2. 设置模式: TUN 模式"
        echo "3. 设置模式: TProxy 模式"
        echo "4. 设置模式: 启用全部 (Both)"
        echo ""
        echo "5. 切换监听流量: [${listener_status}]"
        echo "   (仅网关=只代理转发流量; 本机+网关=同时代理本机流量)"
        echo "6. 设置出口流量目标"
        echo ""
        echo "q. 返回主菜单"
        read -p "选择: " tp_choice
        
        case "$tp_choice" in
            1) set_tun_tproxy_mode "off" ;;
            2) set_tun_tproxy_mode "tun" ;;
            3) set_tun_tproxy_mode "tproxy" ;;
            4) set_tun_tproxy_mode "both" ;;
            5) toggle_local_listener_mode ;;
            6) select_tun_tproxy_target ;;
            q|Q) return ;;
            *) echo -e "${RED}无效选择${NC}" ;;
        esac
    done
}

select_tun_tproxy_target() {
    if [ ! -f "$CUSTOM_OUT_FILE" ] || [ ! -s "$CUSTOM_OUT_FILE" ]; then
        echo -e "${YELLOW}没有找到自定义出站配置，只能使用直连。${NC}"
        read -p "按回车继续..."
        return
    fi
    
    local count=$(jq 'length' "$CUSTOM_OUT_FILE" 2>/dev/null)
    if [ -z "$count" ] || [ "$count" -eq 0 ]; then
        echo -e "${YELLOW}自定义出站列表为空。${NC}"
        read -p "按回车继续..."
        return
    fi
    
    echo -e "\n=== 选择 TUN/TProxy 出口目标 ==="
    echo "0. 直连 (Direct)"
    for ((i=0; i<count; i++)); do
        local tag=$(jq -r ".[$i].config.tag" "$CUSTOM_OUT_FILE")
        echo "$((i+1)). 自定义: $tag"
    done
    echo ""
    read -p "请输入目标编号 (0-$count): " t_choice
    
    if [[ "$t_choice" =~ ^[0-9]+$ ]] && [ "$t_choice" -le "$count" ]; then
        TUN_TPROXY_TARGET=$t_choice
        if grep -q "TUN_TPROXY_TARGET=" "$CONF_FILE"; then
            sed -i "s/TUN_TPROXY_TARGET=.*/TUN_TPROXY_TARGET=$TUN_TPROXY_TARGET/" "$CONF_FILE"
        else
            echo "TUN_TPROXY_TARGET=$TUN_TPROXY_TARGET" >> "$CONF_FILE"
        fi
        
        echo -e "${GREEN}✅ 目标已更新，正在应用并重启服务...${NC}"
        generate_config
        sys_restart
        sleep 1
    else
        echo -e "${RED}无效输入${NC}"
        sleep 1
    fi
}

set_tun_tproxy_mode() {
    local target_mode=$1
    if grep -q "TUN_TPROXY_MODE=" "$CONF_FILE"; then
        sed -i "s/TUN_TPROXY_MODE=.*/TUN_TPROXY_MODE=$target_mode/" "$CONF_FILE"
    else
        echo "TUN_TPROXY_MODE=$target_mode" >> "$CONF_FILE"
    fi
    
    # 自动应用配置
    generate_config
    setup_firewall_rules
    sys_restart
    
    echo -e "${GREEN}✅ 模式已更新为: $target_mode${NC}"
    
    if [ "$target_mode" == "tproxy" ] || [ "$target_mode" == "both" ]; then
        echo -e "${YELLOW}⚠️  已应用透明代理规则 (iptables/nftables)${NC}"
    fi
    if [ "$target_mode" == "tun" ] || [ "$target_mode" == "both" ]; then
         echo -e "${YELLOW}⚠️  TUN 模式需确保系统路由正确配置${NC}"
    fi
    sleep 1
}

toggle_local_listener_mode() {
    source "$CONF_FILE"
    if [ "${LOCAL_LISTENER_MODE:-false}" == "true" ]; then
        LOCAL_LISTENER_MODE="false"
        echo -e "${BLUE}已切换为: 仅网关模式 (只代理转发流量)${NC}"
    else
        LOCAL_LISTENER_MODE="true"
        echo -e "${BLUE}已切换为: 本机代理模式 (代理本机+转发流量)${NC}"
    fi
    
    if grep -q "LOCAL_LISTENER_MODE=" "$CONF_FILE"; then
        sed -i "s/LOCAL_LISTENER_MODE=.*/LOCAL_LISTENER_MODE=$LOCAL_LISTENER_MODE/" "$CONF_FILE"
    else
        echo "LOCAL_LISTENER_MODE=$LOCAL_LISTENER_MODE" >> "$CONF_FILE"
    fi
    
    generate_config
    setup_firewall_rules # 更新规则
    sys_restart
    echo -e "${GREEN}✅ 本机监听状态已更新${NC}"
    sleep 1
}

setup_firewall_rules() {
    local tproxy_port=$TPROXY_PORT
    local mark=1
    local table=100
    
    # 清理旧规则
    ip rule del fwmark $mark table $table >/dev/null 2>&1
    ip route del local 0.0.0.0/0 dev lo table $table >/dev/null 2>&1
    
    if [ "$TUN_TPROXY_MODE" != "off" ]; then
        sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
        sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
    fi
    
    # 清理 iptables
    iptables -t mangle -D PREROUTING -j XRAY_TPROXY >/dev/null 2>&1
    iptables -t mangle -D OUTPUT -j XRAY_OUTPUT >/dev/null 2>&1
    iptables -t mangle -F XRAY_TPROXY >/dev/null 2>&1
    iptables -t mangle -X XRAY_TPROXY >/dev/null 2>&1
    iptables -t mangle -F XRAY_OUTPUT >/dev/null 2>&1
    iptables -t mangle -X XRAY_OUTPUT >/dev/null 2>&1
    
    # 清理 nftables (如果存在)
    if command -v nft >/dev/null 2>&1; then
        nft delete table ip xray_proxya >/dev/null 2>&1
    fi
    
    if [ "$TUN_TPROXY_MODE" == "off" ] || [ "$TUN_TPROXY_MODE" == "tun" ]; then
        return 0
    fi
    
    # === TProxy 配置 ===
    echo -e "${BLUE}配置 TProxy 防火墙规则...${NC}"
    
    # 策略路由
    ip rule add fwmark $mark table $table
    ip route add local 0.0.0.0/0 dev lo table $table
    
    # 优先使用 nftables (如果已安装)
    if command -v nft >/dev/null 2>&1; then
        echo "应用 nftables 规则..."
        
        # 构建 nftables 规则
        cat > /tmp/xray_nft.conf <<EOF
table ip xray_proxya {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255/32 } return
        ip protocol { tcp, udp } tproxy to 127.0.0.1:$tproxy_port meta mark set $mark
    }
    chain output {
        type route hook output priority mangle; policy accept;
        meta mark $mark return
        ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255/32 } return
        
        # 排除 xray 用户 (防止回环) - 需确保 xray 以 root 或特定用户运行，这里暂按 mark 排除
        # 实际生产中应排除运行 Xray 的用户 ID 或 cgroup
        
        # 本机监听模式
        $(if [ "$LOCAL_LISTENER_MODE" == "true" ]; then echo "ip protocol { tcp, udp } meta mark set $mark"; fi)
    }
}
EOF
        nft -f /tmp/xray_nft.conf
        rm /tmp/xray_nft.conf
        
    else
        echo "应用 iptables 规则..."
        # PREROUTING 链
        iptables -t mangle -N XRAY_TPROXY
        # 排除局域网和特殊地址
        iptables -t mangle -A XRAY_TPROXY -d 127.0.0.0/8 -j RETURN
        iptables -t mangle -A XRAY_TPROXY -d 10.0.0.0/8 -j RETURN
        iptables -t mangle -A XRAY_TPROXY -d 172.16.0.0/12 -j RETURN
        iptables -t mangle -A XRAY_TPROXY -d 192.168.0.0/16 -j RETURN
        iptables -t mangle -A XRAY_TPROXY -d 224.0.0.0/4 -j RETURN
        iptables -t mangle -A XRAY_TPROXY -d 255.255.255.255/32 -j RETURN
        # TProxy 标记
        iptables -t mangle -A XRAY_TPROXY -p tcp -j TPROXY --on-port $tproxy_port --tproxy-mark $mark
        iptables -t mangle -A XRAY_TPROXY -p udp -j TPROXY --on-port $tproxy_port --tproxy-mark $mark
        iptables -t mangle -A PREROUTING -j XRAY_TPROXY
        
        # OUTPUT 链 (监听本机)
        if [ "$LOCAL_LISTENER_MODE" == "true" ]; then
            iptables -t mangle -N XRAY_OUTPUT
            iptables -t mangle -A XRAY_OUTPUT -m mark --mark 0xff -j RETURN # 排除 Xray 发出的流量 (需配合 sockopt mark)
            iptables -t mangle -A XRAY_OUTPUT -d 127.0.0.0/8 -j RETURN
            iptables -t mangle -A XRAY_OUTPUT -d 10.0.0.0/8 -j RETURN
            iptables -t mangle -A XRAY_OUTPUT -d 172.16.0.0/12 -j RETURN
            iptables -t mangle -A XRAY_OUTPUT -d 192.168.0.0/16 -j RETURN
            iptables -t mangle -A XRAY_OUTPUT -p tcp -j MARK --set-mark $mark
            iptables -t mangle -A XRAY_OUTPUT -p udp -j MARK --set-mark $mark
            iptables -t mangle -A OUTPUT -j XRAY_OUTPUT
        fi
    fi
    
    echo -e "${GREEN}✅ 防火墙规则已应用${NC}"
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
    # 同步新变量
    [ -n "$TUN_TPROXY_MODE" ] && sed -i "s/^TUN_TPROXY_MODE=.*/TUN_TPROXY_MODE=$TUN_TPROXY_MODE/" "$CONF_FILE"
    [ -n "$LOCAL_LISTENER_MODE" ] && sed -i "s/^LOCAL_LISTENER_MODE=.*/LOCAL_LISTENER_MODE=$LOCAL_LISTENER_MODE/" "$CONF_FILE"
    [ -n "$TUN_TPROXY_TARGET" ] && sed -i "s/^TUN_TPROXY_TARGET=.*/TUN_TPROXY_TARGET=$TUN_TPROXY_TARGET/" "$CONF_FILE"
    source "$CONF_FILE"; generate_config; setup_firewall_rules; create_service
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
        echo -e "\n${BLUE}Xray-Proxya Client [CLIENT]${NC}"
        check_status
        echo "1. 安装 / 重置"
        echo "2. TUN/TProxy"
        echo "3. 出站配置"
        echo "4. 维护菜单"
        echo "5. 测试连通性"
        echo ""
        echo "8. 刷新配置"
        echo "9. 重装内核"
        echo "0. 卸载"
        echo "q. 退出"
        read -p "选择: " choice
        case "$choice" in
            1) install_xray ;;
            2) tun_tproxy_menu ;;
            3) custom_outbound_menu ;;
            4) maintenance_menu ;;
            5) test_custom_outbound ;;
            8) apply_refresh ;;
            9) reinstall_core ;;
            0) uninstall_xray ;;
            q|Q) exit 0 ;;
            *) echo -e "${RED}无效${NC}" ;;
        esac
    done
fi
