#!/bin/bash

# ==================================================
# Xray-Proxya Common Library
# Contains shared functions and variables
# ==================================================

# --- Global Variables & Constants ---

CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
CUSTOM_OUT_FILE="$CONF_DIR/custom_outbound.json"
XRAY_DIR="/usr/local/bin/xray-proxya-core"
XRAY_BIN="$XRAY_DIR/xray"
JSON_FILE="$XRAY_DIR/config.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Defaults (Can be overridden by sourcing script)
DEFAULT_PORT_VMESS=${DEFAULT_PORT_VMESS:-8081}
DEFAULT_PORT_VLESS_KEM=${DEFAULT_PORT_VLESS_KEM:-8082}
DEFAULT_PORT_REALITY=${DEFAULT_PORT_REALITY:-8443}
DEFAULT_PORT_VISION=${DEFAULT_PORT_VISION:-443}
DEFAULT_PORT_SS=${DEFAULT_PORT_SS:-8083}
SERVICE_AUTO_RESTART=${SERVICE_AUTO_RESTART:-"true"}

# Encryption / Cipher Defaults
VMESS_CIPHER=${VMESS_CIPHER:-"chacha20-poly1305"}
SS_CIPHER=${SS_CIPHER:-"aes-256-gcm"}
REALITY_DEST=${REALITY_DEST:-"apple.com:443"}
REALITY_SNI=${REALITY_SNI:-"apple.com"}

VISION_DEST=${VISION_DEST:-"apple.com:443"}
VISION_SNI=${VISION_SNI:-"apple.com"}

# Detect System
IS_OPENRC=0
if [ -f /etc/alpine-release ] && command -v rc-service >/dev/null 2>&1; then
    IS_OPENRC=1
fi

if [ "$IS_OPENRC" -eq 1 ]; then
    SERVICE_FILE="/etc/init.d/xray-proxya"
else
    SERVICE_FILE="/etc/systemd/system/xray-proxya.service"
fi

# --- Helper Functions ---

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}❌ Error: This script must be run as root.${NC}"
        exit 1
    fi
}

# Safe config file loader - prevents command injection via source
# Usage: load_config [config_file]
# Defaults to $CONF_FILE if no argument given
load_config() {
    local config_file="${1:-$CONF_FILE}"
    [ ! -f "$config_file" ] && return 1
    local line key value
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        # Must contain =
        [[ "$line" != *=* ]] && continue
        # Extract key (before first =) and value (after first =)
        key="${line%%=*}"
        value="${line#*=}"
        # Strip whitespace from key
        key="${key// /}"
        # Validate key: must be a valid shell variable name
        [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && continue
        # Reject values containing command substitution patterns
        if [[ "$value" == *'$('* ]] || [[ "$value" == *'\`'* ]]; then
            echo "⚠️  load_config: skipped unsafe key: $key" >&2
            continue
        fi
        # Remove surrounding quotes if present
        if [[ "$value" =~ ^\"(.*)\"$ ]]; then
            value="${BASH_REMATCH[1]}"
        elif [[ "$value" =~ ^\'(.*)\'$ ]]; then
            value="${BASH_REMATCH[1]}"
        fi
        # Safely assign variable (printf -v does not interpret shell metacharacters)
        printf -v "$key" '%s' "$value"
        export "$key"
    done < "$config_file"
    return 0
}

# Safe config value update - escapes sed special characters to prevent injection
# Usage: update_config_value KEY VALUE [config_file]
update_config_value() {
    local key="$1"
    local value="$2"
    local file="${3:-$CONF_FILE}"
    # Validate key format
    [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && return 1
    # Escape sed replacement special characters: & / \
    local safe_value
    safe_value=$(printf '%s' "$value" | sed 's/[&/\]/\\&/g')
    if [ -f "$file" ] && grep -q "^${key}=" "$file"; then
        sed -i "s/^${key}=.*/${key}=${safe_value}/" "$file"
    else
        echo "${key}=${value}" >> "$file"
    fi
}

human_readable() {
    local bytes="$1"
    if [ -z "$bytes" ] || ! [[ "$bytes" =~ ^[0-9]+$ ]]; then echo "0 B"; return; fi
    if [ "$bytes" -lt 1024 ]; then echo "${bytes} B"
    elif [ "$bytes" -lt 1048576 ]; then echo "$(( (bytes * 100) / 1024 ))" | sed 's/..$/.&/' | awk '{printf "%.2f KB", $0}'
    elif [ "$bytes" -lt 1073741824 ]; then echo "$(( (bytes * 100) / 1048576 ))" | sed 's/..$/.&/' | awk '{printf "%.2f MB", $0}'
    else echo "$(( (bytes * 100) / 1073741824 ))" | sed 's/..$/.&/' | awk '{printf "%.2f GB", $0}'
    fi
}

get_runtime_formatted() {
    local pid=$1
    if [ -z "$pid" ]; then return; fi
    
    local runtime_str=""
    
    # Method 1: Directory modification time (Container friendly)
    if [ -d "/proc/$pid" ]; then
        local start_time=$(stat -c %Y "/proc/$pid" 2>/dev/null)
        local now=$(date +%s)
        
        if [ -n "$start_time" ] && [ "$now" -ge "$start_time" ]; then
            local run_sec=$((now - start_time))
            local d=$((run_sec / 86400))
            local h=$(( (run_sec % 86400) / 3600 ))
            local m=$(( (run_sec % 3600) / 60 ))
            local s=$(( run_sec % 60 ))
            
            if [ "$d" -gt 0 ]; then runtime_str=$(printf "%dd/%dh/%dm" "$d" "$h" "$m")
            elif [ "$h" -gt 0 ]; then runtime_str=$(printf "%dh/%dm" "$h" "$m")
            elif [ "$m" -gt 0 ]; then runtime_str=$(printf "%dm/%ds" "$m" "$s")
            else runtime_str=$(printf "%ds" "$s")
            fi
        fi
    fi

    # Method 2: Fallback to ps
    if [ -z "$runtime_str" ] && command -v ps >/dev/null 2>&1; then
         local etime=$(ps -o etime= -p "$pid" 2>/dev/null | tr -d ' ')
         if [ -n "$etime" ]; then
             runtime_str="running($etime)"
         fi
    fi
    
    echo "$runtime_str"
}

sys_enable() {
    if [ "$IS_OPENRC" -eq 1 ]; then
        rc-update add xray-proxya default >/dev/null 2>&1
    else
        systemctl enable xray-proxya >/dev/null 2>&1
    fi
}
sys_disable() {
    if [ "$IS_OPENRC" -eq 1 ]; then
        rc-update del xray-proxya default >/dev/null 2>&1
    else
        systemctl disable xray-proxya >/dev/null 2>&1
    fi
}
sys_start() {
    if [ "$IS_OPENRC" -eq 1 ]; then
        rc-service xray-proxya start
    else
        systemctl start xray-proxya
    fi
}
sys_stop() {
    if [ "$IS_OPENRC" -eq 1 ]; then
        rc-service xray-proxya stop
    else
        systemctl stop xray-proxya
    fi
}
sys_restart() {
    if [ "$IS_OPENRC" -eq 1 ]; then
        rc-service xray-proxya restart
    else
        systemctl restart xray-proxya
    fi
}
sys_reload_daemon() {
    if [ "$IS_OPENRC" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
    fi
}

check_status() {
    local pid=""
    if [ -f "/run/xray-proxya.pid" ]; then
        pid=$(cat /run/xray-proxya.pid 2>/dev/null)
    fi
    if [ -z "$pid" ] || [ ! -d "/proc/$pid" ]; then
        if command -v pgrep >/dev/null; then
            pid=$(pgrep -f "xray-proxya-core/xray" | head -n1)
        fi
    fi
    
    local is_running=0
    if [ "$IS_OPENRC" -eq 1 ]; then
        if rc-service xray-proxya status 2>/dev/null | grep -q "started"; then is_running=1; fi
    else
        if systemctl is-active --quiet xray-proxya; then is_running=1; fi
    fi
    
    if [ "$is_running" -eq 1 ]; then
        local runtime=""
        if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
             runtime="($(get_runtime_formatted "$pid"))"
        fi
        echo -e "🟢 Service Status: ${GREEN}Running${NC} $runtime"
    else
        echo -e "🔴 Service Status: ${RED}Stopped${NC}"
    fi
    
    if [ "$is_running" -eq 1 ] && [ -f "$CONF_FILE" ]; then
        local api_port=$(grep "PORT_API=" "$CONF_FILE" | cut -d= -f2)
        if [ -n "$api_port" ]; then
             echo -e "$(get_xray_stats "$api_port")"
        fi
    fi
}

get_xray_stats() {
    local port_api=$1
    if [ -z "$port_api" ]; then return; fi
    
    # 获取属于 xray 进程的已建立 TCP 连接数
    local conn_count
    conn_count=$(ss -ntp 2>/dev/null | grep -i "\"xray\"" | grep -c "ESTAB") || true
    [ -z "$conn_count" ] && conn_count=0
    
    # 查询 Xray API (使用 api.listen 方式, 无需 dokodemo-door inbound)
    local stats_json
    stats_json=$("$XRAY_BIN" api statsquery -server=127.0.0.1:$port_api 2>/dev/null)
    
    # 查询失败则显示 N/A
    if [ -z "$stats_json" ] || ! echo "$stats_json" | jq -e . >/dev/null 2>&1; then
        echo "| Connections: $conn_count | Total Usage: N/A | Custom Outbound: N/A |"
        return
    fi
    
    # 统计所有真实入站的总和 (排除 api-in 内部通信)
    local total_bytes
    total_bytes=$(echo "$stats_json" | jq -r '[.stat[]? | select(.name | startswith("inbound>>>") and (contains("api-in")|not)) | (.value // 0)] | add // 0' 2>/dev/null)
    local h_total="0 B"
    [ "${total_bytes:-0}" -gt 0 ] && h_total=$(human_readable "$total_bytes")
    
    local custom_status="N/A"
    
    # 获取所有的自定义出站统计 (匹配 custom-out-xxx 所有后缀)
    if [ -f "$CUSTOM_OUT_FILE" ] && [ -s "$CUSTOM_OUT_FILE" ] && [ "$(cat "$CUSTOM_OUT_FILE")" != "[]" ]; then
        custom_status="0 B"
        local custom_total
        custom_total=$(echo "$stats_json" | jq -r '[.stat[]? | select(.name | startswith("outbound>>>custom-out")) | (.value // 0)] | add // 0' 2>/dev/null)
        if [ "${custom_total:-0}" -gt 0 ]; then
            custom_status=$(human_readable "$custom_total")
        fi
    fi
    
    echo "| Connections: $conn_count | Total Usage: $h_total | Custom Outbound: $custom_status |"
}

show_scroll_log() {
    local title="$1"
    local command="$2"
    
    if ! command -v tput >/dev/null 2>&1; then
        "$command"
        return $?
    fi

    local log_file=$(mktemp)
    echo -e "${BLUE}=== $title ===${NC}"
    for i in {1..5}; do echo ""; done
    
    "$command" >"$log_file" 2>&1 &
    local pid=$!
    
    while kill -0 $pid 2>/dev/null; do
        tput cuu 5
        tput ed
        tail -n 5 "$log_file"
        sleep 0.2
    done
    wait $pid
    local ret=$?
    
    if [ "$ret" -ne 0 ]; then
        tput cuu 5
        tput ed
        echo -e "${RED}❌ $title Failed. Log:${NC}"
        cat "$log_file"
        rm "$log_file"
        return "$ret"
    else
        tput cuu 5
        tput ed
        echo -e "${GREEN}✅ $title Completed${NC}"
        rm "$log_file"
        return 0
    fi
}

install_deps() {
    echo -e "${BLUE}📦 Checking dependencies...${NC}"
    local deps_chk=("curl" "jq" "openssl" "unzip")
    local need_install=0
    for dep in "${deps_chk[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then need_install=1; break; fi
    done
    if [ "$need_install" -eq 0 ]; then echo -e "${GREEN}✅ Dependencies ready.${NC}"; return 0; fi
    
    echo -e "${BLUE}🔨 Installing dependencies...${NC}"
    if [ -f /etc/alpine-release ]; then
        apk update && apk add curl jq openssl bash coreutils gcompat iproute2 grep libgcc libstdc++ sed gawk unzip dialog ncurses tzdata
    else
        apt-get update && apt-get install -y curl jq unzip openssl dialog ncurses-bin
    fi
}

optimize_network() {
    echo -e "${BLUE}🔧 Optimizing network (Sysctl & UDP)...${NC}"
    # Simple check if fs is writable, otherwise suppress errors
    sysctl -w net.core.rmem_max=8388608 >/dev/null 2>&1
    sysctl -w net.core.wmem_max=8388608 >/dev/null 2>&1
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
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
            pid=$(echo "$output" | sed -n 's/[^0-9]*\([0-9]*\)\/.*/\1/p' | awk '{print $NF}')
        fi
        if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
            local exe_link=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
            if [[ "$exe_link" == "$XRAY_BIN" ]]; then return 1; fi
        fi
        return 0
    fi
    return 1
}

validate_port() {
    local port=$1
    local default=$2
    if [ -z "$port" ]; then echo "$default"; return 0; fi
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo -e "${RED}❌ Error: Port must be 1-65535${NC}" >&2
        return 1
    fi
    echo "$port"
    return 0
}

generate_random() {
    openssl rand -base64 $(( $1 * 2 )) | tr -dc 'a-zA-Z0-9' | head -c $1
}

decode_base64() {
    local str="$1"
    local mod=$((${#str} % 4))
    if [ "$mod" -eq 3 ]; then str="${str}="; elif [ "$mod" -eq 2 ]; then str="${str}=="; elif [ "$mod" -eq 1 ]; then str="${str}==="; fi
    echo "$str" | base64 -d 2>/dev/null || echo "$str" | base64 -d -i 2>/dev/null
}

url_decode() {
    local data="${1//+/ }"
    local decoded="" i=0 c hex
    while [ "$i" -lt "${#data}" ]; do
        c="${data:$i:1}"
        if [ "$c" == "%" ] && [ $((i + 2)) -le "${#data}" ]; then
            hex="${data:$((i+1)):2}"
            decoded+=$(printf "\\x$hex")
            i=$((i + 3))
        else
            decoded+="$c"
            i=$((i + 1))
        fi
    done
    echo "$decoded"
}

# Generate a random port using /dev/urandom (better entropy than $RANDOM)
random_port() {
    local min=${1:-10000}
    local max=${2:-65000}
    local range=$((max - min))
    local port
    while true; do
        port=$(( $(od -An -tu2 -N2 /dev/urandom | tr -d ' ') % range + min ))
        if ! check_port_occupied "$port"; then
            echo "$port"
            return 0
        fi
    done
}

download_core() {
    if [ -f "$XRAY_BIN" ]; then return 0; fi
    echo -e "${BLUE}⬇️  Fetching Xray-core...${NC}"
    local api_url="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    local fallback_url="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    local download_url=""
    local api_response
    
    # Fetch API with rate limit detection
    local retry=0
    while [ "$retry" -lt 2 ]; do
        api_response=$(curl -s -w "\n%{http_code}" "$api_url")
        local http_code
        http_code=$(echo "$api_response" | tail -1)
        api_response=$(echo "$api_response" | head -n -1)
        
        if [ "$http_code" == "403" ] || [ "$http_code" == "429" ]; then
            if [ "$retry" -eq 0 ]; then
                echo -e "${YELLOW}⚠️  GitHub API rate limit hit, retrying in 5s...${NC}"
                sleep 5
                retry=$((retry + 1))
                continue
            fi
        fi
        break
    done
    
    if command -v jq >/dev/null 2>&1; then
        download_url=$(echo "$api_response" | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url' 2>/dev/null)
    fi
    if [ -z "$download_url" ] || [ "$download_url" == "null" ]; then
        download_url=$(echo "$api_response" | grep -o '"browser_download_url": *"[^"]*Xray-linux-64.zip"' | head -n 1 | cut -d '"' -f 4)
    fi
    
    # Fallback: use latest redirect URL (no API needed)
    if [ -z "$download_url" ]; then
        echo -e "${YELLOW}⚠️  API failed, using fallback URL...${NC}"
        download_url="$fallback_url"
    fi
    
    echo "URL: $download_url"
    mkdir -p "$XRAY_DIR"
    
    local tmp_zip
    tmp_zip=$(mktemp /tmp/xray-download.XXXXXX.zip)
    trap "rm -f '$tmp_zip'" RETURN
    
    if ! curl -L --connect-timeout 15 -o "$tmp_zip" "$download_url"; then
        # All downloads failed — prompt user to manually copy
        rm -f "$tmp_zip"
        echo -e "${RED}❌ 下载失败 (可能是网络不可达)${NC}"
        echo -e "${YELLOW}请手动下载 Xray-core 并放置到服务器:${NC}"
        echo -e "  1. 从 ${BLUE}https://github.com/XTLS/Xray-core/releases${NC} 下载 Xray-linux-64.zip"
        echo -e "  2. 上传到服务器并解压到: ${BLUE}${XRAY_DIR}${NC}"
        echo -e "  3. 确保可执行: ${BLUE}chmod +x ${XRAY_BIN}${NC}"
        echo -e "  4. 完成后重新运行安装脚本"
        return 1
    fi
    
    # SHA256 checksum verification
    local dgst_url="${download_url}.dgst"
    local expected_sha256
    expected_sha256=$(curl -sL "$dgst_url" | grep -i 'SHA256' | head -1 | awk '{print $NF}')
    if [ -n "$expected_sha256" ]; then
        local actual_sha256
        actual_sha256=$(sha256sum "$tmp_zip" | awk '{print $1}')
        if [ "$actual_sha256" != "$expected_sha256" ]; then
            echo -e "${RED}❌ SHA256 checksum mismatch!${NC}"
            echo -e "${RED}   Expected: $expected_sha256${NC}"
            echo -e "${RED}   Actual:   $actual_sha256${NC}"
            return 1
        fi
        echo -e "${GREEN}✅ SHA256 checksum verified${NC}"
    else
        echo -e "${YELLOW}⚠️  Checksum file not available, skipping verification${NC}"
    fi
    
    unzip -o "$tmp_zip" -d "$XRAY_DIR" >/dev/null
    if [ $? -ne 0 ]; then echo -e "${RED}❌ Unzip failed${NC}"; return 1; fi
    
    chmod +x "$XRAY_BIN"
    return 0
}

reinstall_core() {
    echo -e "${BLUE}🔄 Reinstalling Xray Core...${NC}"
    sys_stop 2>/dev/null
    rm -rf "$XRAY_DIR"
    if show_scroll_log "Core Download & Install" download_core; then
        sys_start
        echo -e "${GREEN}✅ Core reinstalled and service restarted.${NC}"
    else
        echo -e "${RED}❌ Reinstall failed${NC}"
    fi
}

# --- JSON Parsing Utilities ---

parse_link_to_json() {
    local link="$1"
    
    # VMess
    if [[ "$link" == vmess://* ]]; then
        local b64="${link#vmess://}"
        local json_str=$(decode_base64 "$b64")
        if [ -z "$json_str" ]; then return 1; fi
        echo "$json_str" | jq -c '{
            tag: "custom-out", protocol: "vmess",
            settings: { vnext: [{ address: .add, port: (.port | tonumber), users: [{ id: .id }] }] },
            streamSettings: { network: .net, security: .tls, wsSettings: { path: .path, headers: { Host: .host } } }
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
        
        local type=$(echo "$query" | sed -n 's/.*type=\([^&]*\).*/\1/p'); [ -z "$type" ] && type="tcp"
        type=$(url_decode "$type")
        local security=$(echo "$query" | sed -n 's/.*security=\([^&]*\).*/\1/p'); [ -z "$security" ] && security="none"
        security=$(url_decode "$security")
        local path=$(url_decode "$(echo "$query" | sed -n 's/.*path=\([^&]*\).*/\1/p')")
        local sni=$(url_decode "$(echo "$query" | sed -n 's/.*sni=\([^&]*\).*/\1/p')")
        local pbk=$(url_decode "$(echo "$query" | sed -n 's/.*pbk=\([^&]*\).*/\1/p')")
        local fp=$(url_decode "$(echo "$query" | sed -n 's/.*fp=\([^&]*\).*/\1/p')")
        local sid=$(url_decode "$(echo "$query" | sed -n 's/.*sid=\([^&]*\).*/\1/p')")
        local spx=$(url_decode "$(echo "$query" | sed -n 's/.*spx=\([^&]*\).*/\1/p')")
        local enc=$(url_decode "$(echo "$query" | sed -n 's/.*encryption=\([^&]*\).*/\1/p')"); [ -z "$enc" ] && enc="none"

        jq -n -c \
            --arg addr "$address" --arg port "$port" --arg uuid "$uuid" --arg type "$type" \
            --arg sec "$security" --arg sni "$sni" --arg path "$path" --arg pbk "$pbk" \
            --arg fp "$fp" --arg sid "$sid" --arg spx "$spx" --arg enc "$enc" \
            '{
                tag: "custom-out", protocol: "vless",
                settings: { vnext: [{ address: $addr, port: ($port | tonumber), users: [{ id: $uuid, encryption: $enc }] }] },
                streamSettings: {
                    network: $type, security: $sec,
                    (if $sec == "reality" then "realitySettings" else "tlsSettings" end): (
                        if $sec == "reality" then {show: false, fingerprint: $fp, serverName: $sni, publicKey: $pbk, shortId: $sid, spiderX: ($spx // "")} 
                        else { serverName: $sni } end
                    ),
                    ($type + "Settings"): { path: $path }
                }
            }'
        return 0
    fi
    
    # Shadowsocks
    if [[ "$link" == ss://* ]]; then
        local raw="${link#ss://}"; raw="${raw%%\#*}"; raw="${raw%%\?*}"
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
        jq -n -c --arg addr "$address" --arg port "$port" --arg m "$method" --arg p "$password" \
            '{tag: "custom-out", protocol: "shadowsocks", settings: { servers: [{ address: $addr, port: ($port | tonumber), method: $m, password: $p }] } }'
        return 0
    fi

    # SOCKS5
    if [[ "$link" == socks://* ]]; then
        local raw="${link#socks://}"; raw="${raw%%\#*}"; raw="${raw%%\?*}"
        local user=""; local pass=""; local addr_port=""
        if [[ "$raw" == *@* ]]; then
             local auth_b64="${raw%%@*}"; addr_port="${raw#*@}"
             local decoded=$(decode_base64 "$auth_b64")
             user="${decoded%%:*}"; pass="${decoded#*:}"
        else addr_port="$raw"; fi
        local address="${addr_port%%:*}"; local port="${addr_port##*:}"
        if [ -z "$address" ] || [ -z "$port" ]; then return 1; fi
        jq -n -c --arg a "$address" --arg p "$port" --arg u "$user" --arg pass "$pass" \
            '{tag: "custom-out", protocol: "socks", settings: { servers: [{ address: $a, port: ($p | tonumber), users: (if $u != "" then [{user: $u, pass: $pass}] else [] end) }] } }'
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
    jq -n -c --arg h "$host" --arg p "$port" --arg u "$user" --arg pass "$pass" \
        '{tag: "custom-out", protocol: "http", settings: { servers: [{ address: $h, port: ($p | tonumber), users: [{ user: $u, pass: $pass }] }] } }'
}

parse_interface_bind() {
    local iface="$1"; local bind_addr="$2"
    if [ -z "$iface" ]; then return 1; fi
    if [ -z "$bind_addr" ]; then bind_addr=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1); fi
    jq -n -c --arg iface "$iface" --arg addr "$bind_addr" \
    '{tag: "custom-out", protocol: "freedom", sendThrough: (if $addr != "" then $addr else null end), settings: {domainStrategy: "UseIP"}, streamSettings: {sockopt: {interface: $iface}}} | del(..|nulls)'
}

migrate_custom_config() {
    [ ! -f "$CUSTOM_OUT_FILE" ] && return
    if [ ! -s "$CUSTOM_OUT_FILE" ]; then echo "[]" > "$CUSTOM_OUT_FILE"; return; fi
    local first_char=$(jq -r 'type' "$CUSTOM_OUT_FILE" 2>/dev/null)
    if [ "$first_char" != "array" ]; then
        if [ -f "$CONF_FILE" ]; then load_config; fi
        local u_custom="${UUID_CUSTOM:-$(cat /proc/sys/kernel/random/uuid)}"
        jq -n --arg uuid "$u_custom" --slurpfile old "$CUSTOM_OUT_FILE" \
            '[{ alias: "outbound1", uuid: $uuid, config: ($old[0] | .tag="custom-out-outbound1") }]' > "$CUSTOM_OUT_FILE"
        echo -e "${GREEN}✅ Config migrated${NC}"
    fi
}
