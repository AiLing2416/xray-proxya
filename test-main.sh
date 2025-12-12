#!/bin/bash

# ==================================================
# Xray-Proxya Manager [TEST]
# Supports: Debian/Ubuntu & Alpine (OpenRC)
# ==================================================

# --- 默认配置变量 ---
DEFAULT_PORT_VMESS=8081
DEFAULT_PORT_VLESS_KEM=8082
DEFAULT_PORT_REALITY=8443
DEFAULT_PORT_SS=8083
DEFAULT_GEN_LEN=16

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
if [ -f /etc/alpine-release ]; then
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
        apk add curl jq openssl bash coreutils gcompat iproute2 grep libgcc libstdc++ sed gawk unzip dialog ncurses
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
    # Pre-allocate 5 lines for scrolling area
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
    # WireGuard 协议 (自定义格式)
    # wireguard://<Priv>@<EndpointIP>:<EndpointPort>?publickey=<Pub>&address=<LocalIP/Mask>&mtu=<MTU>
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
        local mtu=$(echo "$query" | sed -n 's/.*mtu=\([^&#]*\).*/\1/p')
        [ -z "$mtu" ] && mtu=1280
        
        local priv_key=$(url_decode "$priv_enc")
        local pub_key=$(url_decode "$pub_enc")
        local local_addr=$(url_decode "$addr_enc")

        if [ -z "$pub_key" ] || [ -z "$priv_key" ] || [ -z "$end_addr" ]; then return 1; fi

        jq -n -c \
            --arg pub "$pub_key" \
            --arg priv "$priv_key" \
            --arg addr "$end_addr" \
            --arg port "$end_port" \
            --arg local "$local_addr" \
            --arg mtu "$mtu" \
            '{
                tag: "custom-out",
                protocol: "wireguard",
                settings: {
                    secretKey: $priv,
                    address: [$local],
                    peers: [{
                        publicKey: $pub,
                        endpoint: ($addr + ":" + $port),
                        keepAlive: 25
                    }],
                    mtu: ($mtu | tonumber)
                }
            }'
        return 0
    fi

    # SOCKS5 (socks://user:pass@host:port#tag)
    if [[ "$link" == socks://* ]]; then
        local raw="${link#socks://}"
        raw="${raw%%\#*}" # Strip tag
        
        local user=""
        local pass=""
        local addr_port=""
        
        if [[ "$raw" == *@* ]]; then
             # Has auth
             local auth_b64="${raw%%@*}"
             addr_port="${raw#*@}"
             
             # Decode auth
             local decoded=$(decode_base64 "$auth_b64")
             if [[ "$decoded" == *:* ]]; then
                 user="${decoded%%:*}"
                 pass="${decoded#*:}"
             fi
        else
             # No auth
             addr_port="$raw"
        fi
        
        local address="${addr_port%%:*}"
        local port="${addr_port##*:}"
        
        if [ -z "$address" ] || [ -z "$port" ]; then return 1; fi
        
        # Build JSON using jq
        # Logic: If user/pass exist, include them in users array
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

test_custom_outbound() {
    echo -e "\n=== 测试自定义出站连通性 ==="
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装或配置文件丢失${NC}"; return; fi
    source "$CONF_FILE"
    
    if [ -z "$PORT_TEST" ]; then
        echo -e "${YELLOW}⚠️  未找到测试端口配置，正在修复...${NC}"
        generate_config
        source "$CONF_FILE"
    fi
    
    # 检查是否有自定义配置
    if [ ! -f "$CUSTOM_OUT_FILE" ] || [ ! -s "$CUSTOM_OUT_FILE" ] || [ "$(cat "$CUSTOM_OUT_FILE")" == "[]" ]; then
         echo -e "${RED}❌ 未配置自定义出站节点。请先添加节点 (选项 5)${NC}"
         return
    fi
    
    echo -e "正在通过本地测试端口 ($PORT_TEST) 连接 Google..."
    echo -e "${BLUE}Cmd: curl -I --proxy socks5h://127.0.0.1:$PORT_TEST https://www.google.com${NC}"
    
    # 使用 curl 测试，超时时间 10秒
    if curl -I -s --max-time 10 --proxy "socks5h://127.0.0.1:$PORT_TEST" "https://www.google.com" | grep -q "HTTP/"; then
        echo -e "${GREEN}✅ 连通性测试通过! (能够访问 Google)${NC}"
    else
        echo -e "${RED}❌ 连接失败或超时。${NC}"
        echo -e "建议检查: 节点有效性 / 系统时间 / DNS (虽然socks5h由远程解析)"
    fi
    read -p "按回车继续..."
}

add_custom_outbound() {
    echo -e "\n=== 添加自定义出站 (流量转发) ==="
    echo -e "${YELLOW}支持链接: VMess(ws), VLESS(tcp/xhttp), Shadowsocks, WireGuard, SOCKS5${NC}"
    read -p "请粘贴链接: " link_str
    if [ -z "$link_str" ]; then echo -e "${RED}输入为空${NC}"; return; fi
    PARSED_JSON=$(parse_link_to_json "$link_str")
    if [ $? -ne 0 ] || [ -z "$PARSED_JSON" ]; then echo -e "${RED}❌ 解析失败或不支持该格式${NC}"; return; fi
    echo "$PARSED_JSON" > "$CUSTOM_OUT_FILE"
    echo -e "${GREEN}✅ 解析成功${NC}"
    
    source "$CONF_FILE"
    if [ -z "$UUID_CUSTOM" ]; then
        UUID_CUSTOM=$("$XRAY_BIN" uuid)
        echo "UUID_CUSTOM=$UUID_CUSTOM" >> "$CONF_FILE"
    fi
    source "$CONF_FILE"
    generate_config
    sleep 0.5
    sys_restart
    echo -e "${GREEN}服务已重启，转发规则已生效${NC}"
}

generate_config() {
    source "$CONF_FILE"

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

    local u_custom="${UUID_CUSTOM:-}"
    
    local co_args=()
    if [ -f "$CUSTOM_OUT_FILE" ] && [ -s "$CUSTOM_OUT_FILE" ]; then
         co_args=("--slurpfile" "custom_outbound" "$CUSTOM_OUT_FILE")
    else
         co_args=("--argjson" "custom_outbound" "[]")
    fi

    jq -n \
        "${co_args[@]}" \
        --arg log_level "warning" \
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
        --arg uuid_custom "$u_custom" \
        --arg port_test "$PORT_TEST" \
    '
    {
        log: { loglevel: $log_level },
        inbounds: [
            {
                tag: "vmess-in",
                port: ($port_vmess | tonumber),
                protocol: "vmess",
                settings: {
                    clients: ([
                        { id: $uuid, email: "direct", level: 0 }
                    ] + (if $uuid_custom != "" and ($custom_outbound | length > 0) then [{ id: $uuid_custom, email: "custom", level: 0 }] else [] end))
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
                    ] + (if $uuid_custom != "" and ($custom_outbound | length > 0) then [{ id: $uuid_custom, email: "custom", level: 0 }] else [] end)),
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
                    ] + (if $uuid_custom != "" and ($custom_outbound | length > 0) then [{ id: $uuid_custom, email: "custom", level: 0 }] else [] end)),
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
                settings: { auth: "noauth", udp: true }
            }
        ],
        outbounds: ([
            { tag: "direct", protocol: "freedom" },
            { tag: "blocked", protocol: "blackhole" }
        ] + ($custom_outbound | flatten(1))),
        routing: {
            rules: [
                { type: "field", user: ["direct"], outboundTag: "direct" },
                { type: "field", user: ["custom"], outboundTag: "custom-out" },
                { type: "field", inboundTag: ["test-in-socks"], outboundTag: "custom-out" }
            ]
        }
    }' > "$JSON_FILE"
}

create_service() {
    if [ $IS_OPENRC -eq 1 ]; then
        cat > "$SERVICE_FILE" <<-EOF
#!/sbin/openrc-run
name="xray-proxya"
description="Xray-Proxya Service"
command="$XRAY_BIN"
command_args="run -c $JSON_FILE"
command_background=true
pidfile="/run/xray-proxya.pid"
depend() {
    need net
    after firewall
}
EOF
        chmod +x "$SERVICE_FILE"
    else
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
Restart=on-failure
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
    
    # 核心下载与检查
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
    
    # === 解析逻辑 ===
    
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
EOF
    generate_config
    
    if ! "$XRAY_BIN" run -test -c "$JSON_FILE" >/dev/null 2>&1; then
        echo -e "${RED}❌ 配置文件验证失败!${NC}"
        "$XRAY_BIN" run -test -c "$JSON_FILE"
        return 1
    fi

    create_service
    echo -e "${GREEN}✅ 安装完成${NC}"
    
    echo -e "\n=== 链接信息 ==="
    show_links_logic "$UUID" "Direct"
}

# --- 链接展示 ---

format_ip() { [[ "$1" =~ .*:.* ]] && echo "[$1]" || echo "$1"; }

print_link_group() {
    local ip=$1; local label=$2; local target_uuid=$3; local desc=$4
    if [ -z "$ip" ]; then return; fi
    # 验证 IP 地址格式 (简单的 IPv4/IPv6 正则)
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
    if [ ! -f "$CUSTOM_OUT_FILE" ]; then
        echo -e "\n=== 链接信息 (直接出站) ==="
        show_links_logic "$UUID" "Direct"
        return
    fi

    # 检查是否有有效的自定义配置
    local has_custom=0
    if [ -f "$CUSTOM_OUT_FILE" ]; then
        if [ -s "$CUSTOM_OUT_FILE" ] && [ "$(cat "$CUSTOM_OUT_FILE")" != "[]" ]; then
            has_custom=1
        fi
    fi
    
    # 如果没有自定义出站配置，直接显示直连，不进入菜单
    if [ $has_custom -eq 0 ]; then
        echo -e "\n=== 链接信息 (直接出站) ==="
        show_links_logic "$UUID" "Direct"
        return
    fi

    echo -e "\n=== 选择要查看的链接类型 ==="
    echo "1. 直接出站 (本机 IP)"
    echo "2. 自定义出站 (转发流量)"
    echo ""
    echo "q. 返回"
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

maintenance_menu() {
    while true; do
        echo -e "\n=== 维护 ==="
        echo "1. 启动"
        echo "2. 停止"
        echo "3. 重启"
        echo "4. 开机自启"
        echo "5. 取消自启"
        echo ""
        echo "q. 返回"
        read -p "选择: " m_choice
        case "$m_choice" in
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

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_root
    while true; do
        echo -e "\n${BLUE}Xray-Proxya 管理${NC}"
        check_status
        echo "1. 安装 / 重置"
        echo "2. 查看链接"
        echo "3. 修改端口"
        echo "4. 维护菜单"
        echo "5. 自定义出站"
        echo "6. 测试出站连通性"
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
            5) add_custom_outbound ;;
            6) test_custom_outbound ;;
            9) reinstall_core ;;
            0) uninstall_xray ;;
            q|Q) exit 0 ;;
            *) echo -e "${RED}无效${NC}" ;;
        esac
    done
fi
