#!/bin/bash

# ==================================================
# Xray-Proxya Core Logic
# Contains non-interactive core functions
# ==================================================

# Source Common Library
LIB_PATH="/opt/xray-proxya/lib.sh"
if [ ! -f "$LIB_PATH" ]; then
    LIB_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
fi
source "$LIB_PATH"

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

    load_config

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
            local rnd_port
            rnd_port=$(random_port 10000 65000)
            if ! check_port_occupied $rnd_port; then
                PORT_TEST=$rnd_port
                break
            fi
        done
        echo "PORT_TEST=$PORT_TEST" >> "$CONF_FILE"
    fi
    
    if [ -z "$PORT_API" ]; then
        while :; do
            local rnd_port
            rnd_port=$(random_port 10000 65000)
            if ! check_port_occupied $rnd_port && [ "$rnd_port" != "$PORT_TEST" ]; then
                PORT_API=$rnd_port
                break
            fi
        done
        echo "PORT_API=$PORT_API" >> "$CONF_FILE"
    fi

    # 自动补全 Vision Reality 密钥
    if [ -z "$VISION_PK" ] || [ -z "$VISION_SID" ]; then
        if [ -x "$XRAY_BIN" ]; then
            local raw_vision_out=$("$XRAY_BIN" x25519 2>&1)
            VISION_PK=$(echo "$raw_vision_out" | awk -F: 'tolower($0) ~ /private/ {gsub(/[ \r\t]/, "", $NF); print $NF; exit}')
            VISION_PUB=$(echo "$raw_vision_out" | awk -F: 'tolower($0) ~ /public|password/ {gsub(/[ \r\t]/, "", $NF); print $NF; exit}')
            VISION_SID=$(openssl rand -hex 4)
            {
                echo "VISION_PK=$VISION_PK"
                echo "VISION_PUB=$VISION_PUB"
                echo "VISION_SID=$VISION_SID"
                echo "VISION_SNI=${VISION_SNI:-$REALITY_SNI}"
                echo "VISION_DEST=${VISION_DEST:-$REALITY_DEST}"
            } >> "$CONF_FILE"
        fi
    fi

    # 日志参数默认值
    local enable_log="${ENABLE_LOG:-$DEFAULT_ENABLE_LOG}"
    local log_dir="${LOG_DIR:-$DEFAULT_LOG_DIR}"
    local log_file="${DEFAULT_LOG_FILE}"
    
    if [ "$enable_log" == "true" ]; then
        if [ ! -d "$log_dir" ]; then mkdir -p "$log_dir"; fi
    fi

    # Apply defaults for core variables to prevent jq errors if config is partial
    local port_vmess="${PORT_VMESS:-$DEFAULT_PORT_VMESS}"
    local path_vm="${PATH_VM:-/vmess}"
    local port_vless="${PORT_VLESS:-$DEFAULT_PORT_VLESS_KEM}"
    local path_vl="${PATH_VL:-/vless}"
    local port_reality="${PORT_REALITY:-$DEFAULT_PORT_REALITY}"
    local port_vision="${PORT_VISION:-$DEFAULT_PORT_VISION}"
    local path_reality="${PATH_REALITY:-/reality}"
    local port_ss="${PORT_SS:-$DEFAULT_PORT_SS}"
    local uuid="${UUID:-$(generate_random 36)}"  # Fallback just in case

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
        --arg port_vmess "$port_vmess" \
        --arg path_vm "$path_vm" \
        --arg port_vless "$port_vless" \
        --arg dec_key "$DEC_KEY" \
        --arg path_vl "$path_vl" \
        --arg port_reality "$port_reality" \
        --arg port_vision "$port_vision" \
        --arg reality_dest "$REALITY_DEST" \
        --arg reality_sni "$REALITY_SNI" \
        --arg reality_pk "$REALITY_PK" \
        --arg reality_sid "$REALITY_SID" \
        --arg vision_dest "$VISION_DEST" \
        --arg vision_sni "$VISION_SNI" \
        --arg vision_pk "$VISION_PK" \
        --arg vision_sid "$VISION_SID" \
        --arg path_reality "$path_reality" \
        --arg port_ss "$port_ss" \
        --arg ss_cipher "$SS_CIPHER" \
        --arg pass_ss "$PASS_SS" \
        --arg uuid "$uuid" \
        --arg port_test "$PORT_TEST" \
        --arg port_api "$PORT_API" \
        --arg dns_strategy "$dns_strategy" \
        --arg direct_outbound "${DIRECT_OUTBOUND:-true}" \
        --arg test_pass "$(generate_random 16)" \
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

    {
        "log": {
            "access": $log_path,
            "error": $log_path,
            "loglevel": $log_level
        },
        "api": {
            "tag": "api",
            "listen": ("127.0.0.1:" + $port_api),
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
        "inbounds": ([
            (if ($port_vmess | tonumber) > 0 then {
                "tag": "vmess-in",
            "port": ($port_vmess | tonumber),
            "protocol": "vmess",
            "settings": {
                "clients": (
                    (if $direct_outbound == "true" then [{ "id": $uuid, "email": "direct", "level": 0 }] else [] end)
                    + $custom_clients
                )
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": { "path": $path_vm }
            }
            } else null end),
        (if ($port_vless | tonumber) > 0 then {
            "tag": "vless-enc-in",
            "port": ($port_vless | tonumber),
            "protocol": "vless",
            "settings": {
                 "clients": (
                    (if $direct_outbound == "true" then [{ "id": $uuid, "email": "direct", "level": 0 }] else [] end)
                    + $custom_clients
                ),
                "decryption": $dec_key
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": { "path": $path_vl }
            }
            } else null end),
        (if ($port_reality | tonumber) > 0 then {
            "tag": "vless-reality-in",
            "port": ($port_reality | tonumber),
            "protocol": "vless",
            "settings": {
                 "clients": (
                    (if $direct_outbound == "true" then [{ "id": $uuid, "email": "direct", "level": 0 }] else [] end)
                    + $custom_clients
                ),
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": $reality_dest,
                    "xver": 0,
                    "serverNames": [$reality_sni],
                    "privateKey": $reality_pk,
                    "shortIds": [$reality_sid]
                },
                "xhttpSettings": { "path": $path_reality }
            }
            } else null end),
        (if ($port_vision | tonumber) > 0 then {
            "tag": "vless-vision-in",
            "port": ($port_vision | tonumber),
            "protocol": "vless",
            "settings": {
                "clients": [ { "id": $uuid, "flow": "xtls-rprx-vision" } ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": $vision_dest,
                    "xver": 0,
                    "serverNames": [ $vision_sni ],
                    "privateKey": $vision_pk,
                    "shortIds": [ $vision_sid ]
                }
            }
        } else null end),
        (if ($port_ss | tonumber) > 0 then {
            "tag": "shadowsocks-in",
            "port": ($port_ss | tonumber),
            "protocol": "shadowsocks",
            "settings": {
                "method": $ss_cipher,
                "password": $pass_ss,
                "network": "tcp,udp"
            }
            } else null end),
        {
            "tag": "test-in-socks",
            "listen": "127.0.0.1",
            "port": ($port_test | tonumber),
            "protocol": "socks",
            "settings": { 
                "auth": "password", 
                "accounts": (
                    (if $direct_outbound == "true" then [{ "user": "direct", "pass": $test_pass }] else [] end)
                    + ($custom_clients | map({ "user": .email, "pass": $test_pass }))
                ),
                "udp": true 
            }
        }
        ] | map(select(. != null))),
        "outbounds": ([
            { "protocol": "freedom", "tag": "direct", "streamSettings": { "sockopt": { "mark": 255 } } },
            { "tag": "blocked", "protocol": "blackhole" }
        ] + $custom_outbounds),
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": ([
                (if $direct_outbound == "true" then 
                    { "type": "field", "user": ["direct"], "outboundTag": "direct" } 
                 else 
                    { "type": "field", "user": ["direct"], "outboundTag": "blocked" } 
                 end)
            ] + $custom_rules + [
                { "type": "field", "inboundTag": ["test-in-socks"], "outboundTag": (if $direct_outbound == "true" then "direct" else "blocked" end) }
            ])
        }
    }' > "$JSON_FILE"
}

create_service() {
    load_config
    if [ $IS_OPENRC -eq 1 ]; then
        local log_dir="/var/log/xray-proxya"
        [ ! -d "$log_dir" ] && mkdir -p "$log_dir"
        
        if [ "$SERVICE_AUTO_RESTART" == "true" ] && command -v supervise-daemon >/dev/null 2>&1; then
            cat > "$SERVICE_FILE" <<-EOF
#!/sbin/openrc-run
name="xray-proxya"
description="Xray-Proxya Service"
supervisor="supervise-daemon"
command="$XRAY_BIN"
command_args="run -c $JSON_FILE"
pidfile="/run/xray-proxya.pid"
output_log="$log_dir/access.log"
error_log="$log_dir/error.log"
respawn_delay=5
respawn_max=0

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath -d -m 0755 -o root:root /run
    
    # 直接执行网络优化，避免在 OpenRC (sh) 中加载 Bash 库
    sysctl -w net.core.rmem_max=8388608 >/dev/null 2>&1 || true
    sysctl -w net.core.wmem_max=8388608 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
}
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
start_stop_daemon_args="--stdout $log_dir/access.log --stderr $log_dir/error.log"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath -d -m 0755 -o root:root /run

    # 直接执行网络优化，避免在 OpenRC (sh) 中加载 Bash 库
    sysctl -w net.core.rmem_max=8388608 >/dev/null 2>&1 || true
    sysctl -w net.core.wmem_max=8388608 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
}
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
ExecStartPre=-/bin/bash -c "source /opt/xray-proxya/lib.sh 2>/dev/null && optimize_network 2>/dev/null"
ExecStart=$XRAY_BIN run -c $JSON_FILE
$(echo -e "$restart_conf")
LimitNOFILE=524288
LimitNPROC=524288
[Install]
WantedBy=multi-user.target
EOF
    fi
    sys_reload_daemon
    sys_enable
    sys_restart
}

format_ip() { [[ "$1" =~ .*:.* ]] && echo "[$1]" || echo "$1"; }

print_link_group() {
    local ip=$1; local label=$2; local target_uuid=$3; local desc=$4
    if [ -z "$ip" ]; then return; fi
    if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! [[ "$ip" =~ : ]]; then
        echo -e "${YELLOW}⚠️  跳过无效 IP: $ip${NC}"
        return
    fi
    local f_ip=$(format_ip "$ip")
    
    local ps_vm=""
    local vm_l=""
    if [[ "$PORT_VMESS" != -* ]]; then
        ps_vm="VMess-WS-${VMESS_CIPHER}-${PORT_VMESS}"
        [ "$desc" == "Custom" ] && ps_vm="转发-$ps_vm"
        local vm_j=$(jq -n --arg add "$ip" --arg port "$PORT_VMESS" --arg id "$target_uuid" --arg path "$PATH_VM" --arg scy "$VMESS_CIPHER" --arg ps "$ps_vm" \
        '{v:"2", ps:$ps, add:$add, port:$port, id:$id, aid:"0", scy:$scy, net:"ws", type:"none", host:"", path:$path, tls:""}')
        vm_l="vmess://$(echo -n "$vm_j" | base64 -w 0)"
    fi
    
    local ps_vl=""
    local vl_l=""
    if [[ "$PORT_VLESS" != -* ]]; then
        ps_vl="VLess-XHTTP-KEM768-${PORT_VLESS}"
        [ "$desc" == "Custom" ] && ps_vl="转发-$ps_vl"
        vl_l="vless://$target_uuid@$f_ip:$PORT_VLESS?security=none&encryption=$ENC_KEY&type=xhttp&path=$PATH_VL&headerType=none#$ps_vl"
    fi
    
    local ps_rea=""
    local rea_l=""
    if [[ "$PORT_REALITY" != -* ]]; then
        ps_rea="VLess-XHTTP-Reality-${PORT_REALITY}"
        [ "$desc" == "Custom" ] && ps_rea="转发-$ps_rea"
        rea_l="vless://$target_uuid@$f_ip:$PORT_REALITY?security=reality&encryption=none&pbk=$REALITY_PUB&fp=chrome&type=xhttp&serviceName=&path=$PATH_REALITY&sni=$REALITY_SNI&sid=$REALITY_SID&spx=%2F#$ps_rea"
    fi
    
    local ps_vis=""
    local vis_l=""
    if [[ "$PORT_VISION" != -* ]]; then
        ps_vis="VLess-Vision-Reality-${PORT_VISION}"
        [ "$desc" == "Custom" ] && ps_vis="转发-$ps_vis"
        vis_l="vless://$target_uuid@$f_ip:$PORT_VISION?security=reality&encryption=none&pbk=$VISION_PUB&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=$VISION_SNI&sid=$VISION_SID#$ps_vis"
    fi

    local ss_l=""
    if [ "$desc" == "Direct" ] && [[ "$PORT_SS" != -* ]]; then
        local ps_ss="SS-TCPUDP-${SS_CIPHER}-${PORT_SS}"
        local ss_auth=$(echo -n "${SS_CIPHER}:$PASS_SS" | base64 -w 0)
        ss_l="ss://$ss_auth@$f_ip:$PORT_SS#$ps_ss"
    fi

    echo -e "\n${BLUE}--- $label ($ip) ---${NC}"
    [ ! -z "$vm_l" ] && echo -e "1️⃣  VMess (${VMESS_CIPHER}):\n    ${GREEN}$vm_l${NC}"
    [ ! -z "$vl_l" ] && echo -e "2️⃣  VLESS (ML-KEM768):\n    ${GREEN}$vl_l${NC}"
    [ ! -z "$rea_l" ] && echo -e "3️⃣  VLESS (Reality-XHTTP):\n    ${GREEN}$rea_l${NC}"
    [ ! -z "$vis_l" ] && echo -e "4️⃣  VLESS (Vision-Reality):\n    ${GREEN}$vis_l${NC}"
    [ ! -z "$ss_l" ] && echo -e "5️⃣  Shadowsocks (${SS_CIPHER}):\n    ${GREEN}$ss_l${NC}"
}

show_links_logic() {
    local target_uuid=$1; local desc_tag=$2
    local ipv4=$(curl -s -4 --max-time 2 https://ipconfig.me || curl -s -4 --max-time 2 https://ifconfig.co)
    local ipv6=$(curl -s -6 --max-time 2 https://ifconfig.co)
    if [ -n "$ipv4" ]; then print_link_group "$ipv4" "IPv4" "$target_uuid" "$desc_tag"; fi
    if [ -n "$ipv6" ]; then print_link_group "$ipv6" "IPv6" "$target_uuid" "$desc_tag"; fi
    if [ -z "$ipv4" ] && [ -z "$ipv6" ]; then echo -e "${RED}❌ 无法获取 IP${NC}"; fi
}

core_install_xray() {
    local PORT_VMESS=$1
    local PORT_VLESS=$2
    local PORT_REALITY=$3
    local PORT_VISION=$4
    local PORT_SS=$5

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
    
    RAW_VISION_OUT=$("$XRAY_BIN" x25519 2>&1)
    RAW_VISION_OUT=$("$XRAY_BIN" x25519 2>&1)
    VISION_PK=$(echo "$RAW_VISION_OUT" | awk -F: 'tolower($0) ~ /private/ {gsub(/[ \r\t]/, "", $NF); print $NF; exit}')
    VISION_PUB=$(echo "$RAW_VISION_OUT" | awk -F: 'tolower($0) ~ /public|password/ {gsub(/[ \r\t]/, "", $NF); print $NF; exit}')
    VISION_SID=$(openssl rand -hex 4)
    
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
PORT_VISION=$PORT_VISION
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
VISION_SID=$VISION_SID
VISION_PK=$VISION_PK
VISION_PUB=$VISION_PUB
VISION_SNI=$VISION_SNI
VISION_DEST=$VISION_DEST
ENABLE_LOG=$DEFAULT_ENABLE_LOG
LOG_DIR=$DEFAULT_LOG_DIR
AUTO_CONFIG=$AUTO_CONFIG
HIGH_PERFORMANCE_MODE=$HIGH_PERFORMANCE_MODE
MEM_LIMIT=$MEM_LIMIT
BUFFER_SIZE=$BUFFER_SIZE
CONN_IDLE=$CONN_IDLE
EOF
    chmod 600 "$CONF_FILE"
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



core_apply_ports_change() {
    local new_vm=$1
    local new_vl=$2
    local new_rea=$3
    local new_vis=$4
    local new_ss=$5
    local reset_vm=${6:-0}
    local reset_vl=${7:-0}
    local reset_rea=${8:-0}
    local reset_vis=${9:-0}
    local reset_ss=${10:-0}
    
    if [[ -n "$new_vm" ]]; then update_config_value "PORT_VMESS" "$new_vm"; fi
    if [[ -n "$new_vl" ]]; then update_config_value "PORT_VLESS" "$new_vl"; fi
    if [[ -n "$new_rea" ]]; then update_config_value "PORT_REALITY" "$new_rea"; fi
    if [[ -n "$new_vis" ]]; then update_config_value "PORT_VISION" "$new_vis"; fi
    if [[ -n "$new_ss" ]]; then update_config_value "PORT_SS" "$new_ss"; fi
    
    load_config
    
    if [ "$reset_vm" == "1" ]; then
        PATH_VM="/$(generate_random $DEFAULT_GEN_LEN)"
        update_config_value "PATH_VM" "$PATH_VM"
    fi
    if [ "$reset_vl" == "1" ]; then
        PATH_VL="/$(generate_random $DEFAULT_GEN_LEN)"
        update_config_value "PATH_VL" "$PATH_VL"
        local RAW_ENC_OUT=$("$XRAY_BIN" vlessenc 2>&1)
        RAW_ENC_OUT=$("$XRAY_BIN" vlessenc 2>&1)
        local dec_key=$(echo "$RAW_ENC_OUT" | awk -F'"' '/Authentication: ML-KEM-768/{flag=1} flag && /"decryption":/{print $4; exit}')
        local enc_key=$(echo "$RAW_ENC_OUT" | awk -F'"' '/Authentication: ML-KEM-768/{flag=1} flag && /"encryption":/{print $4; exit}')
        if [ -n "$dec_key" ]; then update_config_value "DEC_KEY" "$dec_key"; fi
        if [ -n "$enc_key" ]; then update_config_value "ENC_KEY" "$enc_key"; fi
    fi
    if [ "$reset_rea" == "1" ]; then
        PATH_REALITY="/$(generate_random $DEFAULT_GEN_LEN)"
        update_config_value "PATH_REALITY" "$PATH_REALITY"
        local new_sid=$(openssl rand -hex 4)
        update_config_value "REALITY_SID" "$new_sid"
        local RAW_REALITY_OUT=$("$XRAY_BIN" x25519 2>&1)
        RAW_REALITY_OUT=$("$XRAY_BIN" x25519 2>&1)
        local pk=$(echo "$RAW_REALITY_OUT" | awk -F: 'tolower($0) ~ /private/ {gsub(/[ \r\t]/, "", $NF); print $NF; exit}')
        local pub=$(echo "$RAW_REALITY_OUT" | awk -F: 'tolower($0) ~ /public|password/ {gsub(/[ \r\t]/, "", $NF); print $NF; exit}')
        if [ -n "$pk" ]; then update_config_value "REALITY_PK" "$pk"; fi
        if [ -n "$pub" ]; then update_config_value "REALITY_PUB" "$pub"; fi
    fi
    if [ "$reset_vis" == "1" ]; then
        local new_sid_vis=$(openssl rand -hex 4)
        update_config_value "VISION_SID" "$new_sid_vis"
        local RAW_VISION_OUT=$("$XRAY_BIN" x25519 2>&1)
        RAW_VISION_OUT=$("$XRAY_BIN" x25519 2>&1)
        local pk_v=$(echo "$RAW_VISION_OUT" | awk -F: 'tolower($0) ~ /private/ {gsub(/[ \r\t]/, "", $NF); print $NF; exit}')
        local pub_v=$(echo "$RAW_VISION_OUT" | awk -F: 'tolower($0) ~ /public|password/ {gsub(/[ \r\t]/, "", $NF); print $NF; exit}')
        if [ -n "$pk_v" ]; then update_config_value "VISION_PK" "$pk_v"; fi
        if [ -n "$pub_v" ]; then update_config_value "VISION_PUB" "$pub_v"; fi
    fi
    if [ "$reset_ss" == "1" ]; then
        PASS_SS=$(generate_random $DEFAULT_GEN_LEN)
        update_config_value "PASS_SS" "$PASS_SS"
    fi
    
    # Reload config to apply new keys for generating json
    load_config
    
    generate_config
    sys_restart
    echo -e "${GREEN}✅ 已更新并重启${NC}"
}

core_toggle_direct_listening() {
    load_config
    if [ "${DIRECT_OUTBOUND:-true}" == "true" ]; then
        DIRECT_OUTBOUND="false"
    else
        DIRECT_OUTBOUND="true"
    fi
    if grep -q "DIRECT_OUTBOUND=" "$CONF_FILE"; then
        update_config_value "DIRECT_OUTBOUND" "$DIRECT_OUTBOUND"
    else
        echo "DIRECT_OUTBOUND=$DIRECT_OUTBOUND" >> "$CONF_FILE"
    fi
    
    generate_config
    sys_restart
    echo -e "${GREEN}✅ 已切换直接出站监听状态为: $DIRECT_OUTBOUND${NC}"
    sleep 1
}

core_clear_config() {
    sys_stop 2>/dev/null
    rm -rf "$CONF_DIR"
    echo -e "${GREEN}✅ 配置已清除。如需使用请重新运行安装/重置。${NC}"
}

core_uninstall_xray() {
    echo -e "${BLUE}正在停止服务...${NC}"
    sys_stop 2>/dev/null
    sys_disable 2>/dev/null
    
    echo -e "${BLUE}正在清理文件...${NC}"
    rm -f "$SERVICE_FILE"
    rm -rf "$CONF_DIR"
    rm -rf "$XRAY_DIR"
    
    local log_d="${LOG_DIR:-$DEFAULT_LOG_DIR}"
    [ -d "$log_d" ] && rm -rf "$log_d"
    
    rm -f "/usr/local/bin/xray-proxya-maintenance"
    [ -d "/opt/xray-proxya" ] && rm -rf "/opt/xray-proxya"

    sys_reload_daemon
    
    echo -e "${GREEN}✅ 卸载完成。${NC}"
    rm -f "/opt/xray-proxya/main.sh" "/opt/xray-proxya/lib.sh" "/opt/xray-proxya/logic.sh"
}

core_apply_refresh() {
    echo -e "${BLUE}🔄 正在从脚本头部同步变量并重载服务...${NC}"
    [ -n "$AUTO_CONFIG" ] && update_config_value "AUTO_CONFIG" "$AUTO_CONFIG"
    [ -n "$HIGH_PERFORMANCE_MODE" ] && update_config_value "HIGH_PERFORMANCE_MODE" "$HIGH_PERFORMANCE_MODE"
    [ -n "$MEM_LIMIT" ] && update_config_value "MEM_LIMIT" "$MEM_LIMIT"
    [ -n "$BUFFER_SIZE" ] && update_config_value "BUFFER_SIZE" "$BUFFER_SIZE"
    [ -n "$CONN_IDLE" ] && update_config_value "CONN_IDLE" "$CONN_IDLE"
    load_config; generate_config; create_service
    echo -e "${GREEN}✅ 配置已刷新并重启${NC}"
    sleep 1
}

core_add_custom_outbound() {
    local alias="$1"
    local parsed_json="$2"
    
    local new_uuid=$("$XRAY_BIN" uuid)
    local tag_name="custom-out-$alias"
    
    local tmp=$(mktemp)
    cp "$CUSTOM_OUT_FILE" "${CUSTOM_OUT_FILE}.bak"
    
    if jq --arg alias "$alias" --arg uuid "$new_uuid" --arg tag "$tag_name" --argjson newconf "$parsed_json"        '. + [{ alias: $alias, uuid: $uuid, config: ($newconf | .tag=$tag) }]'        "$CUSTOM_OUT_FILE" > "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
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

core_delete_custom_outbound() {
    local idx=$1
    local alias=$(jq -r ".[$idx].alias" "$CUSTOM_OUT_FILE")
    local tmp=$(mktemp)
    cp "$CUSTOM_OUT_FILE" "${CUSTOM_OUT_FILE}.bak"
    if jq "del(.[$idx])" "$CUSTOM_OUT_FILE" > "$tmp" && mv "$tmp" "$CUSTOM_OUT_FILE"; then
        if apply_config_changes; then
            echo -e "${GREEN}✅ 已删除${NC}"
            rm -f "${CUSTOM_OUT_FILE}.bak"
            return 0
        else
            echo -e "${RED}❌ 配置生效失败，正在回滚...${NC}"
            mv "${CUSTOM_OUT_FILE}.bak" "$CUSTOM_OUT_FILE"
            apply_config_changes
            return 1
        fi
    else
        rm -f "${CUSTOM_OUT_FILE}.bak"
        echo -e "${RED}❌ 删除失败${NC}"
        return 1
    fi
}
