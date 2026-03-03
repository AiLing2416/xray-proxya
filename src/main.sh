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

# Source Common Library (fixed path first, then script directory for dev)
LIB_PATH="/opt/xray-proxya/lib.sh"
if [ ! -f "$LIB_PATH" ]; then
    LIB_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
fi
if [ ! -f "$LIB_PATH" ]; then echo "❌ Error: lib.sh not found."; exit 1; fi
source "$LIB_PATH"

# Source Core Logic Library
LOGIC_PATH="/opt/xray-proxya/logic.sh"
if [ ! -f "$LOGIC_PATH" ]; then
    LOGIC_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logic.sh"
fi
if [ ! -f "$LOGIC_PATH" ]; then echo "❌ Error: logic.sh not found."; exit 1; fi
source "$LOGIC_PATH"

# --- Script Specific Defaults ---
DEFAULT_GEN_LEN=16
DEFAULT_ENABLE_LOG=true
DEFAULT_LOG_DIR="/var/log/xray-proxya"
DEFAULT_LOG_FILE="xray.log"

# --- Functions ---

# (Most utility functions have been moved to lib.sh)

test_custom_outbound() {
    echo -e "\n=== 连通性测试 (SOCKS5 Auth) ==="
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装或配置文件丢失${NC}"; return; fi
    load_config
    
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
    
    local test_pass
    test_pass=$(jq -r '.inbounds[] | select(.tag=="test-in-socks") | .settings.accounts[0].pass' "$JSON_FILE" 2>/dev/null)
    [ -z "$test_pass" ] && test_pass="test"
    local start_time=$(date +%s%N)
    local http_code=$(curl -I -s -o /dev/null -w "%{http_code}" --max-time 10 --proxy-user "$target_user:$test_pass" --proxy "socks5h://127.0.0.1:$PORT_TEST" "$url")
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
        echo "1. 通过链接导入 (SS, Socks5, VMess, VLESS)"
        echo "2. 导入 HTTP 代理 (user:pass@host:port)"
        # echo "3. 导入 WireGuard (通过配置文件内容) [已废弃: 建议使用 Interface Bind]"
        echo "4. 绑定本地网络接口 (Interface Bind)"
        echo "5. 清除当前出站"
        echo "q. 返回"
        read -p "选择: " choice_sub
        
        local parsed_json=""
        case "$choice_sub" in
            1)
                echo -e "${YELLOW}支持链接: SS, Socks5, VMess, VLESS${NC}"
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
            # 3) - Removed
            4)
                echo -e "${YELLOW}请输入要绑定的本地接口名称 (例如: wg0, tun1, eth1):${NC}"
                read -p "接口名: " iface_name
                if [ -n "$iface_name" ]; then
                    echo -e "${YELLOW}请输入要绑定的本地 IP (可选, 留空则系统自动选择):${NC}"
                    echo -e "提示: WireGuard 场景建议填入在该网卡上的本地 IP (如: 10.5.0.2)"
                    read -p "绑定 IP: " local_ip
                    parsed_json=$(parse_interface_bind "$iface_name" "$local_ip")
                    [ $? -ne 0 ] && { echo -e "${RED}❌ 错误${NC}"; sleep 1; continue; }
                fi
                ;;
            5) echo -e "${RED}无效选择${NC}"; return ;;
    esac

    if [ -z "$parsed_json" ] || [ "$parsed_json" == "null" ]; then 
        echo -e "${RED}❌ 解析失败或不支持该格式${NC}"
        return
    fi
    
    core_add_custom_outbound "$alias" "$parsed_json"
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
                    core_delete_custom_outbound "$idx"
                    return
                fi
                ;;
            q|Q) return ;;
            *) echo "❌" ;;
        esac
    done
}











# --- 链接展示 ---





show_links_menu() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}❌ 未配置${NC}"; return; fi
    load_config
    
    echo -e "\n=== 链接信息 (直接出站) ==="
    show_links_logic "$UUID" "Direct"
    
    if [ -f "$CUSTOM_OUT_FILE" ] && [ -s "$CUSTOM_OUT_FILE" ] && [ "$(cat "$CUSTOM_OUT_FILE")" != "[]" ]; then
         echo -e "\n${YELLOW}提示: 自定义出站链接已移至 [5. 自定义出站] 菜单中单独管理${NC}"
    fi
    read -p "按回车继续..."
}



update_config() {
    if [ ! -f "$CONF_FILE" ]; then echo -e "${RED}未安装${NC}"; return; fi
    load_config
    
    if ! inbound_tui_selection; then
        echo -e "${RED}❌ 操作已取消或端口设定无效。${NC}"
        return 1
    fi

    local ports_to_check=()
    [[ "$PORT_VMESS" != -* ]] && ports_to_check+=("$PORT_VMESS")
    [[ "$PORT_VLESS" != -* ]] && ports_to_check+=("$PORT_VLESS")
    [[ "$PORT_REALITY" != -* ]] && ports_to_check+=("$PORT_REALITY")
    [[ "$PORT_VISION" != -* ]] && ports_to_check+=("$PORT_VISION")
    [[ "$PORT_SS" != -* ]] && ports_to_check+=("$PORT_SS")

    for p in "${ports_to_check[@]}"; do
        if check_port_occupied $p; then echo -e "${RED}⚠️ 端口 $p 被占用${NC}"; return; fi
    done
    
    core_apply_ports_change "$PORT_VMESS" "$PORT_VLESS" "$PORT_REALITY" "$PORT_VISION" "$PORT_SS" "$RESET_VMESS" "$RESET_VLESS" "$RESET_REALITY" "$RESET_VISION" "$RESET_SS"
}

clear_config() {
    echo -e "${YELLOW}⚠️  警告: 将清除所有配置 (端口、UUID、自定义出站等)${NC}"
    read -p "确认清除? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi
    core_clear_config
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
    core_toggle_direct_listening
}

maintenance_menu() {
    while true; do
        load_config 2>/dev/null
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
    echo -e "=== 安装向导 ==="
    
    if ! inbound_tui_selection; then
        echo -e "${RED}❌ 端口设定无效，退出安装。${NC}"
        return 1
    fi

    local ports_to_check=()
    [[ "$PORT_VMESS" != -* ]] && ports_to_check+=("$PORT_VMESS")
    [[ "$PORT_VLESS" != -* ]] && ports_to_check+=("$PORT_VLESS")
    [[ "$PORT_REALITY" != -* ]] && ports_to_check+=("$PORT_REALITY")
    [[ "$PORT_VISION" != -* ]] && ports_to_check+=("$PORT_VISION")
    [[ "$PORT_SS" != -* ]] && ports_to_check+=("$PORT_SS")

    for p in "${ports_to_check[@]}"; do
        if check_port_occupied $p; then echo -e "${RED}⚠️ 端口 $p 被占用${NC}"; return; fi
    done

    core_install_xray "$PORT_VMESS" "$PORT_VLESS" "$PORT_REALITY" "$PORT_VISION" "$PORT_SS"
}

apply_refresh() {
    core_apply_refresh
}



inbound_tui_selection() {
    # Test if TTY and ANSI is supported
    if [ ! -t 0 ] || [ "${TERM:-dumb}" = "dumb" ]; then
        # Fallback to normal read mode
        read -p "VMess-WS-$VMESS_CIPHER 入站端口 (默认 $DEFAULT_PORT_VMESS): " port_vm
        read -p "VLess-XHTTP-KEM768 (抗量子) 端口 (默认 $DEFAULT_PORT_VLESS_KEM): " port_vl
        read -p "VLess-XHTTP-Reality (TLS抗量子) 端口 (默认 $DEFAULT_PORT_REALITY): " port_rea
        read -p "VLess-Vision-Reality (XTLS) 端口 (默认 $DEFAULT_PORT_VISION): " port_vis
        read -p "Shadowsocks-$SS_CIPHER 端口 (默认 $DEFAULT_PORT_SS): " port_ss
        
        PORT_VMESS=$(validate_port "$port_vm" "$DEFAULT_PORT_VMESS") || return 1
        PORT_VLESS=$(validate_port "$port_vl" "$DEFAULT_PORT_VLESS_KEM") || return 1
        PORT_REALITY=$(validate_port "$port_rea" "$DEFAULT_PORT_REALITY") || return 1
        PORT_VISION=$(validate_port "$port_vis" "$DEFAULT_PORT_VISION") || return 1
        PORT_SS=$(validate_port "$port_ss" "$DEFAULT_PORT_SS") || return 1
        RESET_VMESS=0; RESET_VLESS=0; RESET_REALITY=0; RESET_VISION=0; RESET_SS=0
        return 0
    fi

    local labels=("VMess-WS-$VMESS_CIPHER" "VLess-XHTTP-KEM768" "VLess-XHTTP-Reality" "VLess-Vision-Reality" "SS-AES256GCM")
    local enabled=(1 1 1 1 1)
    local reset_flags=(0 0 0 0 0)
    local ports=("${PORT_VMESS:-$DEFAULT_PORT_VMESS}" "${PORT_VLESS:-$DEFAULT_PORT_VLESS_KEM}" "${PORT_REALITY:-$DEFAULT_PORT_REALITY}" "${PORT_VISION:-$DEFAULT_PORT_VISION}" "${PORT_SS:-$DEFAULT_PORT_SS}")
    
    if [[ "${PORT_VMESS}" == -* ]]; then enabled[0]=0; ports[0]="${PORT_VMESS#-}"; fi
    if [[ "${ports[0]}" == "1" ]]; then ports[0]="$DEFAULT_PORT_VMESS"; fi
    
    if [[ "${PORT_VLESS}" == -* ]]; then enabled[1]=0; ports[1]="${PORT_VLESS#-}"; fi
    if [[ "${ports[1]}" == "1" ]]; then ports[1]="$DEFAULT_PORT_VLESS_KEM"; fi
    
    if [[ "${PORT_REALITY}" == -* ]]; then enabled[2]=0; ports[2]="${PORT_REALITY#-}"; fi
    if [[ "${ports[2]}" == "1" ]]; then ports[2]="$DEFAULT_PORT_REALITY"; fi
    
    if [[ "${PORT_VISION}" == -* ]]; then enabled[3]=0; ports[3]="${PORT_VISION#-}"; fi
    if [[ "${ports[3]}" == "1" ]]; then ports[3]="$DEFAULT_PORT_VISION"; fi
    
    if [[ "${PORT_SS}" == -* ]]; then enabled[4]=0; ports[4]="${PORT_SS#-}"; fi
    if [[ "${ports[4]}" == "1" ]]; then ports[4]="$DEFAULT_PORT_SS"; fi

    local current_row=0
    local num_rows=${#labels[@]}
    
    tput civis
    stty -echo -icanon
    local old_trap=$(trap -p INT)
    trap 'tput cnorm; stty sane; echo ""; exit 1' INT TERM

    echo -e "${BLUE}=== 入站端口与协议配置 ===${NC}"
    echo -e "导航: [${YELLOW}↑/↓${NC}] | 启用/禁用: [${YELLOW}+/-${NC}] | 重置标签: [${YELLOW}R${NC}] | 修改端口: [${YELLOW}数字${NC}] | 清空: [${YELLOW}Delete${NC}] | 确认: [${YELLOW}回车${NC}]"
    echo ""
    for i in "${!labels[@]}"; do echo ""; done

    render() {
        tput cuu $num_rows
        for i in "${!labels[@]}"; do
            local mark="-"
            if [ "${enabled[$i]}" -eq 1 ]; then mark="+"; fi
            local r_mark=""
            if [ "${reset_flags[$i]}" -eq 1 ]; then r_mark=" R"; fi
            local p_str="${ports[$i]}"
            local label="${labels[$i]}"
            if [ "$i" -eq "$current_row" ]; then
                printf "\r\033[K\033[7m %s %-30s [%-5s]%s \033[0m\n" "$mark" "$label" "$p_str" "$r_mark"
            else
                printf "\r\033[K %s %-30s [%-5s]%s \n" "$mark" "$label" "$p_str" "$r_mark"
            fi
        done
    }

    render

    while true; do
        IFS= read -rsn1 key
        if [[ $key == $'\x1b' ]]; then
            read -rsn2 -t 0.1 key2
            if [[ $key2 == "[A" ]]; then
                ((current_row--))
                [ $current_row -lt 0 ] && current_row=0
                render
            elif [[ $key2 == "[B" ]]; then
                ((current_row++))
                [ $current_row -ge $num_rows ] && current_row=$((num_rows - 1))
                render
            elif [[ $key2 == "[3" ]]; then
                read -rsn1 -t 0.1 tilde
                if [ "$tilde" == "~" ]; then
                    ports[$current_row]=""
                    render
                fi
            fi
        elif [[ $key == "+" ]]; then
            enabled[$current_row]=1
            render
        elif [[ $key == "-" ]]; then
            enabled[$current_row]=0
            render
        elif [[ $key == "r" || $key == "R" ]]; then
            if [ "${reset_flags[$current_row]}" -eq 1 ]; then reset_flags[$current_row]=0; else reset_flags[$current_row]=1; fi
            render
        elif [[ $key == $'\x7f' || $key == $'\b' ]]; then
            local p="${ports[$current_row]}"
            ports[$current_row]="${p%?}"
            render
        elif [[ -z "$key" ]]; then
            break
        elif [[ "$key" =~ ^[0-9]$ ]]; then
            local p="${ports[$current_row]}"
            if [ "${#p}" -lt 5 ]; then ports[$current_row]="${p}${key}"; fi
            render
        fi
    done

    stty sane
    tput cnorm
    eval "$old_trap"
    echo ""

    local p_vm p_vl p_rea p_vis p_ss
    p_vm=$(validate_port "${ports[0]}" "$DEFAULT_PORT_VMESS") || return 1
    p_vl=$(validate_port "${ports[1]}" "$DEFAULT_PORT_VLESS_KEM") || return 1
    p_rea=$(validate_port "${ports[2]}" "$DEFAULT_PORT_REALITY") || return 1
    p_vis=$(validate_port "${ports[3]}" "$DEFAULT_PORT_VISION") || return 1
    p_ss=$(validate_port "${ports[4]}" "$DEFAULT_PORT_SS") || return 1
    
    if [ "${enabled[0]}" -eq 1 ]; then PORT_VMESS="$p_vm"; else PORT_VMESS="-$p_vm"; fi
    if [ "${enabled[1]}" -eq 1 ]; then PORT_VLESS="$p_vl"; else PORT_VLESS="-$p_vl"; fi
    if [ "${enabled[2]}" -eq 1 ]; then PORT_REALITY="$p_rea"; else PORT_REALITY="-$p_rea"; fi
    if [ "${enabled[3]}" -eq 1 ]; then PORT_VISION="$p_vis"; else PORT_VISION="-$p_vis"; fi
    if [ "${enabled[4]}" -eq 1 ]; then PORT_SS="$p_ss"; else PORT_SS="-$p_ss"; fi
    
    RESET_VMESS=${reset_flags[0]}
    RESET_VLESS=${reset_flags[1]}
    RESET_REALITY=${reset_flags[2]}
    RESET_VISION=${reset_flags[3]}
    RESET_SS=${reset_flags[4]}

    return 0
}
install_xray() {
    
    if ! inbound_tui_selection; then
        echo -e "${RED}❌ 端口设定无效，退出安装。${NC}"
        return 1
    fi

    local ports_to_check=()
    [[ "$PORT_VMESS" != -* ]] && ports_to_check+=("$PORT_VMESS")
    [[ "$PORT_VLESS" != -* ]] && ports_to_check+=("$PORT_VLESS")
    [[ "$PORT_REALITY" != -* ]] && ports_to_check+=("$PORT_REALITY")
    [[ "$PORT_VISION" != -* ]] && ports_to_check+=("$PORT_VISION")
    [[ "$PORT_SS" != -* ]] && ports_to_check+=("$PORT_SS")

    for p in "${ports_to_check[@]}"; do
        if check_port_occupied $p; then echo -e "${RED}⚠️ 端口 $p 被占用${NC}"; return; fi
    done

    core_install_xray "$PORT_VMESS" "$PORT_VLESS" "$PORT_REALITY" "$PORT_VISION" "$PORT_SS"
}

cli_inbound() {
    local proto="$1"
    if [ -n "$1" ]; then shift; fi
    if [ -z "$proto" ] || [[ "$proto" =~ ^(help|--help|-h)$ ]]; then
        echo "用法: xray-proxya inbound <vmess|vless|reality|vision|ss> [选项]"
        echo "选项:"
        echo "  --port <num>   修改该入站的监听端口"
        echo "  --up           启用该入站"
        echo "  --down         禁用并挂起该入站"
        echo "  --reset        重置该入站的配置 (密钥/密码/路径等)"
        exit 0
    fi
    
    local opt_port=""
    local opt_state=""
    local opt_reset=0
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port) opt_port="$2"; shift 2 ;;
            --up) opt_state="up"; shift 1 ;;
            --down) opt_state="down"; shift 1 ;;
            --reset) opt_reset=1; shift 1 ;;
            *) echo "Unknown option: $1"; exit 1 ;;
        esac
    done
    
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}未安装或缺少配置文件，请先运行安装。${NC}"
        exit 1
    fi
    load_config
    
    local p_vm="${PORT_VMESS:-$DEFAULT_PORT_VMESS}"
    local p_vl="${PORT_VLESS:-$DEFAULT_PORT_VLESS_KEM}"
    local p_rea="${PORT_REALITY:-$DEFAULT_PORT_REALITY}"
    local p_vis="${PORT_VISION:-$DEFAULT_PORT_VISION}"
    local p_ss="${PORT_SS:-$DEFAULT_PORT_SS}"
    
    local r_vm=0 r_vl=0 r_rea=0 r_vis=0 r_ss=0

    get_abs_port() {
        local val="$1"
        if [[ "$val" == -* ]]; then echo "${val#-}"; else echo "$val"; fi
    }
    
    is_enabled() {
        local val="$1"
        if [[ "$val" == -* ]]; then return 1; else return 0; fi
    }
    
    local target_port=""
    local target_enabled=0
    
    case "$proto" in
        vmess) target_port="$(get_abs_port "$p_vm")"; if is_enabled "$p_vm"; then target_enabled=1; fi ;;
        vless) target_port="$(get_abs_port "$p_vl")"; if is_enabled "$p_vl"; then target_enabled=1; fi ;;
        reality) target_port="$(get_abs_port "$p_rea")"; if is_enabled "$p_rea"; then target_enabled=1; fi ;;
        vision) target_port="$(get_abs_port "$p_vis")"; if is_enabled "$p_vis"; then target_enabled=1; fi ;;
        ss) target_port="$(get_abs_port "$p_ss")"; if is_enabled "$p_ss"; then target_enabled=1; fi ;;
        *) echo "Error: Unknown protocol '$proto'. Options: vmess, vless, reality, vision, ss"; exit 1 ;;
    esac
    
    if [ -n "$opt_port" ]; then
        target_port=$(validate_port "$opt_port" "$target_port") || exit 1
    fi
    
    if [ "$opt_state" == "up" ]; then
        target_enabled=1
    elif [ "$opt_state" == "down" ]; then
        target_enabled=0
    fi
    
    local final_port="$target_port"
    if [ "$target_enabled" -eq 0 ]; then
        final_port="-$target_port"
    fi
    
    case "$proto" in
        vmess) p_vm="$final_port"; r_vm=$opt_reset ;;
        vless) p_vl="$final_port"; r_vl=$opt_reset ;;
        reality) p_rea="$final_port"; r_rea=$opt_reset ;;
        vision) p_vis="$final_port"; r_vis=$opt_reset ;;
        ss) p_ss="$final_port"; r_ss=$opt_reset ;;
    esac
    
    local ports_to_check=()
    [[ "$p_vm" != -* ]] && ports_to_check+=("$p_vm")
    [[ "$p_vl" != -* ]] && ports_to_check+=("$p_vl")
    [[ "$p_rea" != -* ]] && ports_to_check+=("$p_rea")
    [[ "$p_vis" != -* ]] && ports_to_check+=("$p_vis")
    [[ "$p_ss" != -* ]] && ports_to_check+=("$p_ss")

    for p in "${ports_to_check[@]}"; do
        if check_port_occupied "$p"; then echo -e "${RED}⚠️ 端口 $p 被占用${NC}"; exit 1; fi
    done
    
    core_apply_ports_change "$p_vm" "$p_vl" "$p_rea" "$p_vis" "$p_ss" "$r_vm" "$r_vl" "$r_rea" "$r_vis" "$r_ss"
}

cli_help() {
    echo -e "${BLUE}Xray-Proxya CLI 管理工具${NC}"
    echo "用法: xray-proxya <command> [options]"
    echo ""
    echo "可用命令 (Commands):"
    echo "  inbound    管理入站监听 (启用/禁用/修改端口/重置)"
    echo "  help       显示此帮助信息"
    echo ""
    echo "执行 xray-proxya <command> --help 查看特定命令的参数列表"
}

cli_main() {
    local cmd="$1"
    shift
    case "$cmd" in
        inbound) cli_inbound "$@" ;;
        help|-h|--help) cli_help ;;
        *)
            echo -e "${RED}未知命令: $cmd${NC}\n"
            cli_help
            exit 1
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_root
    
    if [ $# -gt 0 ]; then
        # CLI Mode
        cli_main "$@"
        exit 0
    fi
    
    if [ -f "$CONF_FILE" ]; then
        load_config
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
        echo "3. 更新配置"
        echo "4. 维护菜单"
        echo "5. 自定义出站"
        echo "6. 测试自定义出站"
        echo ""
        echo "7. 刷新配置"
        echo "8. 重装内核"
        echo "9. 卸载"
        echo "q. 退出"
        read -p "选择: " choice
        case "$choice" in
            1) install_xray ;;
            2) show_links_menu ;;
            3) update_config ;;
            4) maintenance_menu ;;
            5) custom_outbound_menu ;;
            6) test_custom_outbound ;;
            7) apply_refresh ;;
            8) reinstall_core ;;
            9) uninstall_xray ;;
            q|Q) exit 0 ;;
            *) echo -e "${RED}无效${NC}" ;;
        esac
    done
fi
