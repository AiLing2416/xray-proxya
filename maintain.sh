#!/bin/bash

# ==================================================
# Xray-Proxya 自动化维护脚本
# 用于 Crontab 定时任务调用
# ==================================================

set -e

# 配置路径
CONF_DIR="/etc/xray-proxya"
CONF_FILE="$CONF_DIR/config.env"
SCRIPT_DIR="/opt/xray-proxya"
MAIN_LIB="$SCRIPT_DIR/main_lib.sh"

# 检测系统类型
IS_OPENRC=0
if command -v rc-service &>/dev/null; then
    IS_OPENRC=1
fi

# 服务重启函数
restart_service() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始重启 xray-proxya 服务..."
    
    if [ $IS_OPENRC -eq 1 ]; then
        if rc-service xray-proxya restart 2>/dev/null; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ 服务重启成功 (OpenRC)"
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ 服务重启失败 (OpenRC)" >&2
            exit 1
        fi
    else
        if systemctl restart xray-proxya 2>/dev/null; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ 服务重启成功 (systemd)"
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ 服务重启失败 (systemd)" >&2
            exit 1
        fi
    fi
}

# 日志清理函数
clean_logs() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始清理日志..."
    
    # 从配置文件读取日志目录
    local log_dir="/var/log/xray-proxya"  # 默认值
    
    if [ -f "$CONF_FILE" ]; then
        source "$CONF_FILE"
        log_dir="${LOG_DIR:-/var/log/xray-proxya}"
    fi
    
    if [ ! -d "$log_dir" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⚠️  日志目录不存在: $log_dir"
        return 0
    fi
    
    # 删除 .log 文件
    local log_count=$(find "$log_dir" -name "*.log" -type f 2>/dev/null | wc -l)
    
    if [ "$log_count" -gt 0 ]; then
        rm -f "$log_dir"/*.log
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ 已清理 $log_count 个日志文件 (目录: $log_dir)"
        
        # 重启服务以重新创建日志文件
        restart_service
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 📝 没有需要清理的日志文件"
    fi
}

# 内核更新函数
update_core() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始更新 Xray 核心..."
    
    # 检查 main_lib.sh 是否存在
    if [ ! -f "$MAIN_LIB" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ 找不到 main_lib.sh: $MAIN_LIB" >&2
        exit 1
    fi
    
    # 加载库文件
    source "$MAIN_LIB"
    
    # 调用下载核心函数
    if download_core; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ 核心更新成功"
        
        # 重启服务以应用新核心
        restart_service
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ 核心更新失败" >&2
        exit 1
    fi
}

# 显示使用说明
show_usage() {
    cat <<EOF
用法: $0 <action>

可用操作:
  restart      - 重启 xray-proxya 服务
  clean-logs   - 清理日志文件
  update-core  - 更新 Xray 核心

示例:
  $0 restart
  $0 clean-logs
  $0 update-core
EOF
}

# 主逻辑
case "${1:-}" in
    restart)
        restart_service
        ;;
    clean-logs)
        clean_logs
        ;;
    update-core)
        update_core
        ;;
    *)
        echo "❌ 错误: 无效的操作参数" >&2
        echo ""
        show_usage
        exit 1
        ;;
esac

exit 0
