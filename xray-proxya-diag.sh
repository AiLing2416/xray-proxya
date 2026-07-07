#!/usr/bin/env bash
# xray-proxya-diag.sh - Diagnostic script for xray-proxya
# Safe for rootless execution, handles root-only metrics gracefully.
# Automatically redacts all user critical node details (public IPs, domains, keys, tokens, paths).

set -o pipefail
set -u

# --- Configurations ---
DIAG_VERSION="1.1.0"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(hostname)
USER_NAME=$(whoami)
UID_VAL=$(id -u)

# Define output file and raw temporary file
OUT_FILE="/tmp/xray-proxya-diag-${USER_NAME}-${TIMESTAMP//:/-}.txt"
RAW_FILE="/tmp/xray-proxya-diag-raw-${USER_NAME}-${$}.tmp"

# Initialize raw temp file
echo -n "" > "$RAW_FILE"
chmod 600 "$RAW_FILE"

# Helper to write to raw temp file (post-processed at the end)
log_stdout_and_file() {
    echo -e "$@" >> "$RAW_FILE"
}

log_stdout_and_file "================================================================="
log_stdout_and_file "  Xray-Proxya Diagnostic Report v${DIAG_VERSION} - ${TIMESTAMP}"
log_stdout_and_file "  Host: ${HOSTNAME} | User: ${USER_NAME} (UID: ${UID_VAL})"
log_stdout_and_file "  Output Saved To: ${OUT_FILE}"
log_stdout_and_file "================================================================="

# Helper to print section header
print_header() {
    log_stdout_and_file ""
    log_stdout_and_file "-----------------------------------------------------------------"
    log_stdout_and_file ">>> $1"
    log_stdout_and_file "-----------------------------------------------------------------"
}

# 1. Environment & OS
print_header "1. System & OS Information"
log_stdout_and_file "Kernel: $(uname -a)"
if [ -f /etc/os-release ]; then
    os_info=$(grep -E '^(NAME|VERSION|PRETTY_NAME)=' /etc/os-release | sed 's/"//g')
    log_stdout_and_file "OS Info:\n$os_info"
else
    log_stdout_and_file "OS Info: /etc/os-release not found"
fi
log_stdout_and_file "Uptime: $(uptime)"
log_stdout_and_file "Memory Status:"
log_stdout_and_file "$(free -h 2>/dev/null || echo 'free command failed')"
log_stdout_and_file "Disk Status (/):"
log_stdout_and_file "$(df -h / 2>/dev/null || echo 'df command failed')"
log_stdout_and_file "CPU Model:"
cpu_info=$(lscpu | grep "Model name" || cat /proc/cpuinfo | grep "model name" | head -n 1)
log_stdout_and_file "${cpu_info:-Unknown CPU}"
log_stdout_and_file "Architecture: $(uname -m)"

# 2. Find xray-proxya Binary & Version
print_header "2. Xray-Proxya Binary"
BINARY_PATH=""
# Candidates for binary path
CANDIDATES=(
    "$HOME/.local/bin/xray-proxya"
    "/root/.local/bin/xray-proxya"
    "./xray-proxya"
    "xray-proxya"
)

for cand in "${CANDIDATES[@]}"; do
    if command -v "$cand" >/dev/null 2>&1; then
        BINARY_PATH=$(command -v "$cand")
        break
    fi
done

if [ -n "$BINARY_PATH" ]; then
    log_stdout_and_file "Binary found at: $BINARY_PATH"
    log_stdout_and_file "Version info:"
    ver_out=$("$BINARY_PATH" version 2>&1)
    log_stdout_and_file "$ver_out"
else
    log_stdout_and_file "xray-proxya binary not found in expected paths or PATH!"
fi

# 3. Running Status & Services
print_header "3. Service & Process Status"
if [ -n "$BINARY_PATH" ]; then
    log_stdout_and_file "xray-proxya status output:"
    status_out=$("$BINARY_PATH" status 2>&1)
    log_stdout_and_file "$status_out"
fi

log_stdout_and_file "\nSystemd service status:"
if [ "$UID_VAL" -eq 0 ]; then
    sysd_out=$(systemctl status xray-proxya --no-pager 2>&1)
    log_stdout_and_file "$sysd_out"
else
    sysd_out=$(systemctl --user status xray-proxya --no-pager 2>&1)
    log_stdout_and_file "$sysd_out"
fi

log_stdout_and_file "\nProcess list (xray-proxya / xray):"
proc_out=$(ps aux | grep -E 'xray-proxya|xray' | grep -v grep)
if [ -n "$proc_out" ]; then
    log_stdout_and_file "$proc_out"
else
    log_stdout_and_file "No running xray-proxya/xray processes found."
fi

# 4. Configuration Files
print_header "4. Configuration Files"
CONFIG_DIR=""
if [ -n "${XRAY_PROXYA_CONFIG_DIR:-}" ]; then
    CONFIG_DIR="$XRAY_PROXYA_CONFIG_DIR"
else
    CONFIG_DIR="$HOME/.config/xray-proxya"
fi

log_stdout_and_file "Config Directory: $CONFIG_DIR"

if [ -d "$CONFIG_DIR" ]; then
    for f in "$CONFIG_DIR"/config*.json; do
        if [ -f "$f" ]; then
            log_stdout_and_file "--- File: $(basename "$f") ---"
            log_stdout_and_file "$(cat "$f")"
            log_stdout_and_file ""
        fi
    done
else
    log_stdout_and_file "Config directory does not exist."
fi

# 5. Kernel Tune State
print_header "5. Kernel Tune State"
if [ -n "$BINARY_PATH" ]; then
    tune_out=$("$BINARY_PATH" tune show 2>&1)
    log_stdout_and_file "$tune_out"
else
    log_stdout_and_file "Cannot retrieve tune show: xray-proxya binary not found."
fi

# 6. Network Information
print_header "6. Network Interfaces & IP Configuration"
net_addr=$(ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "ip/ifconfig not available")
log_stdout_and_file "$net_addr"

print_header "7. Routing Tables & Rules"
log_stdout_and_file "Routing table (default/main):"
net_route=$(ip route show 2>/dev/null || route -n 2>/dev/null || echo "ip route show not available")
log_stdout_and_file "$net_route"

log_stdout_and_file "\nIP Rules (Routing Policy):"
net_rules=$(ip rule show 2>/dev/null || echo "ip rule show not available")
log_stdout_and_file "$net_rules"

log_stdout_and_file "\nCustom routing tables (if any):"
has_custom_table=false
for t in 100 1000; do
    if ip route show table "$t" >/dev/null 2>&1; then
        t_route=$(ip route show table "$t")
        if [ -n "$t_route" ]; then
            log_stdout_and_file "--- Table $t ---"
            log_stdout_and_file "$t_route"
            has_custom_table=true
        fi
    fi
done
if [ "$has_custom_table" = false ]; then
    log_stdout_and_file "No active custom tables (100 / 1000) found."
fi

print_header "8. DNS configuration"
log_stdout_and_file "Resolv.conf:"
resolv_conf=$(cat /etc/resolv.conf 2>/dev/null || echo "Cannot read /etc/resolv.conf")
log_stdout_and_file "$resolv_conf"

log_stdout_and_file "\nsystemd-resolved status:"
resolve_status=$(resolvectl status 2>/dev/null || systemd-resolve --status 2>/dev/null || echo "systemd-resolved status not available")
log_stdout_and_file "$resolve_status"

print_header "9. Socket Connections (Listening Ports)"
if [ "$UID_VAL" -eq 0 ]; then
    sock_out=$(ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || echo "ss/netstat not available")
else
    sock_out=$(ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null || echo "ss/netstat not available (running rootless)")
fi
log_stdout_and_file "$sock_out"

# 10. Firewall Rules (Root required)
print_header "10. Firewall / nftables Ruleset"
if [ "$UID_VAL" -eq 0 ]; then
    if command -v nft >/dev/null 2>&1; then
        nft_out=$(nft list ruleset 2>&1)
        log_stdout_and_file "$nft_out"
    elif command -v iptables >/dev/null 2>&1; then
        log_stdout_and_file "iptables-save:"
        iptables_out=$(iptables-save 2>&1)
        log_stdout_and_file "$iptables_out"
    else
        log_stdout_and_file "No nft or iptables command found."
    fi
else
    log_stdout_and_file "[Notice] Firewall ruleset (nftables/iptables) requires root privileges to read. Skipping."
fi

# 11. Recent Logs
print_header "11. Recent Xray Logs"
if [ -n "$BINARY_PATH" ]; then
    logs_out=$("$BINARY_PATH" logs -n 50 2>&1)
    log_stdout_and_file "$logs_out"
else
    if [ -f "$CONFIG_DIR/xray.log" ]; then
        log_stdout_and_file "Last 50 lines of $CONFIG_DIR/xray.log:"
        log_stdout_and_file "$(tail -n 50 "$CONFIG_DIR/xray.log")"
    else
        log_stdout_and_file "No log file found."
    fi
fi

# 12. Connectivity test
print_header "12. Connectivity Test"
targets=("1.1.1.1" "8.8.8.8" "www.google.com" "www.baidu.com")
for target in "${targets[@]}"; do
    if ping -c 1 -W 2 "$target" >/dev/null 2>&1; then
        log_stdout_and_file "Ping $target: OK"
    else
        log_stdout_and_file "Ping $target: FAILED"
    fi
done

if command -v curl >/dev/null 2>&1; then
    curl_out=$(curl -I -s --connect-timeout 3 https://www.google.com | head -n 1)
    log_stdout_and_file "HTTP check to https://www.google.com: ${curl_out:-FAILED}"
else
    log_stdout_and_file "HTTP check to https://www.google.com: curl not found"
fi

log_stdout_and_file "================================================================="
log_stdout_and_file "  End of Diagnostic Report"
log_stdout_and_file "  Full log saved to: ${OUT_FILE}"
log_stdout_and_file "================================================================="

# --- Post-Processing (Redaction & Anonymization) ---
if command -v python3 >/dev/null 2>&1; then
    python3 -c '
import sys, re, ipaddress

def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip_str == "0.0.0.0" or ip_str == "255.255.255.255"
    except:
        return False

# Patterns
ipv4_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ipv6_pattern = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|:\b(?::[0-9a-fA-F]{1,4}){1,7}\b")
domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|edu|gov|mil|xyz|co|info|io|cc|us|cn|hk|tw|jp|kr|eu|uk)\b", re.IGNORECASE)
json_redact_pattern = re.compile(r"(\"(?:uuid|token|sub_token|privateKey|publicKey|password|secret|user_uuid|id|address|dest|sni|serverName|path|shortId)\"\s*:\s*)\"([^\"]+)\"", re.IGNORECASE)

def redact_line(line):
    # Redact JSON keys
    def json_repl(match):
        key_part = match.group(1)
        val = match.group(2)
        key_name = re.search(r"\"([^\"]+)\"", key_part).group(1).lower()
        if key_name in ["uuid", "token", "sub_token", "privatekey", "publickey", "password", "secret", "user_uuid", "id", "shortid"]:
            return f"{key_part}\"<REDACTED>\""
        elif key_name in ["address", "dest", "sni", "servername", "path"]:
            host_part = val.split(":")[0] if ":" in val else val
            if is_private_ip(host_part):
                return f"{key_part}\"{val}\""
            if key_name == "address":
                return f"{key_part}\"<REDACTED_ADDR>\""
            elif key_name == "dest":
                return f"{key_part}\"<REDACTED_DEST>\""
            elif key_name in ["sni", "servername"]:
                return f"{key_part}\"<REDACTED_SNI>\""
            elif key_name == "path":
                return f"{key_part}\"<REDACTED_PATH>\""
        return f"{key_part}\"<REDACTED>\""

    line = json_redact_pattern.sub(json_repl, line)

    # Redact public IPv4
    def ipv4_repl(match):
        ip = match.group(0)
        if not is_private_ip(ip):
            return "<PUBLIC_IP>"
        return ip
    line = ipv4_pattern.sub(ipv4_repl, line)

    # Redact public IPv6
    def ipv6_repl(match):
        ip = match.group(0)
        if not is_private_ip(ip):
            return "<PUBLIC_IP6>"
        return ip
    line = ipv6_pattern.sub(ipv6_repl, line)

    # Redact Domain names (ignoring systemd services)
    def domain_repl(match):
        dom = match.group(0)
        dom_lower = dom.lower()
        if dom_lower in ["localhost", "127.0.0.1", "::1"]:
            return dom
        if dom_lower.endswith(".service") or dom_lower.endswith(".device") or dom_lower.endswith(".mount"):
            return dom
        return "<DOMAIN>"
    line = domain_pattern.sub(domain_repl, line)

    return line

for line in sys.stdin:
    sys.stdout.write(redact_line(line))
' < "$RAW_FILE" > "$OUT_FILE"
else
    # Fallback to simple sed if Python is absent
    cat "$RAW_FILE" | sed -E 's/"(uuid|token|sub_token|privateKey|publicKey|password|secret|user_uuid|id|shortId)"\s*:\s*"[^"]*"/"\1": "<REDACTED>"/gI' > "$OUT_FILE"
fi

# Print final redacted report to stdout & clean up raw temporary file
cat "$OUT_FILE"
rm -f "$RAW_FILE"
