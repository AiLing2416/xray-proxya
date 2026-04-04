---
name: xray-proxya-tester
description: Guidance for testing all CLI functions of xray-proxya on the KVM workstation environment (gateway & client VMs). Use this when developers need to verify builds, outbounds, or transparent gateway features.
---

# Xray-Proxya CLI Testing Guide

This skill provides a structured workflow for testing `xray-proxya` CLI features using the provided x86-64 KVM workstation.

## Environment Overview
- **Host**: Your current Arm64 development environment.
- **Gateway VM (`gateway`)**: x86-64 Debian 13. Runs the `xray-proxya` gateway service. IP: `192.168.99.214`.
- **Client VM (`client`)**: x86-64 Debian 13. Used to verify transparent proxying. IP: `192.168.99.124`.

## 1. Build and Deploy
Always cross-compile for x86-64 before deploying to VMs.

```bash
# 1. Cross-compile
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/xray-proxya-linux-amd64 ./cmd/xray-proxya/

# 2. Deploy to Gateway
scp build/xray-proxya-linux-amd64 gateway:~/.local/bin/xray-proxya
```

## 2. Core CLI Function Testing

### Initialization & Apply
On `gateway` VM:
```bash
# Initialize (downloads Xray core and generates defaults)
ssh gateway "~/.local/bin/xray-proxya init"

# Apply configuration (starts/restarts Xray service)
ssh gateway "cp ~/.config/xray-proxya/config.json ~/.config/xray-proxya/config.json.staging && ~/.local/bin/xray-proxya apply"
```

### Outbound (Relay) Management
Test importing and isolated connectivity verification:
```bash
# Add a node (supports vmess, vless, ss, http, socks)
ssh gateway "~/.local/bin/xray-proxya outbound add 'my-node' 'vless://...'"

# List and test nodes
ssh gateway "~/.local/bin/xray-proxya outbound list"
ssh gateway "~/.local/bin/xray-proxya outbound test 'my-node'"
```

## 3. Advanced Gateway (Transparent Proxy) Testing

### Kernel and Firewall Setup
Essential for TPROXY/TUN and Blacklist to work:
```bash
# One-click kernel optimization (requires sudo)
ssh gateway "~/.local/bin/xray-proxya gateway setup-kernel"

# Grant Xray privilege to bind low ports (53) and manage TUN
ssh gateway "sudo setcap 'cap_net_bind_service,cap_net_admin+ep' /home/gemini/.local/bin/xray"
```

### Transparent Proxy Workflow
```bash
# 1. Configure mode and bind to an outbound node
ssh gateway "~/.local/bin/xray-proxya gateway set --mode tun --relay 'my-node'"

# 2. Enable and Apply
ssh gateway "~/.local/bin/xray-proxya gateway enable"
ssh gateway "cp ~/.config/xray-proxya/config.json ~/.config/xray-proxya/config.json.staging && ~/.local/bin/xray-proxya apply"

# 3. Synchronize Blacklist to Kernel (if using blacklist)
ssh gateway "~/.local/bin/xray-proxya gateway sync-firewall"
```

## 4. Verification from Client
To verify if the gateway is actually proxying traffic:

```bash
# 1. Set client's default gateway to the gateway VM
ssh client "sudo ip route del default && sudo ip route add default via 192.168.99.214"

# 2. Test Public IP (should show the relay node's IP)
ssh client "curl -s http://ip-api.com/json | jq"

# 3. Test Blacklist (should timeout or be rejected)
ssh client "curl -v --connect-timeout 5 https://blocked-domain.com"
```

## Troubleshooting
- **Logs**: Check `~/.config/xray-proxya/xray.log` on `gateway` for Xray core errors.
- **Port 53**: If DNS fails, ensure `systemd-resolved` is stopped on `gateway`: `sudo systemctl disable --now systemd-resolved`.
- **Permission**: If TUN fails to start, verify `setcap` was applied correctly to the `xray` binary.
