# Xray-Proxya

Xray-Proxya is a Go-based manager for two primary roles: deploying proxy servers with authentic web camouflage and running Linux TUN-based transparent gateways. It features a staging-first configuration workflow, relay routing, multi-tenant isolation, and operational safety mechanisms tailored for Linux systems.

## Key Features

- **Staging-First Configuration**:
  - Configuration changes are written to a staging file and validated before activation.
  - `diff` (or `config diff`) inspects structured pending modifications before committing with `apply`.
- **Role-Based Deployment**:
  - `server`: Inbound protocol termination, web camouflage, and relay distribution.
  - `gateway`: Transparent proxy forwarding via dedicated TUN devices and policy routing.
- **Authentic Web Camouflage**:
  - Embedded decoy web applications (**Nextcloud**, **File Browser**, and **Seafile**) bundled directly via Go `embed.FS`.
  - Built-in timing-attack defense simulating password evaluation latency to resist active probing.
  - Automated Let's Encrypt TLS certificate issuance and renewals on port 80 ([Architecture Guide](WIKI/skin-en.md)).
- **Transparent Gateway**:
  - Single-core TUN mode (`proxya-tun`) with automated `nftables` rules and policy routing (Table 100).
  - Bidirectional SSH safety: prevents interception of inbound SSH listeners while permitting gateway outbound SSH connections.
  - Optional geographical country bypass and custom DNS diversion ([Gateway Guide](WIKI/gateway_en.md)).
- **Relay Testing & Diagnostics**:
  - `relay test`: Diagnostic checks covering exit IPs, DNS resolution, and modern transports (H2, gRPC, WebSocket, XHTTP).
  - `relay info`: Exit node profile inspection, streaming platform unlocks, and regional attributes.
  - `relay speed`: Multi-provider bandwidth testing (Cloudflare, Fast.com, M-Lab NDT7, Ookla) featuring adaptive automated probing (`-a`), terminal 2D Unicode waveform charts (`-c`), and multi-threading (`-P`).
- **Multi-Tenant Guest Management**:
  - Independent UUID generation, customizable traffic quotas, staged alert notifications, and optional webhook delivery.
- **Operational Safety & System Integration**:
  - Automated host health diagnostics (`doctor check`).
  - Safe system resource uninstallation and data wipeout (`purge`).
  - PathLink loopback ICMP diagnostics through upstream relays ([PathLink Guide](WIKI/pathlink_en.md)).
  - Temporary runtime kernel parameter tuning without modifying `/etc/sysctl.conf` (`tune`).
  - SELinux security module support for Fedora Server ([SELinux Guide](WIKI/selinux-en.md)).
  - Managed systemd unit lifecycles and interactive full-screen TUI dashboard (`tui`).

## Installation

### One-Click Install
```bash
curl -Ls https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/install.sh | bash
```

The installer verifies and downloads release assets, placing the public `xray-proxya` binary in `~/.local/bin/` (or `/root/.local/bin/` for root).

### Manual Build
Requires Go 1.25+
```bash
git clone https://github.com/AiLing2416/xray-proxya
cd xray-proxya
CGO_ENABLED=0 go build -ldflags "-s -w" -o xray-proxya ./cmd/xray-proxya
CGO_ENABLED=0 go build -ldflags "-s -w" -o pathd ./cmd/xray-proxya-pathd
```

> [!NOTE]
> - `pathd` is a companion binary for PathLink. Install it under `~/.local/share/xray-proxya/bin/pathd` (or `/root/.local/share/xray-proxya/bin/pathd` for root).
> - Privileged commands (such as `gateway`, `cert`, `service`, and `path`) require a full root environment. Switch via `sudo -i`, `su -`, or log in as `root` directly; avoid single-command `sudo xray-proxya ...` to ensure clean environment variables and configuration paths.

---

## Quick Start

### Scenario A: Deploying a Distribution Server

```bash
# 1. Initialize server role
xray-proxya init --role server

# 2. Issue a TLS certificate and bind a decoy skin to Preset 1 (VLESS Reality)
xray-proxya cert add sea.example.com
xray-proxya presets set 1 --skin seafile --skin-domain sea.example.com

# 3. Validate and apply staged configuration
xray-proxya apply

# 4. Install and start the systemd service
xray-proxya service install
xray-proxya service start

# 5. Display client connection links and QR codes
xray-proxya show --all
```

### Scenario B: Setting up a Transparent Gateway

```bash
# 1. Initialize gateway role (in a root shell via sudo -i, su -, or direct root login)
xray-proxya init --role gateway

# 2. Import an upstream relay node and verify connectivity
xray-proxya relay add upstream "vless://..."
xray-proxya apply
xray-proxya relay test upstream

# 3. Bind upstream relay and LAN interface, then apply
xray-proxya gateway set upstream --lan eth0
xray-proxya apply

# 4. Bring up transparent proxying and inspect state
xray-proxya gateway up
xray-proxya gateway status
xray-proxya gateway check
```
> For LAN routing setups, client configuration, and state semantics, see the [Transparent Gateway Guide](WIKI/gateway_en.md) ([中文教程](WIKI/gateway_zh.md)).

---

## Common Operations

```bash
# Inspect changes before applying
xray-proxya diff

# Run adaptive bandwidth test with live waveform chart
xray-proxya relay speed upstream --auto --chart

# Query egress IP of a local proxy instance
xray-proxya proxy probe my-proxy

# Export proxy environment variables for current shell
eval $(xray-proxya proxy env my-proxy)

# Run host and environment health diagnostics
xray-proxya doctor check

# Launch the interactive terminal dashboard
xray-proxya tui

# Safely preview resource cleanup
xray-proxya purge -i config,core,service --dry-run
```

---

## Advanced Documentation

- [Transparent Gateway Architecture & Guide](WIKI/gateway_en.md) ([中文](WIKI/gateway_zh.md))
- [PathLink ICMP Link Diagnostics](WIKI/pathlink_en.md) ([中文](WIKI/pathlink_zh.md))
- [Authentic Web Camouflage & Timing Defense](WIKI/skin-en.md) ([中文](WIKI/skin-zh.md))
- [SELinux Policy Guide for Fedora](WIKI/selinux-en.md) ([中文](WIKI/selinux-zh.md))

---

## CLI Reference

- `apply / undo`: Validate and commit, or discard pending staging changes.
- `cert`: Manage ACME / Let's Encrypt TLS certificates (root-only).
- `completion`: Generate shell completion script for stdout (Bash V2, Zsh, Fish).
- `config`: Inspect and upgrade configuration files.
- `diff`: Display structured differences between active and staging configurations.
- `doctor`: Automated environment diagnostics (`check`), SELinux management, backup/rollback, and user linger checks.
- `endpoint`: Manage connection endpoints and address providers for proxy nodes.
- `gateway`: Manage TUN-based transparent proxy forwarding, bypass routing, and runtime state.
- `guests`: Manage multi-tenant users, bandwidth quotas, alert triggers, and relay bindings.
- `logs`: Inspect unified systemd journal logs across managed services.
- `path`: Manage loopback PathLink ICMP diagnostic agent and probe tools (root-only).
- `presets`: Configure inbound protocol slots (Reality, Vision, KEM) and web camouflage.
- `proxy`: Manage and run local SOCKS/HTTP proxy listeners, probe egress IPs, and export shell variables.
- `purge`: Safely delete and purge specified resources (`config`, `service`, `core`, `selinux`, `all`).
- `relay`: Manage relay nodes, upstream subscriptions (`relay sub`), and test suites (`test`, `info`, `speed`).
- `run`: Run Xray core in the foreground for debugging.
- `service`: Install and control systemd units (`xray-proxya`, `xray-proxya-pathd`, `xray-proxya-he-tunnel`, `xray-proxya-sub@<instance>`).
- `show`: Display client connection links, guest subscriptions, and QR codes.
- `status`: Display systemd service overview, network state, and real-time traffic statistics.
- `sub`: Configure and control server subscription distribution services.
- `tui`: Launch the interactive terminal UI management dashboard.
- `tune`: Apply and rollback temporary kernel sysctl profiles (root-only).
- `version`: Display version, Go build environment, and active Xray-core path.
