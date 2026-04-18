# Xray-Proxya

Xray-Proxya is a professional, Go-based proxy management tool and transparent gateway. It is designed to be the modern successor to legacy bash-based deployment scripts, focusing on multi-tenant isolation, reliability, and advanced networking features.

## Key Features

- **Multi-Tenant Guest Management (v0.2.2)**:
  - **Isolation**: Manage multiple tenants with independent UUIDs using `guests` commands.
  - **Quotas**: Set downlink traffic quotas (GB) with monthly auto-reset and boundary adaptation.
  - **Dedicated Routes**: Bind specific guests to dedicated outbound relay nodes for personalized traffic paths.
- **Role-Based Architecture**: Clearly separated **Server** (inbound distribution) and **Gateway** (transparent proxy) roles.
- **Advanced Networking**:
  - **Physical Interface Binding**: Bind the `freedom` protocol to specific local interfaces (e.g., WireGuard, ProtonVPN) for policy-based routing.
  - **Internal Proxies**: Instantly create private, unauthenticated Socks/HTTP ports for any outbound node.
  - **Dual-Stack Gateway**: Automatic IPv4/IPv6 forwarding and TProxy/TUN support with `nftables` (and `iptables` fallback).
- **Security & Stealth**:
  - **VLESS-Reality-XHTTP**: State-of-the-art stealth with randomized international SNIs.
  - **VLESS-XHTTP-KEM768**: Post-quantum security ready.
  - **SSH Protection**: Automatically excludes SSH ports from intercept rules to prevent lockout.
- **Reliability**:
  - **Zero-Dependency Core**: Pure Go zip implementation for downloading Xray core—works on Alpine/Debian Slim.
  - **Self-Healing**: Automatic TUN device cleanup and process management (`pkill -x` matching).
  - **Shell Guard**: Built-in detection for truncated links caused by missing shell quotes.

## Installation

### One-Click Install
```bash
curl -Ls https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/install.sh | bash
```

### Manual Build
Requires Go 1.25+
```bash
git clone https://github.com/AiLing2416/xray-proxya
cd xray-proxya
CGO_ENABLED=0 go build -ldflags "-s -w" -o xray-proxya ./cmd/xray-proxya/
```

## Quick Start

### 1. Initialize
```bash
# For a distribution server
xray-proxya init --role server

# For a transparent gateway
xray-proxya init --role gateway
```

### 2. Multi-Tenant Setup
```bash
# Add a guest with 100GB monthly quota
xray-proxya guests add john-doe --quota 100 --reset 1
xray-proxya apply
```

### 3. Dedicated Outbound
```bash
# Bind a guest to a specific relay node
xray-proxya outbound add hk-node "vless://..."
xray-proxya guests set john-doe --outbound hk-node
xray-proxya apply
```

## CLI Reference

- `guests`: Manage multi-tenant users, quotas, and dedicated outbounds.
- `presets`: Manage pre-defined inbound protocols (Reality, Vision, KEM, etc.).
- `outbound`: Manage relay nodes, **physical interface bindings**, and **internal proxies**.
- `gateway`: Configure transparent proxy settings, dual-stack forwarding, and blacklists.
- `status`: Real-time traffic stats and process monitoring.
- `apply / undo`: Commit or discard staging changes with automatic validation.
- `completion install`: Setup shell autocompletion.

Built with ❤️ by the Xray-Proxya team.
