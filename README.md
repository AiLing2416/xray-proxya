# Xray-Proxya

Xray-Proxya is a professional, Go-based proxy management tool and transparent gateway. It is designed to be the modern successor to the archive bash-based deployment scripts, focusing on reliability, security, and advanced networking features.

## Key Features

- **Role-Based Architecture**: Clearly separated **Server** (inbound distribution) and **Gateway** (transparent proxy) roles to prevent configuration conflicts.
- **Staging System**: A safe "Modify -> Validate -> Commit" workflow. All changes are saved to a staging area and verified by an isolated Xray process before going live.
- **Advanced Inbounds**:
  - **VLESS-Reality-XHTTP**: State-of-the-art stealth with randomized international SNIs.
  - **VLESS-XHTTP-KEM768**: Post-quantum security ready.
  - **VMess-WS & Shadowsocks**: Reliable fallback protocols.
- **Transparent Gateway**:
  - Built-in **TUN (gvisor)** and **TPROXY** support.
  - **DNS Hijacking & FakeDNS**: Accurate domain-based routing for LAN clients.
  - **Kernel-Level Blacklist**: High-performance blocking using `nftables` sets.
- **Relay System**: Easily bind incoming users to specific outbound relay nodes with per-relay DNS strategies.
- **Zero-Conflict Testing**: Automated connectivity tests use randomized ports to ensure zero impact on running services.

## Installation

### One-Click Install
```bash
curl -Ls https://raw.githubusercontent.com/paimon-vless/xray-proxya/main/install.sh | bash
```

### Manual Build
Requires Go 1.25+
```bash
git clone https://github.com/paimon-vless/xray-proxya
cd xray-proxya
CGO_ENABLED=0 go build -o xray-proxya ./cmd/xray-proxya/
sudo mv xray-proxya /usr/local/bin/
```

## Quick Start

### 1. Initialize
Choose your role during initialization:
```bash
# For a distribution server
xray-proxya init --role server

# For a transparent gateway
xray-proxya init --role gateway
```

### 2. Manage Nodes (Relays)
```bash
# Add a node to staging
xray-proxya outbound add my-hk-node "vless://..."

# Apply changes (Validates and restarts service)
xray-proxya apply
```

### 3. Gateway Configuration
```bash
# Setup kernel parameters (forwarding, etc.)
xray-proxya gateway setup-kernel

# Bind gateway traffic to a relay
xray-proxya gateway set --mode tun --relay my-hk-node
xray-proxya apply
```

## CLI Reference

- `presets`: Manage pre-defined inbound slots.
- `outbound`: Manage relay nodes and interface bindings.
- `gateway`: Configure transparent proxy settings and blacklists.
- `service`: Install/Uninstall systemd service and view logs.
- `status`: Show real-time traffic and process info.
- `apply / undo`: Commit or discard staging changes.

## Development

The project is built with a focus on **Rootless** execution where possible. Higher-level gateway features (TUN/TPROXY) leverage Linux capabilities (`setcap`) or explicit `sudo` calls for kernel interactions.

Built with ❤️ by the Xray-Proxya team.
