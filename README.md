# Xray-Proxya

Xray-Proxya is a Go-based Xray manager for two main jobs: running a role-based proxy server and building a TUN-based transparent gateway. It focuses on staging-first configuration changes, relay routing, guest isolation, and operational commands that are practical on small Linux VPS nodes.

## Key Features

- **Staging-first operations**:
  - Most configuration commands write to a staging file first.
  - `apply` performs validation before committing changes into the active config.
- **Role-based deployment**:
  - `server` mode for inbound distribution and relay serving.
  - `gateway` mode for TUN-based transparent proxy forwarding.
- **Relay and outbound tooling**:
  - Import relay links with `outbound add`.
  - Bind guests or the gateway to specific relays.
  - Expose per-relay local SOCKS/HTTP listeners for debugging or local forwarding.
  - Probe relay paths directly with IPv4 / IPv6-aware outbound tests.
- **Guest isolation**:
  - Create multiple guests with separate UUIDs.
  - Set quotas and reset schedules.
  - Route selected guests through dedicated outbounds.
- **Modern transport presets**:
  - VLESS Vision + Reality TCP
  - VLESS Reality XHTTP
  - VLESS XHTTP KEM-768
  - VMess WS
  - Shadowsocks TCP
- **Operational safety**:
  - Gateway firewall sync protects active SSH listeners from interception.
  - Runtime-only `tune` profiles can apply temporary kernel `sysctl` changes for `gateway`, `relay`, and `server` roles.
  - Shell completion generation and install helpers are built in.

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
CGO_ENABLED=0 go build -ldflags "-s -w" -o xray-proxya ./cmd/xray-proxya
```

## Quick Start

### 1. Initialize
```bash
# For a distribution server
xray-proxya init --role server

# For a transparent gateway
xray-proxya init --role gateway
```

### 2. Add a Relay
```bash
xray-proxya outbound add hk-node "vless://..."
xray-proxya outbound list
```

### 3. Multi-Tenant Setup
```bash
# Add a guest with 100GB monthly quota
xray-proxya guests add john-doe --quota 100 --reset 1
xray-proxya guests set john-doe --outbound hk-node
xray-proxya apply
```

### 4. Transparent Gateway
```bash
# Use a relay as the transparent upstream
xray-proxya gateway set --mode tun --relay hk-node
xray-proxya apply
```

### 5. Temporary Kernel Tuning
```bash
# Inspect available tuning profiles
sudo xray-proxya tune profiles

# Preview the relay profile before applying it
sudo xray-proxya tune diff relay

# Apply temporary runtime-only sysctl tuning
sudo xray-proxya tune apply relay

# Verify or rollback the session later
sudo xray-proxya tune verify relay
sudo xray-proxya tune rollback
```

Notes:
- `tune` is root-only by design.
- Tuning is runtime-only and does not write `/etc/sysctl.conf` or `/etc/sysctl.d/*`.
- Unsupported keys are reported and skipped rather than forcing legacy compatibility behavior.

## Common Commands

```bash
xray-proxya status
xray-proxya show
xray-proxya show --guest john-doe
xray-proxya outbound test hk-node
xray-proxya outbound info hk-node
xray-proxya outbound probe-local hk-node -4
```

## CLI Reference

- `guests`: Manage multi-tenant users, quotas, and dedicated outbounds.
- `presets`: Manage pre-defined inbound protocols (Reality, Vision, KEM, etc.).
- `outbound`: Manage relay nodes, **physical interface bindings**, and **internal proxies**.
- `gateway`: Configure transparent proxy settings, dual-stack forwarding, and blacklists.
- `tune`: Apply and rollback temporary kernel tuning profiles for gateway, relay, and server roles.
- `status`: Real-time traffic stats and process monitoring.
- `apply / undo`: Commit or discard staging changes with automatic validation.
- `completion install`: Setup shell autocompletion.
