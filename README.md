# Xray-Proxya

Xray-Proxya is a Go-based Xray manager for two main jobs: running a role-based proxy server and building a TUN-based transparent gateway. It focuses on staging-first configuration changes, relay routing, guest isolation, and operational commands that are practical on small Linux VPS nodes.

## Key Features

- **Staging-first operations**:
  - Most configuration commands write to a staging file first.
  - `apply` performs validation before committing changes into the active config.
- **Role-based deployment**:
  - `server` mode for inbound distribution and relay serving.
  - `gateway` mode for TUN-based transparent proxy forwarding.
- **Authentic Web Camouflage v3**:
  - Pixel-perfect Web login replicas for **Nextcloud 34**, **File Browser 2.63**, and **Seafile 11**.
  - Embedded assets via Go `embed.FS` with zero external dependencies.
  - Active probing and timing-attack defense via simulated password hash delay (400–700ms).
  - Port 80 redirector with dynamic ACME challenge delegation and automatic expiration safety fuses.
- **ACME Certificate Automation (`cert`)**:
  - Native Let's Encrypt TLS issuance and automated renewal with root-shell protection.
- **Upstream Subscription Lifecycle (`relay sub`)**:
  - Add, update, diff, and remove upstream airport subscriptions directly in STAGING.
  - Automatic base64 decoding, node remark sanitization (`<airport>/<node>`), and active gateway relay protection.
- **Multi-Tenant Guest Isolation & Notifications**:
  - Create multiple guests with separate UUIDs.
  - Unit-aware quotas supporting Base-10 (KB, MB, GB, TB) and Base-2 (KiB, MiB, GiB, TiB).
  - Staged percentage and capacity alert triggers (`--notify-trigger`).
  - Multi-mode notifications (HTTP headers, dynamic remarks, memorial nodes) and native `ntfy.sh` / JSON Webhook integration.
- **Modular Relay Diagnostics & Multi-Provider Speed Tests**:
  - `relay test`: Dual-stack IPv4/IPv6 exit IP, DNS53, modern protocols (H2/gRPC/WS/XHTTP), and SOCKS5 UDP test.
  - `relay info`: Landing profile, streaming unlocks, and AI service web access with parallel worker pools.
  - `relay speed`: Multi-provider speed testing (Cloudflare, Fast.com, M-Lab, Ookla, Custom) with persistent TCP latency probing.
- **Automated Health Diagnostics (`doctor check`)**:
  - Automated 7-point health check inspecting system clock sync, Xray core, kernel parameters, linger state, modern transport support, port collisions, and UDP reachability.
- **Interactive Terminal UI (TUI)**:
  - Full-screen dashboard with in-bar hierarchical service configuration, vertical gateway selection, non-blocking relay testing, and one-key upstream subscription refresh (`[P]`).
- **Modern transport presets**:
  - VLESS Vision + Reality TCP
  - VLESS Reality XHTTP
  - VLESS XHTTP KEM-768
  - VMess WS
  - Shadowsocks TCP
- **Operational safety**:
  - Gateway firewall sync protects active SSH listeners from interception.
  - Runtime-only `tune` profiles can apply temporary kernel `sysctl` changes for `gateway`, `relay`, and `server` roles.
  - PathLink provides authenticated, relay-carried ICMP probes without exposing its agent publicly.
  - Managed systemd units keep the main proxy, PathLink agent, and subscription instances on explicit lifecycles.
  - Shell completion generation and install helpers are built in.

## Installation

### One-Click Install
```bash
curl -Ls https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/install.sh | bash
```

The installer verifies and installs the public `xray-proxya` CLI plus its
private Xray core / `pathd` components. Only the CLI is added to `PATH`.

PathLink and Certificate commands are root-shell only. Use a direct root login or `su -`; do
not invoke them through `sudo`, because configuration and system services
are intentionally owned by root.

### Manual Build
Requires Go 1.25+
```bash
git clone https://github.com/AiLing2416/xray-proxya
cd xray-proxya
CGO_ENABLED=0 go build -ldflags "-s -w" -o xray-proxya ./cmd/xray-proxya
CGO_ENABLED=0 go build -ldflags "-s -w" -o pathd ./cmd/xray-proxya-pathd
```

`pathd` is a private companion binary. Install it under
`~/.local/share/xray-proxya/bin/pathd` (or
`/root/.local/share/xray-proxya/bin/pathd` for root) rather than adding it to
`PATH`.

## Quick Start

### 1. Initialize
```bash
# For a distribution server
xray-proxya init --role server

# For a transparent gateway
xray-proxya init --role gateway
```

### 2. Authentic Web Camouflage & ACME TLS (Server)
```bash
# Issue a Let's Encrypt certificate for your domain (direct root shell)
xray-proxya cert add sea.example.com

# Bind high-fidelity Seafile camouflage skin to Reality preset
xray-proxya presets set 1 --skin seafile --skin-domain sea.example.com
xray-proxya apply
```

### 3. Upstream Subscriptions & Relay Nodes
```bash
# Import an airport subscription into STAGING
xray-proxya relay sub add myairport "https://sub.example.com/api/v1/..."

# Or add a single relay node manually
xray-proxya relay add hk-node "vless://..."

# Run health diagnostics or speed tests
xray-proxya relay test hk-node
xray-proxya relay info hk-node
xray-proxya relay speed hk-node
xray-proxya apply
```

### 4. Multi-Tenant Guest Setup
```bash
# Add a guest user
xray-proxya guests add john-doe

# Configure 100GB limit, monthly reset, and alert triggers
xray-proxya guests set john-doe --limit 100GB --reset 1 --notify-trigger 80%,90%
xray-proxya guests set john-doe --relay hk-node
xray-proxya apply
```

### 5. Transparent Gateway
```bash
# Use a relay as the transparent upstream
xray-proxya gateway set --relay hk-node
xray-proxya apply
xray-proxya gateway up
```

### 6. System Health Check
```bash
# Run host, kernel, and network diagnostics
xray-proxya doctor check
```

### 7. Interactive TUI
```bash
# Launch full-screen management interface
xray-proxya tui
```

### 8. Temporary Kernel Tuning

`tune` is root-only. Enter a direct root shell or use `su -` before running
these commands; do not invoke it through `sudo`.

```bash
# Inspect available tuning profiles
xray-proxya tune profiles

# Preview the relay profile before applying it
xray-proxya tune diff relay

# Apply temporary runtime sysctl tuning
xray-proxya tune use relay

# Verify or rollback the session later
xray-proxya tune verify relay
xray-proxya tune rollback
```

Notes:
- `tune` is root-only by design.
- Tuning does not write `/etc/sysctl.conf` or `/etc/sysctl.d/*`. `tune use` changes only the current runtime; restarting Xray-Proxya does not reapply a profile, and a reboot restores the system-managed sysctl state. `tune rollback` restores values recorded for the current runtime session.

### 9. PathLink ICMP Probes

PathLink is a root-only feature for probing a public destination through the
Gateway's selected relay. Use a direct root login or `su -`, never `sudo`.

On the Server, configure the local Pathd endpoint, commit it, then enable its
already-registered systemd service. `service install` writes the Pathd unit but
does not enable or start it. Keep the token for the paired Gateway:

```bash
xray-proxya path set --generate-token
xray-proxya apply
xray-proxya service install
xray-proxya service enable --now xray-proxya-pathd
```

On the paired Gateway, bind that token to each relay that can reach a Pathd.
Gateway relay selection automatically selects its matching credentials:

```bash
xray-proxya path set --relay hk --token <hk-token> --listen 127.0.0.1:39091
xray-proxya path set --relay sg --token <sg-token> --listen 127.0.0.1:39091
xray-proxya apply
xray-proxya gateway set --relay hk
xray-proxya gateway up
xray-proxya path ping 1.1.1.1
xray-proxya path trace 1.1.1.1
xray-proxya path mtu 1.1.1.1
```

## CLI Reference

- `cert`: Manage ACME / Let's Encrypt TLS certificates (root-only: add, list, renew, remove).
- `presets`: Manage pre-defined inbound protocols (Reality, Vision, KEM, etc.) and Web camouflage (`--skin`, `--skin-domain`, `--sni`).
- `relay`: Manage relay nodes, upstream subscriptions (`relay sub`), physical interface bindings, and test suites (`test`, `info`, `speed`).
- `guests`: Manage multi-tenant users, unit-aware quotas, staged alert triggers, and dedicated outbounds.
- `gateway`: Configure transparent proxy settings and dual-stack forwarding.
- `doctor`: Run automated health diagnostics (`doctor check`) and manage shell completion (`doctor completion`).
- `tui`: Full-screen terminal dashboard for real-time monitoring and configuration.
- `status`: Real-time traffic stats and process monitoring.
- `show`: Display client connection links, guest subscription links, and QR codes.
- `apply / undo`: Commit or discard staging changes with automatic validation.
- `tune`: Apply and rollback temporary kernel tuning profiles for gateway, relay, and server roles.
- `path`: Configure PathLink and run relay-carried ICMP ping, trace, and MTU probes from a root Gateway shell.
- `service`: Install and control the managed systemd units (`xray-proxya`, `xray-proxya-pathd`, `xray-proxya-sub@<instance>`).
