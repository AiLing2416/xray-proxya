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

PathLink commands are root-shell only. Use a direct root login or `su -`; do
not invoke `path` through `sudo`, because its configuration and system service
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
xray-proxya gateway set --relay hk-node
xray-proxya apply
xray-proxya gateway up
```

### 5. Temporary Kernel Tuning

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

### 6. PathLink ICMP Probes

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

`--relay` is Gateway-only: a Server always configures its local Pathd and
rejects this flag. Pathd enablement is owned by `service enable/disable`, not
by the PathLink configuration. Only public IP addresses and hostnames resolving
to public addresses can be probed. `path status` reports the local agent state
on a Server and the selected relay's credential/runtime state on a Gateway.

### Tune migration

Older releases could leave a `.tune_state` marker that claimed a profile would
be replayed when Xray-Proxya started. Current releases intentionally ignore
that marker: tuning is no longer tied to proxy service lifecycle. Remove the
legacy marker if it remains, and use a separate, explicit systemd unit or
configuration-management policy if boot-time tuning is required.
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
- `gateway`: Configure transparent proxy settings and dual-stack forwarding.
- `tune`: Apply and rollback temporary kernel tuning profiles for gateway, relay, and server roles.
- `status`: Real-time traffic stats and process monitoring.
- `apply / undo`: Commit or discard staging changes with automatic validation.
- `path`: Configure PathLink and run relay-carried ICMP ping, trace, and MTU probes from a root Gateway shell.
- `service`: Install and control the managed systemd units. `service install` only writes units; it does not enable or start them. Root installs register `xray-proxya`, `xray-proxya-pathd`, and `xray-proxya-sub@<instance>`; Pathd remains disabled until explicitly enabled.
- `doctor completion install / uninstall`: Automatically detect bash, zsh, or fish and manage its shell completion.
