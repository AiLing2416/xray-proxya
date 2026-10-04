# PathLink ICMP Link Diagnostics Guide

This document describes the design, deployment, and operational usage of PathLink in Xray-Proxya.

## 1. Overview & Purpose

Standard proxy protocols (such as VLESS, VMess, and Shadowsocks) operate at the transport layer, handling TCP and UDP traffic. They do not natively forward network-layer ICMP packets. Consequently, executing standard diagnostic tools like `ping` or `traceroute` on a transparent gateway measures local connectivity rather than the true path characteristics from the upstream proxy egress to the remote target.

PathLink provides a private ICMP diagnostic channel. By running a private companion daemon (`pathd`) bound exclusively to the loopback interface on the proxy server, the gateway can issue token-authenticated requests through the proxy tunnel, allowing the server to perform ICMP probing on behalf of the gateway.

---

## 2. Architecture & How It Works

PathLink operates across two paired roles:

1. **Server Role**:
   - Runs the private companion daemon `pathd` (managed by the systemd unit `xray-proxya-pathd.service`).
   - Listens on `127.0.0.1:2828` by default and does not expose ports publicly.
   - Upon receiving an authenticated probe request from a paired gateway, `pathd` sends raw ICMP packets toward the requested target and returns the responses across the proxy tunnel.
2. **Gateway Role**:
   - Binds the pre-shared authentication token to the corresponding upstream relay node.
   - When that relay is active, diagnostic commands (`path ping`, `path trace`, `path mtu`) forward probe requests through the proxy tunnel to the server's `pathd` process.
   - The measured values represent the network conditions between the server egress and the target destination.

---

## 3. Deployment & Configuration

PathLink requires raw socket operations and systemd service management. **Commands must be run from a clean root environment** (`sudo -i`, `su -`, or a direct root login); do not invoke commands via single-command `sudo xray-proxya ...`.

### Step 1: Server Configuration

Generate a token, stage the configuration, and enable the systemd service:

```bash
# Generate and configure the Pathd token in STAGING
xray-proxya path set --generate-token

# Commit staged changes
xray-proxya apply

# Install and start the pathd systemd unit
xray-proxya service install
xray-proxya service enable --now xray-proxya-pathd
```

Verify service status and retrieve the active token:

```bash
xray-proxya path status
```

The output displays `Token: <token-string>` and the loopback listen endpoint (`127.0.0.1:2828`). Keep this token to configure the gateway.

### Step 2: Gateway Configuration

On the gateway, bind the token to the matching relay node (for example, `hk-node`):

```bash
# Bind the token to the relay node (supports positional relay argument)
xray-proxya path set hk-node --token <token-string>

# Commit staged changes
xray-proxya apply
```

List all configured relay PathLink bindings on the gateway:

```bash
xray-proxya path list
```

---

## 4. Command Reference

### 4.1 Status & Listing

* **`xray-proxya path list`** (alias: `path ls`)
  Displays a summary table of all relay nodes, showing PathLink configuration status, listen addresses, and whether the node is the currently active egress.
* **`xray-proxya path status [relay]`**
  On the server, displays the runtime status of the `pathd` service. On the gateway, displays connection metrics, last RTT, and tunnel context for the selected relay.

### 4.2 Diagnostic Probes

Diagnostic commands must be executed on a running gateway with a PathLink-enabled relay selected:

* **`xray-proxya path ping <target> [flags]`**
  Sends ICMP Echo requests to a remote hostname or IP address.
  - `-c, --count <n>`: Number of ICMP requests to send (default: 1).
  - `-i, --interval <duration>`: Wait interval between packets (default: 1s).
  - `-s, --size <n>`: ICMP payload size in bytes (8–1024, default: 8).
  - `-W, --timeout <duration>`: Timeout per probe (default: 2s).
  - `--ttl <n>`: Outgoing TTL / Hop limit (default: 64).
  - `--json`: Format results as structured JSON (includes Min/Avg/Max/Mdev and packet loss percentage).

* **`xray-proxya path trace <target> [flags]`**
  Probes intermediate hops between the server egress and the target destination.
  - `-m, --max-hops <n>`: Maximum hop limit to probe (default: 16).
  - `-W, --timeout <duration>`: Timeout per hop probe (default: 2s).
  - `--json`: Format hop IPs and round-trip times as JSON.

* **`xray-proxya path mtu <target> [flags]`**
  Discovers path MTU between the server egress and the remote target.
  - `--min <n>`: Minimum MTU to probe (default: 576 for IPv4, 1280 for IPv6).
  - `--max <n>`: Maximum MTU to probe (default: 2000).
  - `-W, --timeout <duration>`: Timeout per probe (default: 2s).
  - `--json`: Format output as JSON.

### 4.3 Removing Credentials

* **`xray-proxya path unset <relay>`**
  Removes PathLink credentials for the specified relay node from STAGING. Run `apply` to commit.

---

## 5. Operational Notes & Troubleshooting

1. **Root Shell Requirement**:
   PathLink commands must run inside a full root environment (`sudo -i`, `su -`, or direct root login). Running without root privileges or using single-command `sudo xray-proxya ...` will be rejected.
2. **Service Verification**:
   If the gateway cannot reach PathLink, check the server daemon using `systemctl status xray-proxya-pathd` or `xray-proxya path status` to verify it is `active (running)`.
3. **Loopback Isolation**:
   `pathd` binds exclusively to `127.0.0.1:2828`. It is not designed to accept direct external connections. Connectivity from the gateway relies entirely on routing through the upstream proxy inbound.
4. **Token Consistency**:
   The token passed to `path set` on the gateway must match the server's `path.token`. Mismatched tokens will be rejected during connection handshake.
