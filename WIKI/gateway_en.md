# Xray-Proxya Transparent Gateway Guide

This guide explains how to run Xray-Proxya as a TUN-based transparent gateway. Gateway mode is TUN-only now, so there is no `--mode` flag to configure.

## Goal

A transparent gateway lets one Linux host act as the LAN egress:

- The gateway host's own traffic can be transparently proxied.
- Neighbor LAN clients can use the gateway by pointing their default route to it.
- Xray outbound traffic is marked with `255` so it bypasses the transparent capture path and avoids loops.

## Roles

A typical setup has two or three machines:

- Upstream server: runs `xray-proxya init --role server` and exposes VLESS / Shadowsocks inbound links.
- Gateway: runs `xray-proxya init --role gateway` and handles transparent proxying.
- Client: a LAN test machine whose default route is temporarily pointed to the gateway.

## Runtime Principle

**Do not run single-command `sudo xray-proxya ...` across users.** Single-command `sudo` produces an uncleaned environment with conflicting `SUDO_USER`, `HOME`, `PATH`, and config directories, which easily causes split setups where binaries or configurations are read from unexpected paths.

When performing privileged operations (transparent gateway requires managing TUN, nftables, policy routing, and sysctl), use **Root Mode**:
- Switch to a clean, full root login environment using `sudo -i`, `su -`, or by logging in as `root` directly.
- Execute `xray-proxya` commands only after entering the root environment.

Commands in this guide assume a full root shell. If currently running as a standard user, switch to root first:

```bash
# Enter a full root environment (sudo -i or su - recommended)
sudo -i
# or
su -
```

## Prepare An Upstream Node

On the upstream server:

```bash
xray-proxya init --role server
xray-proxya service install
xray-proxya service start
```

Export sharing links:

```bash
xray-proxya show --all
```

Use a link that passes connectivity tests, for example a Reality Vision TCP link.

## Initialize The Gateway

On the gateway host:

```bash
xray-proxya init --role gateway
```

Find the default egress interface:

```bash
ip -4 route show default
```

The interface after `dev` is the LAN/egress interface, for example:

```text
default via 10.50.0.1 dev eth0 proto static
```

Here the interface is `eth0`.

## Import The Upstream Node

```bash
xray-proxya relay add remote-v029 "vless://..."
xray-proxya apply
xray-proxya relay test remote-v029
```

Expected result:

```text
TCP: OK
UDP: OK
DNS: OK
```

If `relay test` fails, fix the upstream first before enabling transparent gateway rules.

## Configure Transparent Gateway

Xray-Proxya provides two approaches to configure a transparent gateway:
1. **Declarative Configuration Architecture (`gateway.conf`)**: Recommended. Uses a lightweight, crontab-like line syntax to declaratively manage interfaces, zones, device aliases, groups, L3 IP/CIDR routing, and port forwarding. It is easy to understand, text-editable, and ideal for version control and backup.
2. **Interactive CLI Configuration (`gateway set` / `gateway rule`)**: Suitable for quick ad-hoc adjustments or automation scripts, writing changes directly to the Staging area.

Both paradigms are fully interoperable under the hood; `gateway export -w` can export the active or staged configuration to `gateway.conf` at any time.

### Approach 1: Declarative Configuration via gateway.conf (Recommended)

#### 1. Configuration File Locations
- **Root Environment (Recommended for Gateway)**: `/root/.config/xray-proxya/gateway.conf`
- **Standard User Environment**: `~/.config/xray-proxya/gateway.conf`

#### 2. Quickstart Workflow
1. **Auto-Generate Initial Template**:
   When initializing the gateway role, the system automatically writes an annotated `gateway.conf` template containing detailed syntax comments and examples:
   ```bash
   xray-proxya init gateway
   ```
2. **Safe Interactive Editing**:
   Use the built-in edit command to edit the configuration file with your preferred editor. It respects `$EDITOR` or `$VISUAL` (falling back automatically to `nano`, `vim`, or `vi`):
   ```bash
   xray-proxya gateway edit
   ```
   > [!TIP]
   > `gateway edit` features **real-time syntax linting and compilation validation** upon exit. If syntax errors or references to non-existent upstream relays are detected, the editor prompts you to press `e` to continue fixing the file or `q` to safely exit (preserving disk changes) without loading invalid configurations into runtime.
3. **Export Current Configuration**:
   Reverse-export active or staged rules into a clean, formatted `gateway.conf`:
   ```bash
   # Output directly to stdout
   xray-proxya gateway export

   # Write back into the default gateway.conf file
   xray-proxya gateway export -w

   # Export to a custom file path
   xray-proxya gateway export /etc/xray-proxya/my-gateway.conf
   ```
4. **Compile and Apply**:
   ```bash
   xray-proxya apply
   ```
   `apply` automatically compiles `gateway.conf`, validates outbound targets, port forwards, and interface definitions, commits staged changes, and hot-reloads Xray multi-inbound processes and nftables firewall/policy routing rules.

---

### Approach 2: Interactive CLI Configuration

Set the transparent upstream and LAN interface (uses `tproxy` by default; optional `--mode tun` is available for legacy TUN setups):

```bash
xray-proxya gateway set --relay remote-v029 --lan eth0
# Or select TUN compatibility mode:
# xray-proxya gateway set --mode tun
xray-proxya gateway enable
xray-proxya apply
```

`apply` commits the staged configuration and synchronizes Gateway runtime when a Gateway setting changed. For a `proxy` state it restarts Xray and applies the managed routing and firewall rules.

---

## gateway.conf Syntax Specification And Examples

`gateway.conf` uses a plain-text line-oriented syntax, supporting comments starting with `#`. Directives are organized into five primary categories:

### 1. Zone Definitions (`def zone`)
Define WAN egress and LAN service interfaces, with support for comma-separated interfaces and optional subnet annotations:
```text
# WAN egress interface
def zone wan eth0

# Standard LAN zone (supports multiple interfaces and optional subnet CIDR)
def zone lan eth1, vmbr0 subnet=192.168.1.0/24
```

### 2. Zone Network Isolation (`isolate=true`)
For guest networks (Guest Wi-Fi) or untrusted IoT subnets, specify `isolate=true` on the zone:
```text
# Define an isolated guest zone
def zone guest vmbr1 isolate=true
```
When `isolate=true` is enabled, Xray-Proxya enforces multiple safety defenses in nftables:
- **Block Inter-LAN Forwarding**: Drops forwarding traffic originating from the isolated interface (`vmbr1`) towards any other LAN interface (`eth1`, `vmbr0`), preventing lateral movement.
- **Connection Tracking Allowance**: Allows returning packets and established connections via `ct state established,related accept`.
- **Gateway Host Management Hardening**: Explicitly drops incoming TCP packets destined for port 22 (SSH) on the isolated interface in the input chain, preventing guest devices from probing or accessing gateway administration.
- **Preserve Essential Services and WAN Access**: Gateway DNS resolution and DHCP allocation remain accessible; guest devices can reach the Internet via the WAN interface or assigned relay outbounds without disruption.

### 3. Device and Group Aliases (`def device` / `def group`)
Bind human-readable aliases to Layer-2 MAC addresses, and optionally associate them with a zone and static Layer-3 IP:
```text
# Device definition: def device <name> mac=<mac> [zone=<zone>] [ip=<ip>]
def device tv  mac=52:54:00:84:00:11 zone=lan ip=192.168.1.50
def device pad mac=52:54:00:84:00:12 zone=lan ip=192.168.1.51
def device nas mac=52:54:00:84:00:20 zone=lan ip=192.168.1.200

# Logical group: def group <name> <device1>, <device2>...
def group streaming tv, pad
```

### 4. Outbound Routing Rules
Specify egress traffic targets using `<subject> -> <target>` (or `=>`). The `<target>` may be `direct` (bypass proxy), `block` (drop traffic), or any active upstream relay alias (e.g., `hk-relay`):
```text
# 1. Gateway host local egress
local -> hk-relay

# 2. Zone-level default policy
zone lan -> hk-relay
zone guest -> direct

# 3. Logical group policy (automatically expanded to all group members)
group streaming -> us-relay

# 4. Device alias policy (overrides zone default)
device tv -> us-relay

# 5. Client MAC address rule
mac 52:54:00:84:00:11 -> hk-relay

# 6. Native Layer-3 IP and CIDR subnet rule
ip 192.168.1.95 -> hk-relay
ip 10.0.83.0/24 -> direct

# 7. Physical interface default rule
interface eth1 -> jp-relay
```

### 5. Port Forwarding Rules (`forward`)
Forward incoming WAN traffic to internal LAN hosts or device aliases for NAT traversal and service exposure:
```text
# Syntax: forward [wan:]<wan_port> -> <target>:<target_port> [proto=tcp|udp]

# Forward to a device alias (resolves device's declared IP, e.g. nas -> 192.168.1.200)
forward 8443 -> nas:443 proto=tcp

# Forward to an explicit IP address with UDP (e.g. WireGuard VPN service)
forward 51820 -> 192.168.1.100:51820 proto=udp

# Omit proto (defaults to forwarding both TCP and UDP)
forward 8080 -> 192.168.1.50:80
```
nftables automatically applies DNAT rules in the prerouting chain and allows forwarded flows via `ct status dnat accept`.

---

## Native Layer-3 IP & CIDR Rules

### 1. Why Native L3 Rules Are Necessary
In typical Layer-2 LANs, gateways identify clients primarily by their MAC addresses. However, MAC addresses become unavailable or ambiguous in several common networking topologies:
- **Downstream Layer-3 Switches or VLAN Gateways**: When client traffic crosses a Layer-3 switch to reach Xray-Proxya, the source MAC in the Ethernet frame header is rewritten with the switch's interface MAC.
- **Wireless APs in Router/NAT Mode or Extenders**: Consumer routers or access points operating with NAT or L2 proxying mask client MAC addresses behind a single device MAC.
- **Container and Virtualized Bridge Networks**: Virtual bridge interfaces frequently strip or rewrite Layer-2 headers across virtual boundaries.

In these environments, MAC-based routing rules fail. Xray-Proxya introduces **native Layer-3 IP and CIDR rule evaluation**, matching packet source IP addresses and subnet masks directly in the kernel network stack.

### 2. Configuration and Usage
L3 rules can be defined declaratively in `gateway.conf` or interactively via the CLI:

- **Using `ip` Directives in `gateway.conf`**:
  ```text
  # Route single client IP through Hong Kong relay
  ip 192.168.1.95 -> hk-relay

  # Route entire subnet directly to WAN
  ip 10.0.83.0/24 -> direct

  # IPv6 addresses and subnets are fully supported
  ip fd00:82::/64 -> hk-relay
  ```

- **Using CLI `gateway rule set --ip`**:
  ```bash
  # Set relay target for a single client IP
  xray-proxya gateway rule set --ip 192.168.1.95 --to hk-relay

  # Route an entire CIDR subnet directly on physical interface eth1
  xray-proxya gateway rule set --ip 10.0.83.0/24 --iface eth1 --to direct

  # Block an unauthorized host or subnet
  xray-proxya gateway rule set --ip 192.168.1.199 --to block
  ```

- **List Active and Staged Rules**:
  ```bash
  xray-proxya gateway rule list
  ```

- **Underlying Execution**:
  The system compiles these into nftables `ip saddr` and `ip6 saddr` match sets. The Linux kernel evaluates CIDR prefixes using optimized radix tree lookups with negligible overhead.

## Interception Modes (Mode)

- `tproxy` (default): Primary interception mode. Uses Linux `nftables` socket TProxy redirect and policy routing `table 100 dev lo`. Delivers high performance and supports multi-relay per-MAC and per-interface routing rules.
- `tun` (optional compatibility mode): Intercepts traffic via the `proxya-tun` network device (IP `172.16.255.1/30`, policy route `table 100 dev proxya-tun`). Preserved for compatibility with legacy environments or complex external user infrastructure expecting `proxya-tun`. Routes to the default relay without adjusting client routing rules.

## State Semantics

Gateway transparent operation is root-only. The persistent configuration describes the desired state; `gateway up` and `gateway down` control the currently running state without changing that desired configuration.

- `proxy`: Xray runs with `proxya-tun` when either Local Proxy or LAN Gateway is enabled. Local Proxy captures this host's traffic; LAN Gateway captures traffic arriving from the configured LAN interface.
- `disabled`: Xray runs without a TUN inbound and Xray-Proxya installs no transparent Gateway rules.
- `forward-only`: Xray runs without a TUN inbound. It enables kernel forwarding only; it is not a NAT or direct-internet mode, so LAN reachability requires routing provided outside Xray-Proxya.
- LAN Gateway disabled: Xray-Proxya does not forward or transparently proxy LAN client traffic. A LAN client whose default route still points at this host can lose connectivity; that is intentional.

Bring runtime gateway rules up:

```bash
xray-proxya gateway up
xray-proxya gateway check
```

`gateway up` does the following:

- Restarts the single Xray core with its TUN inbound enabled and waits for `proxya-tun`
- Assigns addresses to `proxya-tun`: `172.16.255.1/30` and `fd00:eea:ff::1/126`
- Enables IPv4/IPv6 forwarding
- Disables IPv4 rp_filter
- Creates policy routing: `fwmark 1 -> table 100`
- Creates nftables rules to send local and LAN TCP/UDP traffic into TUN
- Excludes the LAN subnet, private ranges, upstream proxy server ports, and active SSH listener ports

## Inspect Runtime State

```bash
xray-proxya gateway status
xray-proxya gateway check
ip addr show proxya-tun
ip rule show
ip route show table 100
nft list table inet xray_proxya
```

A healthy setup should show:

- `proxya-tun` exists and has `172.16.255.1/30`
- `ip rule` contains pref `10/50/51/100`
- routing table `100` has a default route to `proxya-tun`
- nft table `inet xray_proxya` exists

## Test Gateway-Local Transparent Proxying

Run on the gateway:

```bash
curl -4 http://api.ipify.org
curl -4 https://api.ipify.org
```

The returned IP should be the upstream server's egress IP.

If DNS fails, check the local DNS service:

```bash
systemctl is-active systemd-resolved
cat /etc/resolv.conf
```

Current `gateway up` does not stop `systemd-resolved`. If an older version stopped it, restore it with:

```bash
systemctl start systemd-resolved
```

You can also bypass DNS for a connectivity test:

```bash
curl -4 --resolve api.ipify.org:80:104.26.12.205 http://api.ipify.org
```

## Test A Neighbor Client Through The Gateway

On the client, temporarily point the default route to the gateway:

```bash
ip route replace default via <gateway-lan-ip> dev <client-lan-iface>
```

Example:

```bash
ip route replace default via 10.50.0.103 dev eth0
```

Test:

```bash
curl -4 http://api.ipify.org
curl -4 https://api.ipify.org
```

The returned IP should be the upstream server's egress IP.

After testing, restore the original default route:

```bash
ip route replace default via <original-router-ip> dev <client-lan-iface>
```

Example:

```bash
ip route replace default via 10.50.0.1 dev eth0
```

## Bring Gateway Runtime Rules Down

```bash
xray-proxya gateway down
xray-proxya gateway check
```

`gateway down` first removes Xray-Proxya-managed nftables, policy routing, and table 100 entries, then restarts the single Xray core without its TUN inbound. The service remains running for non-Gateway features. The persistent `proxy` configuration remains unchanged; run `gateway up` to reactivate it.

To disable gateway mode at the configuration level:

```bash
xray-proxya gateway disable
xray-proxya apply
xray-proxya gateway down
```

## Per-Client Rules, NAT And Isolation Notes

- **Rule precedence follows specificity**: Evaluated in kernel rule matching from highest to lowest specificity:
  1. `Interface + MAC` (`interface + mac`)
  2. `MAC only` (`mac only`)
  3. `Interface + IP` (`interface + ip`)
  4. `IP / CIDR only` (`ip / cidr only`)
  5. `Interface only` (`interface only`)
  6. `Global LAN default`
  A broader `block` rule yields to a more specific non-block rule (for example, a subnet-wide `block` rule yields to a specific IP or MAC rule configured for `direct` or a relay).
- **SSH Lockout Protection**:
  When using `gateway rule set` to add a rule targeting `block`, the command actively inspects the active SSH management session (`SSH_CONNECTION`, `SSH_CLIENT`, current ingress interface, client IP, and client MAC). If the proposed rule would sever the current management session, execution halts with a high-visibility warning, prompting for explicit confirmation (`[N/y]`). Operators using unattended scripts can bypass this with `--force`.
- **Zone Isolation (`isolate=true`)**: Interfaces marked with `isolate=true` are blocked from forwarding traffic to any other internal LAN interface in the forward chain. The input chain drops TCP port 22 (SSH) on the isolated interface, while preserving local DHCP, DNS, and WAN access.
- **Rule targets must be valid**: `apply` rejects rules whose relay was deleted or disabled; a dangling rule found at runtime is dropped (fail-closed) instead of falling back to the default relay.
- **Interface names**: 1-15 characters from letters, digits, `.`, `-`, `_`.
- **Port conflicts**: `apply` checks TProxy ports (base port and one per extra relay) against the API, test, DNS listener, preset and relay internal ports.
- **WAN and NAT**: the WAN interface is resolved once at `apply`; without `--wan` and without a default route a warning is printed and managed NAT is skipped. Managed masquerade lives in an `inet` table and therefore applies to IPv4 and IPv6 (NAT66). LANs are not isolated from each other (forward policy is accept), unless marked with `isolate=true`. Protecting inbound WAN traffic is the operator's responsibility.
- **IPv6**: every non link-local prefix on an interface (for example ULA and GUA) is included in the source guard and bypass rules.

## Troubleshooting

### `gateway check` Reports That `proxya-tun` Is Missing

Check that the Xray service is running:

```bash
systemctl status xray-proxya
journalctl -u xray-proxya --no-pager -n 80
```

`proxya-tun` is created by the Xray TUN inbound. It will not exist if the service is stopped or the active config is invalid.

### `gateway check` Reports That TUN Is Missing Its IPv4 Address

Run:

```bash
xray-proxya gateway up
```

### The Upstream Works But Transparent Proxying Times Out

Check:

```bash
ip addr show proxya-tun
ip route get 1.1.1.1 mark 1
journalctl -u xray-proxya --since "5 min ago" --no-pager -o cat
```

`ip route get ... mark 1` should route traffic into `proxya-tun`, and the source address should be `172.16.255.1`.

### Will SSH Be Captured By The Gateway?

`gateway up` detects active SSH listener ports and excludes them in the nftables output chain. The LAN subnet is also excluded.

## Command Summary

```bash
# Upstream relay management
xray-proxya relay add remote-v029 "vless://..."
xray-proxya relay test remote-v029

# Declarative gateway configuration (Recommended)
xray-proxya init gateway              # Initialize and generate annotated gateway.conf template
xray-proxya gateway edit              # Safely edit gateway.conf with real-time lint validation
xray-proxya gateway export            # Export declarative configuration to stdout
xray-proxya gateway export -w         # Write active/staged configuration back to gateway.conf
xray-proxya apply                     # Compile gateway.conf and hot-reload runtime

# Interactive CLI configuration
xray-proxya gateway set --relay remote-v029 --lan eth0
xray-proxya gateway rule set --ip 192.168.1.95 --to remote-v029
xray-proxya gateway rule set --mac 52:54:00:84:00:11 --to direct
xray-proxya gateway rule list
xray-proxya gateway enable
xray-proxya apply

# Runtime control and diagnostics
xray-proxya gateway up
xray-proxya gateway check
xray-proxya gateway status
xray-proxya gateway down
```
