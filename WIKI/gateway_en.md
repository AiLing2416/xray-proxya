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

## Prepare An Upstream Node

On the upstream server:

```bash
sudo xray-proxya init --role server
sudo xray-proxya service install
sudo xray-proxya service start
```

Export sharing links:

```bash
xray-proxya show --address <server-ip> --all
```

Use a link that passes connectivity tests, for example a Reality Vision TCP link.

## Initialize The Gateway

On the gateway host:

```bash
sudo xray-proxya init --role gateway
```

Find the default egress interface:

```bash
ip -4 route show default
```

The interface after `dev` is the LAN/egress interface, for example:

```text
default via 10.47.0.1 dev eth0 proto static
```

Here the interface is `eth0`.

## Import The Upstream Node

```bash
sudo xray-proxya outbound add remote-v029 "vless://..."
sudo xray-proxya apply
sudo xray-proxya outbound test remote-v029
```

Expected result:

```text
TCP: OK
UDP: OK
DNS: OK
```

If `outbound test` fails, fix the upstream first before enabling transparent gateway rules.

## Configure Transparent Gateway

Set the transparent upstream and LAN interface:

```bash
sudo xray-proxya gateway set --relay remote-v029 --lan eth0
sudo xray-proxya gateway enable
sudo xray-proxya apply
```

`apply` only commits Xray configuration and restarts the service. It no longer modifies system routing, firewall rules, or sysctl values.

Bring runtime gateway rules up:

```bash
sudo xray-proxya gateway up
sudo xray-proxya gateway check
```

`gateway up` does the following:

- Assigns addresses to `proxya-tun`: `172.16.255.1/30` and `fd00:eea:ff::1/126`
- Enables IPv4/IPv6 forwarding
- Disables IPv4 rp_filter
- Creates policy routing: `fwmark 1 -> table 100`
- Creates nftables rules to send local and LAN TCP/UDP traffic into TUN
- Excludes the LAN subnet, private ranges, upstream server IPs, and SSH ports

## Inspect Runtime State

```bash
sudo xray-proxya gateway status
sudo xray-proxya gateway check
ip addr show proxya-tun
ip rule show
ip route show table 100
sudo nft list table inet xray_proxya
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
sudo systemctl start systemd-resolved
```

You can also bypass DNS for a connectivity test:

```bash
curl -4 --resolve api.ipify.org:80:104.26.12.205 http://api.ipify.org
```

## Test A Neighbor Client Through The Gateway

On the client, temporarily point the default route to the gateway:

```bash
sudo ip route replace default via <gateway-lan-ip> dev <client-lan-iface>
```

Example:

```bash
sudo ip route replace default via 10.47.0.103 dev eth0
```

Test:

```bash
curl -4 http://api.ipify.org
curl -4 https://api.ipify.org
```

The returned IP should be the upstream server's egress IP.

After testing, restore the original default route:

```bash
sudo ip route replace default via <original-router-ip> dev <client-lan-iface>
```

Example:

```bash
sudo ip route replace default via 10.47.0.1 dev eth0
```

## Bring Gateway Runtime Rules Down

```bash
sudo xray-proxya gateway down
sudo xray-proxya gateway check
```

`gateway down` only removes nftables, policy routing, and table 100 entries managed by Xray-Proxya. It does not stop the Xray service.

To disable gateway mode at the configuration level:

```bash
sudo xray-proxya gateway disable
sudo xray-proxya apply
sudo xray-proxya gateway down
```

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
sudo xray-proxya gateway up
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
sudo xray-proxya outbound add remote-v029 "vless://..."
sudo xray-proxya outbound test remote-v029

sudo xray-proxya gateway set --relay remote-v029 --lan eth0
sudo xray-proxya gateway enable
sudo xray-proxya apply
sudo xray-proxya gateway up
sudo xray-proxya gateway check

sudo xray-proxya gateway down
```
