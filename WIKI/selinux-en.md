# Xray-Proxya SELinux (Fedora) Configuration Guide

This document applies to Linux distributions with SELinux enabled by default, such as Fedora Server. The operations below assume systemd services managed by `root`. Always use a direct root shell; avoid configuring under an unprivileged user and then starting services via `sudo`.

```bash
su -
```

## How It Works

Under SELinux Enforcing mode, root does not automatically possess all privileges. Xray-Proxya places its long-running background service into a dedicated `xray_proxya_t` domain, strictly granting it only permission to:

- Read and write its own configuration, runtime state, and logs;
- Spawn the Xray core binary running within the same domain;
- Bind to Server inbound ports and establish outbound relay connections;
- Create and manage the TUN device under Gateway mode.

System network modifications for the Gateway (`nft`, `ip`, `sysctl`, etc.) are intentionally not executed by the long-running proxy service. When root explicitly executes `gateway up`, `gateway down`, or synchronizes the gateway via `apply`, the CLI re-executes briefly into the `xray_proxya_gateway_t` management domain, which exits immediately upon completion. This domain is strictly confined to reading the project's internal state, restarting the designated `xray-proxya` systemd unit, and invoking specific networking binaries. It cannot function as a long-running proxy service, nor can it modify systemd unit files. This architecture guarantees that the long-running daemon handling external network traffic never permanently holds firewall or policy routing alteration capabilities.

## Installing the Policy

After deploying the current binary and completing initialization, install the project's built-in static SELinux policy:

```bash
xray-proxya doctor selinux
```

This command will:

1. Compile the built-in policy module locally against Fedora's SELinux reference policy headers;
2. Install the `xray_proxya` policy module;
3. Label all application binaries, configuration files, runtime data, and log directories;
4. Pre-create systemd output log targets to prevent `209/STDOUT` execution errors on fresh configuration directories.

It will **not** switch the global SELinux state to Permissive, nor will it auto-generate rules from historical `audit.log` files.

If prerequisite compilation tools are missing, install them:

```bash
dnf install -y selinux-policy-devel policycoreutils-python-utils
```

Verify the environment:

```bash
getenforce
semodule -lfull | grep xray_proxya
ps -eZ | grep -E 'xray-proxya| xray$'
```

Expected output: `getenforce` prints `Enforcing`, and service process contexts match `system_u:system_r:xray_proxya_t:s0`.

## Server Role

### Initialization and Startup

```bash
xray-proxya init --role server
xray-proxya doctor selinux
xray-proxya service install
xray-proxya service start
```

When modifying inbound presets, ports, or subscriptions, make changes to the staging configuration first, then commit them:

```bash
xray-proxya presets set 1 --port 443
xray-proxya apply
```

Never directly edit `config.json` or `config.active.json`.

### Verification

```bash
systemctl is-active xray-proxya
ss -ltnp | grep xray
tail -n 50 /root/.config/xray-proxya/xray.log
ausearch -m AVC,USER_AVC -ts recent -i
```

Under normal operation, the service is `active`, Xray listens on enabled preset ports and internal API/Test ports, and no new AVC denial messages are logged during startup.

## Gateway Role

The transparent Gateway is strictly root-managed. Configure your upstream relay and commit via `apply` before bringing up the gateway runtime:

```bash
xray-proxya init --role gateway
xray-proxya doctor selinux
xray-proxya outbound add remote 'vless://...'
xray-proxya gateway set --relay remote --lan eth0
xray-proxya apply
xray-proxya gateway up
```

`gateway up` runs within the short-lived `xray_proxya_gateway_t` management domain, restarting the service to create `proxya-tun`, confirming device readiness, and then configuring nftables rules, policy routing, and runtime sysctl parameters. The main service domain does not execute these system utilities; manual `runcon` invocation is not required.

Verify transparent forwarding:

```bash
xray-proxya gateway check
xray-proxya gateway test
ip link show proxya-tun
nft list table inet xray_proxya
ip rule show
```

Always clean up after testing:

```bash
xray-proxya gateway down
```

After tearing down, `proxya-tun`, the `inet xray_proxya` nftables table, and the gateway policy routing rules should no longer exist.

## Troubleshooting

First check policy installation and process contexts, then inspect recent AVC denials:

```bash
getenforce
systemctl --no-pager --full status xray-proxya
ps -eZ | grep -E 'xray-proxya| xray$'
ausearch -m AVC,USER_AVC -ts recent -i
```

Never attempt to fix issues by running `setenforce 0` and blindly generating policy rules from the entire historical audit log with `audit2allow`. That approach captures unrelated events and can excessively broaden incorrect domains. Keep the system in Enforcing mode, record the exact reproduction steps along with the specific AVC denials, and add reviewed, least-privilege permissions to the project's static policy.
