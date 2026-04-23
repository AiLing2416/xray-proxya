# Xray-Proxya 透明网关教程

本文说明如何使用 Xray-Proxya 的 TUN 透明网关模式。当前 gateway 只支持 TUN 模式，因此不再需要配置 `--mode`。

## 目标

透明网关用于让一台 Linux 主机承担局域网出口：

- 网关机本机流量可以透明进入代理。
- 局域网内其他设备把默认网关指向这台机器后，也可以透明进入代理。
- Xray 出站流量会打 `mark 255`，避免被再次送回 TUN 形成回环。

## 角色

典型部署包含两台或三台机器：

- 上游服务器：运行 `xray-proxya init --role server`，提供 VLESS / Shadowsocks 等入站。
- Gateway：运行 `xray-proxya init --role gateway`，负责透明代理。
- Client：局域网内测试机，把默认路由临时指向 Gateway。

## 运行原则

不要使用 `sudo xray-proxya ...` 这种跨用户调用方式。原因是 `sudo` 会切换用户、HOME、PATH 和配置目录，容易出现“普通用户安装，root 环境找不到二进制或读到另一份配置”的问题。

推荐二选一：

- 普通用户模式：以同一个普通用户安装和运行，只使用不需要系统网络权限的功能。
- Root 模式：直接登录 root shell，或先执行 `su -` 进入 root 环境，再安装和运行 `xray-proxya`。透明网关需要修改 TUN、nftables、policy routing 和 sysctl，推荐使用 Root 模式。

本文中的命令默认在正确用户的 shell 中直接执行。如果你采用 Root 模式，请先进入 root shell：

```bash
su -
```

## 准备上游节点

在上游服务器上初始化并启动服务：

```bash
xray-proxya init --role server
xray-proxya service install
xray-proxya service start
```

导出分享链接：

```bash
xray-proxya show --address <server-ip> --all
```

优先选择经测试可用的节点，例如 Reality Vision TCP 链接。

## 初始化 Gateway

在网关机上：

```bash
xray-proxya init --role gateway
```

确认默认出口接口：

```bash
ip -4 route show default
```

输出中 `dev` 后面的接口就是 LAN/出口接口，例如：

```text
default via 10.47.0.1 dev eth0 proto static
```

这里接口是 `eth0`。

## 导入上游节点

```bash
xray-proxya outbound add remote-v029 "vless://..."
xray-proxya apply
xray-proxya outbound test remote-v029
```

期望看到：

```text
TCP: OK
UDP: OK
DNS: OK
```

如果 `outbound test` 不通过，不要继续配置透明网关，先修复上游节点。

## 配置透明网关

设置透明上游和 LAN 接口：

```bash
xray-proxya gateway set --relay remote-v029 --lan eth0
xray-proxya gateway enable
xray-proxya apply
```

`apply` 只提交 Xray 配置并重启服务，不再修改系统路由、防火墙或 sysctl。

应用 gateway 运行态规则：

```bash
xray-proxya gateway up
xray-proxya gateway check
```

`gateway up` 会执行：

- 给 `proxya-tun` 配置地址：`172.16.255.1/30`、`fd00:eea:ff::1/126`
- 开启 IPv4/IPv6 转发
- 关闭 IPv4 rp_filter
- 创建 policy routing：`fwmark 1 -> table 100`
- 创建 nftables 规则，把本机和 LAN 的 TCP/UDP 流量送入 TUN
- 排除 LAN 网段、私有地址、上游服务器 IP 和 SSH 端口

## 检查状态

```bash
xray-proxya gateway status
xray-proxya gateway check
ip addr show proxya-tun
ip rule show
ip route show table 100
nft list table inet xray_proxya
```

正常情况下应看到：

- `proxya-tun` 存在并有 `172.16.255.1/30`
- `ip rule` 中有 pref `10/50/51/100`
- table `100` 的默认路由指向 `proxya-tun`
- nft table `inet xray_proxya` 存在

## 测试网关机本机透明代理

在 Gateway 上执行：

```bash
curl -4 http://api.ipify.org
curl -4 https://api.ipify.org
```

返回值应为上游服务器出口 IP。

如果 DNS 失败，先检查本机 DNS 服务：

```bash
systemctl is-active systemd-resolved
cat /etc/resolv.conf
```

当前版本的 `gateway up` 不会停止 `systemd-resolved`。如果系统之前被旧版本停止过，可以恢复：

```bash
systemctl start systemd-resolved
```

也可以绕过 DNS 做连通性测试：

```bash
curl -4 --resolve api.ipify.org:80:104.26.12.205 http://api.ipify.org
```

## 测试邻居设备指定 Gateway

在 Client 上临时把默认网关改为 Gateway：

```bash
ip route replace default via <gateway-lan-ip> dev <client-lan-iface>
```

例如：

```bash
ip route replace default via 10.47.0.103 dev eth0
```

测试：

```bash
curl -4 http://api.ipify.org
curl -4 https://api.ipify.org
```

返回值应为上游服务器出口 IP。

测试完成后恢复默认路由：

```bash
ip route replace default via <original-router-ip> dev <client-lan-iface>
```

例如：

```bash
ip route replace default via 10.47.0.1 dev eth0
```

## 关闭透明网关运行态

```bash
xray-proxya gateway down
xray-proxya gateway check
```

`gateway down` 只清理 Xray-Proxya 管理的 nftables、policy routing 和 table 100，不停止 Xray 服务。

如果要在配置层禁用 gateway：

```bash
xray-proxya gateway disable
xray-proxya apply
xray-proxya gateway down
```

## 常见问题

### `gateway check` 提示 `proxya-tun` 不存在

确认 Xray 服务正在运行：

```bash
systemctl status xray-proxya
journalctl -u xray-proxya --no-pager -n 80
```

`proxya-tun` 由 Xray TUN inbound 创建，服务未启动或配置无效时不会出现。

### `gateway check` 提示 TUN 缺少 IPv4 地址

重新执行：

```bash
xray-proxya gateway up
```

### 上游可用，但透明代理超时

检查：

```bash
ip addr show proxya-tun
ip route get 1.1.1.1 mark 1
journalctl -u xray-proxya --since "5 min ago" --no-pager -o cat
```

`ip route get ... mark 1` 应显示流量进入 `proxya-tun`，并且源地址应是 `172.16.255.1`。

### SSH 连接会不会被透明代理影响

`gateway up` 会探测当前 SSH 监听端口，并在 nftables output 规则中排除这些端口。同时 LAN 网段也会被排除。

## 命令速查

```bash
xray-proxya outbound add remote-v029 "vless://..."
xray-proxya outbound test remote-v029

xray-proxya gateway set --relay remote-v029 --lan eth0
xray-proxya gateway enable
xray-proxya apply
xray-proxya gateway up
xray-proxya gateway check

xray-proxya gateway down
```
