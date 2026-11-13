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

**不要使用单命令 `sudo xray-proxya ...` 跨用户调用**。原因是单命令 `sudo` 会导致 `SUDO_USER`、`HOME`、`PATH` 和配置目录环境不纯净，容易出现“普通用户安装，root 环境找不到二进制或读错另一份配置”的问题。

若需执行特权操作（透明网关需要管理 TUN、nftables、策略路由和 sysctl），推荐使用 **Root 模式**：
- 先通过 `sudo -i`、`su -` 切换到完整的 root 登录环境，或直接以 `root` 用户登录；
- 进入 root 环境后再执行 `xray-proxya` 命令。

本文中的命令默认在完整的 root shell 中执行。若当前为普通用户，请先进入 root 环境：

```bash
# 切换至完整 root 环境（推荐使用 sudo -i 或 su -）
sudo -i
# 或
su -
```

> [!NOTE]
> 涉及网络规则与服务变更的特权操作（如 `gateway up`、`down`、`set`、`apply`）需要 root 环境。所有只读审计类命令（如 `gateway status`、`diff`、`export`、`rule list`、`dns list`、`check`）均已支持普通非特权用户直接运行。

## 准备上游节点

在上游服务器上初始化并启动服务：

```bash
xray-proxya init --role server
xray-proxya service install
xray-proxya service start
```

导出分享链接：

```bash
xray-proxya show --all
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
default via 10.50.0.1 dev eth0 proto static
```

这里接口是 `eth0`。

## 导入上游节点

```bash
xray-proxya relay add remote-v029 "vless://..."
xray-proxya apply
xray-proxya relay test remote-v029
```

期望看到：

```text
TCP: OK
UDP: OK
DNS: OK
```

如果 `relay test` 不通过，不要继续配置透明网关，先修复上游节点。

## 配置透明网关

Xray-Proxya 支持两种透明网关配置方式：
1. **声明式配置文件体系 (`gateway.conf`)**：推荐方式。采用类似 Crontab 的轻量行语法，统一管理接口、区域、设备别名、群组、L3 IP/CIDR 分流及端口映射，直观清晰且便于版本管理与文本备份。
2. **CLI 命令行交互配置 (`gateway set` / `gateway rule`)**：适合快速简单配置或自动化脚本，修改直接写入 Staging 暂存区。

两者底层完全互通，`gateway export -w` 可随时将当前配置导出同步为 `gateway.conf`。

### 方式一：通过 gateway.conf 声明式配置（推荐）

#### 1. 配置文件位置
- **Root 运行环境（网关推荐）**：`/root/.config/xray-proxya/gateway.conf`
- **非特权用户环境**：`~/.config/xray-proxya/gateway.conf`

#### 2. 快速上手工作流
1. **自动生成初始模板**：
   在初始化网关角色时，系统会自动在配置目录生成包含完整英文语法注释和范例的 `gateway.conf`：
   ```bash
   xray-proxya init gateway
   ```
2. **安全交互式编辑**：
   使用内置命令安全编辑配置文件。系统将优先调用环境变量 `$EDITOR` 或 `$VISUAL`（未设置时自动依次探测 `nano`、`vim`、`vi`）：
   ```bash
   xray-proxya gateway edit
   ```
   > [!TIP]
   > `gateway edit` 具备保存退出时的**实时语法 Linting 与编译校验**机制。若存在语法错误或引用了不存在的上游 Relay，退出编辑器时会自动拦截报错，并提示按 `e` 重新编辑或按 `q` 退出（保留磁盘修改），绝不会将非法配置载入运行态。
3. **导出当前配置**：
   可将现有配置或 Staging 暂存规则反向导出为格式化 `gateway.conf` 文本：
   ```bash
   # 直接输出到标准输出 (stdout)
   xray-proxya gateway export

   # 将当前活跃/暂存配置写回默认 gateway.conf 文件
   xray-proxya gateway export -w

   # 导出到指定文件路径
   xray-proxya gateway export /etc/xray-proxya/my-gateway.conf
   ```
4. **编译与生效**：
   ```bash
   xray-proxya apply
   ```
   `apply` 会自动检测并编译 `gateway.conf`，校验所有出站目标、端口映射与接口有效性，提交至 Staging，并热重载 Xray 多入站服务及 nftables 防火墙/策略路由规则。

---

### 方式二：通过 CLI 命令行配置

设置透明上游和 LAN 接口（默认使用主力 `tproxy` 模式；若需兼容旧版 TUN 基础设施，可加 `--mode tun`）：

```bash
xray-proxya gateway set --relay remote-v029 --lan eth0
# 或选择 TUN 兼容模式：
# xray-proxya gateway set --mode tun
xray-proxya gateway enable
xray-proxya apply
```

`apply` 会提交暂存配置；当 Gateway 设置发生变化时，它还会同步 Gateway 运行态。对于 `proxy` 状态，它会重启 Xray 并应用受管路由和防火墙规则。

---

## gateway.conf 语法规范与示例

`gateway.conf` 采用纯文本行语法，支持使用 `#` 添加单行或行尾注释。主要指令涵盖以下五大类别：

### 1. 区域定义 (`def zone`)
用于定义网络出口（WAN）与内网业务接口（LAN），支持绑定多网卡与关联子网：
```text
# WAN 出口接口
def zone wan eth0

# 普通 LAN 接口（支持逗号分隔多网卡，可选标注所属 subnet CIDR）
def zone lan eth1, vmbr0 subnet=192.168.1.0/24
```

### 2. 区域网络隔离 (`isolate=true`)
对于访客网络（Guest Wi-Fi）或不可信的 IoT 设备网段，可为区域指定 `isolate=true` 参数：
```text
# 定义隔离的访客区域
def zone guest vmbr1 isolate=true
```
启用 `isolate=true` 后，Xray-Proxya 将在 nftables 中自动下沉多重安全隔离机制：
- **双向跨网段与同网段防渗透**：在 forward 链中阻断隔离接口（`vmbr1`）流向其他任何 LAN 接口（`eth1`、`vmbr0`）及同接口的三层回环互转（`iifname "vmbr1" oifname "vmbr1" drop`），同时拦截主 LAN 主动向隔离区发起的新连接（`ct state new drop`）；
- **连接追踪放行**：通过 `ct state established,related accept` 放行已建立 WAN 出站连接的关联回包；
- **网关主机管理面严格白名单**：在 input 链针对隔离接口仅放行经 TProxy 劫持的流量（`meta mark 1`）、DHCP（`udp dport { 67, 68, 546, 547 }`）、DNS（`tcp/udp dport 53`，受前置 `block` 规则约束）及基础 ICMP/ICMPv6 邻居发现，随后 `iifname "vmbr1" drop` 封禁访问网关 SSH、`:19999`、Xray API 等所有管理端口；
- **基础网络服务与外网放行**：在未被 `block` 的前提下，访客设备可正常获取 DHCP/DNS 并通过 WAN 或分配的 Relay 出站访问互联网。

### 3. 设备别名与分组 (`def device` / `def group`)
通过易读别名绑定二层 MAC 地址，并支持关联所属区域与三层固定 IP：
```text
# 设备定义：def device <name> mac=<mac> [zone=<zone>] [ip=<ip>]
def device tv  mac=52:54:00:84:00:11 zone=lan ip=192.168.1.50
def device pad mac=52:54:00:84:00:12 zone=lan ip=192.168.1.51
def device nas mac=52:54:00:84:00:20 zone=lan ip=192.168.1.200

# 逻辑分组：def group <name> <device1>, <device2>...
def group streaming tv, pad
```

### 4. 规则流向指令 (Routing Rules)
通过 `<subject> -> <target>`（或 `=>`）指定流量出口。目标 `<target>` 可以为 `direct`（直连出站）、`block`（阻断流量）或已启用的上游 Relay 节点别名（如 `hk-relay`）：
```text
# 1. 网关主机本机出站流向
local -> hk-relay

# 2. 区域默认流向
zone lan -> hk-relay
zone guest -> direct

# 3. 逻辑分组流向（自动展开至组内所有成员）
group streaming -> us-relay

# 4. 指定设备别名流向（覆盖区域默认设置）
device tv -> us-relay

# 5. 指定客户端 MAC 地址规则
mac 52:54:00:84:00:11 -> hk-relay

# 6. 原生三层 IP 与 CIDR 子网规则
ip 192.168.1.95 -> hk-relay
ip 10.0.83.0/24 -> direct

# 7. 指定物理接口默认规则
interface eth1 -> jp-relay
```

### 5. 端口映射与 NAT 转发 (`forward`)
用于将 WAN 口入站端口映射至局域网内特定主机或设备别名，满足内网穿透与服务暴露需求：
```text
# 语法：forward [wan:]<wan_port> -> <target>:<target_port> [proto=tcp|udp]

# 映射到设备别名（自动解析设备绑定的 IP 地址，例如 nas -> 192.168.1.200）
forward 8443 -> nas:443 proto=tcp

# 映射到指定 IP 地址（指定 UDP 协议，例如 WireGuard 服务）
forward 51820 -> 192.168.1.100:51820 proto=udp

# 缺省 proto 选项（默认同时映射 TCP 与 UDP）
forward 8080 -> 192.168.1.50:80
```
配置端口映射后，nftables 会自动在 prerouting 链应用 DNAT 规则，并在 forward 链放行 `ct status dnat accept`。

### 6. DNS 与局域网静态解析
支持在 `gateway.conf` 中声明内置 DNS 服务参数、上游解析节点与局域网静态 A/AAAA 记录：
```text
# --- 全局 DNS 参数设置 ---
# 监听端口（提供给局域网客户端使用，缺省时 LAN 请求自动经 TProxy 拦截至代理内核）
set dns_listen :53

# 查询策略 (UseIP: IPv4+IPv6 双栈, 也可选 UseIPv4 / UseIPv6)
set dns_strategy UseIP

# 上游 DNS 列表 (支持标准 IP、DoH、DoT，按顺序匹配回退)
set dns_servers 223.5.5.5, 1.1.1.1, https://1.1.1.1/dns-query, tls://8.8.8.8:853

# 直连上游 DNS IP (防止 DNS 查询自身进入代理死循环)
set bypass_dns 223.5.5.5, 1.1.1.1, 8.8.8.8

# --- 局域网静态解析记录 (A/AAAA) ---
dns router.lan -> 10.0.82.1
dns gateway.local -> 10.0.82.1, fd00:82::1
dns nas.lan -> 10.0.82.50, fd00:82::50
```
此外，DNS 劫持行为具备如下安全保障：
- `:53` 端口劫持位于 LAN 源网段守卫之前，确保 IPv6 链路本地地址（`fe80::`）发起的 DNS 请求也能正常截获；
- 匹配指定 Relay 规则（`mac`/`ip`/`interface -> <relay>`）的客户端，其 DNS 请求自动导向对应 Relay 的 TProxy 端口解析；
- 匹配 `direct` 规则的客户端，其 `:53` DNS 流量仍经所属区域默认 Relay（或全局默认 Relay）解析，防止本地运营商 DNS 污染；
- 匹配 `block` 规则的客户端会在 `block_guard` 阶段（早于 `:53` 劫持）被直接丢弃，既禁出站也禁 DNS 解析；
- `local -> <relay>` 绑定宿主机独立 `local_relay`，使本机通过 `lo` 的出站流量可与 `zone lan -> <relay>` 独立分流。

---

## 原生三层 IP/CIDR 规则下沉

### 1. 为什么需要原生 L3 规则？
在经典二层局域网中，网关主要依赖终端的 MAC 地址识别设备。但在以下实际组网拓扑中，二层 MAC 会因转发节点的解封装而丢失：
- **下挂三层交换机或 VLAN 汇聚网关**：终端经由三层路由到达网关时，以太网帧头的源 MAC 会被三层交换机替换为自身接口 MAC；
- **下挂路由/NAT 模式无线 AP 或中继器**：部分商用 AP 或家庭路由器将无线客户端统一做 SNAT 或二层代理，使得网关看到的 MAC 全部同质化；
- **容器与虚拟化网桥网络**：虚拟网络设备在跨 host 转发时通常剥离或重写原始 MAC。

此时，基于 MAC 的分流规则无法准确识别具体设备或网段。Xray-Proxya 引入**原生三层 IP 与 CIDR 规则下沉**，直接在内核 IP 层执行源地址与子网匹配。

### 2. 配置与使用方式
既可以在 `gateway.conf` 中声明，也可以通过 CLI 命令行即时操作：

- **在 `gateway.conf` 中使用 `ip` 指令**：
  ```text
  # 单个终端 IP 走香港节点
  ip 192.168.1.95 -> hk-relay

  # 整个子网段直连
  ip 10.0.83.0/24 -> direct

  # IPv6 地址或网段同样支持
  ip fd00:82::/64 -> hk-relay
  ```

- **通过 CLI 命令 `gateway rule set --ip` 操作**：
  ```bash
  # 为指定 IP 设定出口 Relay
  xray-proxya gateway rule set --ip 192.168.1.95 --to hk-relay

  # 为整段子网设定直连，并限定来自 eth1 物理网卡
  xray-proxya gateway rule set --ip 10.0.83.0/24 --iface eth1 --to direct

  # 阻断特定恶意 IP 或未授权网段
  xray-proxya gateway rule set --ip 192.168.1.199 --to block
  ```

- **查看规则列表**：
  ```bash
  xray-proxya gateway rule list
  ```

- **底层执行机制**：
  系统在 nftables 中动态生成针对 `ip saddr` 或 `ip6 saddr` 的匹配规则，高效利用内核哈希树结构完成 CIDR 前缀匹配，性能开销极低。

## 拦截模式说明 (Mode)

- `tproxy`（默认）：主力拦截模式。基于 Linux `nftables`（`table inet xray_proxya`）原子规则替换与策略路由 `table 100 dev lo` 进行透明重定向，性能优异且支持完整的 7 级精度客户端分流规则、多 Relay 分发、`local_relay` 与多区域默认出口。
- `tun`（独立虚拟网卡兼容模式）：仅启用 `proxya-tun` 虚拟网卡（IP `172.16.255.1/30`、`fd00:eea:ff::1/126`），不配置 `table 100` 策略路由与 `nftables` 客户端分流规则，适用于由外部基础设施自行接管虚拟网卡路由的兼容场景。

## 状态语义

透明 Gateway 只支持 root 运行。持久配置描述期望状态；`gateway up` 和 `gateway down` 只控制当前运行态，不会改变该期望配置。

- `proxy`：在默认 `tproxy` 模式下原子下发 `table inet xray_proxya`，由本机代理（需配置有效本地 Relay）与/或 LAN 网关通过 TProxy 监听口透明代理流量。当 Xray 启动或自检失败且 `fail_open=false`（默认）时，系统启用/保留 **Fail-Closed 保护表** 丢弃受代理保护的公网出站流量以防泄露真实 IP（同时保留 SSH 管理端口、`block` 与 `isolate` 防护）；仅在显式配置 `set fail_open true` 时才会降级为放行直连。
- `disabled`：Xray 不启用网关入站，Xray-Proxya 清理所有受管网关规则。
- `forward-only`：Xray 不启用 TProxy/TUN 网关入站，仅开启内核转发并下发受管 LAN→WAN NAT 伪装（除非配置 `set nat false`）、`block` 规则与 `isolate=true` 隔离规则。
- 关闭 LAN 网关：Xray-Proxya 不再转发或透明代理 LAN 客户端流量。默认路由仍指向本机的 LAN 客户端可能断网；这是预期行为。

应用 gateway 运行态规则：

```bash
xray-proxya gateway up
xray-proxya gateway check
```

`gateway up` 会执行（默认 `tproxy` 模式）：

- 在不提前清空已有防火墙规则的前提下重启 Xray 服务（消除空白窗）
- 开启 IPv4/IPv6 转发并关闭相关接口的 `rp_filter` / `send_redirects`
- 配置策略路由：`fwmark 1 -> table 100 (local dev lo)`
- 通过 `nft -f` 原子替换 `table inet xray_proxya`，统一部署 `block_guard`、DNS 劫持、客户端分流、端口映射（含 `ct status dnat return` 与协议族显式 DNAT）与 NAT 伪装
- 自动旁路 LAN 全子网、私有网段（RFC1918/ULA）、上游代理节点端点及 SSH 监听端口（22、`SSH_CONNECTION` 与 `/etc/ssh/sshd_config` / `sshd_config.d/*.conf`）

## 检查状态

```bash
xray-proxya gateway status
xray-proxya gateway check
ip addr show proxya-tun
ip rule show
ip route show table 100
nft list table inet xray_proxya
```

正常情况下（`tproxy` 模式）应看到：

- `ip rule` 中包含 `fwmark 0x1 lookup 100`、`fwmark 0xff lookup main` 及 LAN 子网 `pref 10010+`
- table `100` 包含 `local default dev lo`
- nft table `inet xray_proxya` 存在（默认不创建 `proxya-tun`，仅 `mode = tun` 时创建虚拟网卡）

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
ip route replace default via 10.50.0.103 dev eth0
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
ip route replace default via 10.50.0.1 dev eth0
```

## 关闭透明网关运行态

```bash
xray-proxya gateway down
xray-proxya gateway check
```

`gateway down` 会先清理 Xray-Proxya 管理的 nftables、policy routing 和 table 100，然后重启单一 Xray 核心为无 TUN 入站模式。服务会继续运行以支持非 Gateway 功能；持久的 `proxy` 配置保持不变，运行 `gateway up` 可再次启用它。

如果要在配置层禁用 gateway：

```bash
xray-proxya gateway disable
xray-proxya apply
xray-proxya gateway down
```

## 按客户端规则、NAT 与隔离说明

- **规则优先级按 7 级特异性严格排序**：内核规则匹配遵循特异性从高到低原则：
  1. `接口 + MAC + IP` (`interface + mac + ip`)
  2. `接口 + MAC` (`interface + mac`)
  3. `接口 + IP` (`interface + ip`)
  4. `MAC + IP` (`mac + ip`)
  5. `独立 MAC` (`mac only`)
  6. `独立 IP / CIDR`（长前缀优先：`/32` 或 `/128` > `/28` > `/24`）
  7. `独立接口` (`interface only`)
  同精度下 `block` 优先。所有规则（含 `block_guard` 放行例外）同时保护 IPv4 与 IPv6，避免单协议族取反导致 IPv6 漏出。
- **管理员 SSH 防锁死保护 (Lockout Protection)**：
  当通过 `gateway rule set` 尝试添加包含 `block` 目标的规则时，系统会自动探测当前活跃的 SSH 管理会话（分析 `SSH_CONNECTION`、`SSH_CLIENT`、当前管理网卡接口、客户端 IP 及 MAC）。若检测到该规则可能切断当前连接导致无法管理，系统会立即拦截并弹出红色高危警示，提示锁死风险，要求管理员显式确认 `[N/y]`；若在自动化运维脚本中确认需要操作，可传入 `--force` 强制应用。
- **访客区域隔离 (`isolate=true`)**：被标记为 isolated 的区域在 forward 链双向阻断跨区域及同接口三层互转，并在 input 链采用严格白名单（仅放行 TProxy 标记流量、DHCP、DNS 与基础 ICMP/ND）后丢弃其余所有管理端口访问。
- **规则目标必须有效**：规则指向的 relay 被删除或禁用时，`apply` 会拒绝；运行时遗留的失效规则会被丢弃（fail-closed），不会回退到默认 relay。
- **接口名规范**：仅允许 1-15 个字符的字母、数字、`.`、`-`、`_`。
- **端口冲突**：`apply` 会检查 TProxy 端口（基础端口与每个额外 relay 端口，含 `local_relay` 与 `zone -> relay`）是否与 API、测试、DNS 监听、预设、relay 内部端口冲突。
- **WAN 与 NAT**：WAN 接口在 `apply` 时解析一次；未配置 `--wan` 且检测不到默认路由时会打印警告并跳过受管 NAT。受管 NAT 的 masquerade 使用 `inet` 表，同时作用于 IPv4 与 IPv6（即 NAT66）。不同普通 LAN 之间默认不做隔离（forward 策略为 accept），除非接口被标记为 `isolate=true`。保护 WAN 侧入站由用户自行负责。
- **IPv6**：接口上的全部 IPv4 与非链路本地 IPv6 前缀（如 ULA 与 GUA）都会纳入多子网源地址守卫与旁路；若启用代理的 LAN 接口没有全局/ULA IPv6 地址，将丢弃该接口上的非链路本地 IPv6 转发以防止直连泄漏。

## 常见问题

### 1. 如何确认 TProxy 运行态是否正常工作？

在默认的 TProxy 模式下，系统不创建 `proxya-tun` 网卡，流量直接由内核 nftables mangle 表透明分流：

```bash
# 1. 检查 nftables 规则是否载入
nft list table inet xray_proxya

# 2. 检查策略路由规则与 table 101
ip rule show
ip route show table 101

# 3. 检查 Xray TProxy 端口是否处于监听状态
ss -tulpn | grep 53905

# 4. 查看网关健康诊断
xray-proxya gateway check
```

### 2. 使用 TUN 兼容模式时提示 `proxya-tun` 异常

若在 `gateway.conf` 中配置了 `set mode tun`：
- 确认 Xray 服务正常启动且加载了 TUN 配置：`xray-proxya logs`
- 若提示设备或 IP 丢失，重新执行：`xray-proxya gateway up`

### 3. 上游可用，但透明代理客户端请求超时

检查：
```bash
# 检查网关机器针对上游的连通性
xray-proxya relay test <upstream-relay>

# 观察是否有针对本地 SSH 或私有网段的误拦截
xray-proxya gateway status
xray-proxya logs --lines 50
```

### 4. SSH 连接会不会被透明代理影响

`gateway up` 会自动探测当前活跃的 SSH 管理端口与连接会话，并在 nftables prerouting/output 链中对 SSH 端口及局域网段进行显式豁免；添加危险规则时系统具备交互式防锁死拦截。

## 命令速查

```bash
# 上游节点管理
xray-proxya relay add remote-v029 "vless://..."
xray-proxya relay test remote-v029

# 声明式网关配置（推荐）
xray-proxya init gateway              # 初始化并生成带有注释的 gateway.conf 模板
xray-proxya gateway edit              # 安全交互式编辑 gateway.conf（保存时实时 Lint 校验）
xray-proxya gateway export            # 导出声明式配置至控制台 (stdout)
xray-proxya gateway export -w         # 将当前活跃/暂存配置写回 gateway.conf 文件
xray-proxya apply                     # 自动编译 gateway.conf 并热重载运行态

# DNS 与静态解析管理 (STAGING)
xray-proxya gateway dns set --servers 223.5.5.5,1.1.1.1 --listen :53
xray-proxya gateway dns record set nas.lan 10.0.82.50 fd00:82::50
xray-proxya gateway dns record list
xray-proxya gateway dns record del nas.lan
xray-proxya gateway dns status

# CLI 命令行交互配置
xray-proxya gateway set --relay remote-v029 --lan eth0
xray-proxya gateway rule set --ip 192.168.1.95 --to remote-v029
xray-proxya gateway rule set --mac 52:54:00:84:00:11 --to direct
xray-proxya gateway rule list
xray-proxya gateway enable
xray-proxya apply

# 运行态控制与诊断 (status/check 支持非特权执行)
xray-proxya gateway up
xray-proxya gateway check
xray-proxya gateway status
xray-proxya gateway down
```
