# 内核网络调优设计（临时 `sysctl` 预设）

本文档定义 `xray-proxya` 首版 Root 专用内核网络调优功能的边界、预设和参数表。

## 目标

- 仅支持 Root 使用
- 仅使用 `sysctl` 做临时修改
- 不写入 `/etc/sysctl.conf` 或 `/etc/sysctl.d/*.conf`
- 不做开机持久化
- 遵循“启动后生效，重启失效”的原则
- 仅适配较新的 Linux 内核
- 以保守、主流、可解释的预设为主

## 非目标

- 不做“神秘提速”
- 不直接修改 `systemd`、`ulimit`、`ethtool`、RPS/XPS、IRQ 亲和性
- 不兼容非常旧的内核
- 不主动处理复杂发行版差异
- 不默认修改激进 TCP 参数

## 角色预设

首版仅提供三个预设：

- `gateway`
  适用于透明网关、TUN 网关、局域网出口机
- `relay`
  适用于中转机、多监听、多转发、多用户的项目核心场景
- `server`
  适用于最终出口机或偏服务端角色的节点

## 应用方式

计划中的命令形态：

- `tune show`
- `tune profiles`
- `tune diff <profile>`
- `tune apply <profile>`
- `tune verify [profile]`
- `tune rollback`

其中 `tune apply` 独立存在，不并入通用 `apply`，避免和 Xray 配置提交流程混淆。

## 应用原则

- 每次 `apply` 前先读取当前值
- 仅对当前 profile 涉及的键执行 `sysctl -w`
- 不支持的键标记为 `unsupported` 并跳过
- 写入失败的键标记为 `failed`，最终汇总返回
- 重复应用同一 profile 应保持幂等
- `rollback` 仅回滚本次运行态记录过的旧值
- 若运行态记录丢失，则只能提示用户重启恢复宿主机默认状态

## 公共基础项

以下参数属于三个预设的共同基础：

| 键 | 值 | 说明 |
| --- | --- | --- |
| `net.core.default_qdisc` | `fq` | 配合 BBR 使用的主流队列调度器 |
| `net.ipv4.tcp_congestion_control` | `bbr` | 主流 TCP 拥塞控制算法 |

说明：

- 若 `tcp_available_congestion_control` 中没有 `bbr`，应直接报告不支持
- 首版不额外做模块自动加载逻辑

## `gateway` 预设

定位：

- 稳定转发优先
- 面向透明代理和 LAN 出口
- 参数保持保守，不追求极端吞吐

| 键 | 值 | 说明 |
| --- | --- | --- |
| `net.core.default_qdisc` | `fq` | 公共基础项 |
| `net.ipv4.tcp_congestion_control` | `bbr` | 公共基础项 |
| `net.ipv4.ip_forward` | `1` | 开启 IPv4 转发 |
| `net.ipv6.conf.all.forwarding` | `1` | 开启 IPv6 转发，若系统未启用 IPv6 也可安全跳过 |
| `net.core.somaxconn` | `4096` | 提高监听队列上限 |
| `net.core.netdev_max_backlog` | `16384` | 适度提高收包队列能力 |
| `net.ipv4.tcp_max_syn_backlog` | `8192` | 提高半连接队列容量 |
| `net.netfilter.nf_conntrack_max` | `262144` | 面向网关/NAT/透明转发的保守连接跟踪容量 |

## `relay` 预设

定位：

- 项目核心场景
- 强调中转承载、多连接、多监听、多用户
- 比 `gateway` 更关注连接规模和端口资源

| 键 | 值 | 说明 |
| --- | --- | --- |
| `net.core.default_qdisc` | `fq` | 公共基础项 |
| `net.ipv4.tcp_congestion_control` | `bbr` | 公共基础项 |
| `net.core.somaxconn` | `8192` | 提高监听队列上限 |
| `net.core.netdev_max_backlog` | `32768` | 中转场景下更高的收包队列 |
| `net.ipv4.tcp_max_syn_backlog` | `16384` | 提高半连接承载能力 |
| `net.netfilter.nf_conntrack_max` | `524288` | 中转场景优先保证连接跟踪容量 |
| `net.ipv4.ip_local_port_range` | `10240 65535` | 扩大临时端口可用范围，减轻高连接数下的端口压力 |
| `net.core.rmem_max` | `33554432` | 提高接收缓冲上限 |
| `net.core.wmem_max` | `33554432` | 提高发送缓冲上限 |

## `server` 预设

定位：

- 面向最终出口和服务端角色
- 偏向 TCP 吞吐、交互延迟和稳妥缓冲区
- 比 `relay` 更收敛，不默认过度放大连接跟踪容量

| 键 | 值 | 说明 |
| --- | --- | --- |
| `net.core.default_qdisc` | `fq` | 公共基础项 |
| `net.ipv4.tcp_congestion_control` | `bbr` | 公共基础项 |
| `net.core.somaxconn` | `4096` | 提高监听队列上限 |
| `net.core.netdev_max_backlog` | `16384` | 适度提高收包队列能力 |
| `net.ipv4.tcp_max_syn_backlog` | `8192` | 提高半连接队列容量 |
| `net.netfilter.nf_conntrack_max` | `262144` | 保守连接跟踪容量 |
| `net.core.rmem_max` | `16777216` | 提高接收缓冲上限 |
| `net.core.wmem_max` | `16777216` | 提高发送缓冲上限 |

## 不纳入首版的参数

以下参数暂不进入首版预设：

- `net.ipv4.tcp_tw_reuse`
- `net.ipv4.tcp_fastopen`
- `net.ipv4.tcp_mtu_probing`
- `net.ipv4.tcp_slow_start_after_idle`
- `net.ipv4.tcp_rmem`
- `net.ipv4.tcp_wmem`
- 任意 `vm.*` 参数
- 任意 `fs.*` 参数
- 任意 `ethtool`、网卡 ring buffer、RPS/XPS、IRQ 绑定相关项

原因：

- 这些参数更容易和宿主机策略打架
- 解释成本和验证成本更高
- 超出“保守预设”的功能定位

## 输出建议

`tune show` 建议至少展示：

- 当前内核版本
- 当前可用拥塞控制算法
- 当前使用中的拥塞控制算法
- 当前 `default_qdisc`
- 当前 `ip_forward` 与 IPv6 forwarding 状态
- 当前 `nf_conntrack_max`
- 当前 `somaxconn`
- 当前 `tcp_max_syn_backlog`
- 当前 `ip_local_port_range`
- 当前 `netdev_max_backlog`
- 当前 `rmem_max / wmem_max`
- 当前是否存在 proxya 的运行态调优记录
- 当前记录对应的 profile 名称

`tune verify` 建议输出：

- profile 名称
- 每个目标键的当前值
- 状态：`ok` / `mismatch` / `unsupported` / `failed`

## 运行态记录

虽然本功能不做系统持久化，但仍建议保存一份 proxya 自己的运行态记录，用于：

- `rollback`
- `show`
- `verify`

推荐记录内容：

- 本次 `apply` 的 profile 名称
- 每个键的旧值
- 每个键的目标值
- 每个键的实际写入结果
- 应用时间

此记录属于项目内部运行态元数据，不属于系统永久配置。

