# PathLink ICMP 链路诊断指南

本文档介绍 Xray-Proxya 的 PathLink 机制及其部署与使用方法。

## 1. 概述与设计目的

常规代理协议（如 VLESS、VMess、Shadowsocks 等）工作在传输层，主要承载 TCP 与 UDP 流量，原生不支持网络层 ICMP 报文的转发。因此，在透明网关或客户端直接使用系统 `ping` 或 `traceroute` 检测远程目标时，无法准确反映经由代理出口到达目标主机的实际往返时延（RTT）、网络跳数与路径 MTU。

PathLink 是 Xray-Proxya 提供的私有 ICMP 诊断通道。它通过在服务端运行一个仅监听在本地回环的私有守护进程（`pathd`），并由网关端通过代理隧道向其发送经过 Token 认证的诊断请求，实现由服务端代表网关发起真实的 ICMP 探测。

---

## 2. 架构与工作原理

PathLink 采用客户端-服务端架构：

1. **服务端（Server 角色）**：
   - 运行私有伴生进程 `pathd`（系统服务名称为 `xray-proxya-pathd.service`）。
   - 默认仅监听本地回环地址 `127.0.0.1:2828`，不对外网暴露端口。
   - 接收经过认证的探测请求后，在服务端网络环境中生成原始 ICMP 报文并发送给目标，再将回包数据返回给网关。
2. **网关端（Gateway 角色）**：
   - 将服务端生成的共享 Token 绑定至对应的上游节点（Relay）。
   - 当透明网关使用该节点时，可通过 `path ping`、`path trace`、`path mtu` 命令将探测指令通过代理隧道传送至服务端的 `pathd` 进程。
   - 探测结果反映的是“服务端出口至目标主机”的真实网络指标。

---

## 3. 部署与配置流程

PathLink 涉及网络底层原始套接字操作与 systemd 单元管理，**需要在完整的 root 环境下执行**（推荐使用 `sudo -i`、`su -` 或直接以 root 登录），请勿使用单命令 `sudo xray-proxya ...` 调用。

### 步骤 1：服务端配置

在服务端生成 Token，保存到配置并启动服务：

```bash
# 生成并配置 Pathd Token（写入 STAGING 暂存区）
xray-proxya path set --generate-token

# 提交配置
xray-proxya apply

# 安装并启动 pathd 系统服务
xray-proxya service install
xray-proxya service enable --now xray-proxya-pathd
```

查看服务端 Pathd 运行状态及生成的 Token：

```bash
xray-proxya path status
```

输出中会包含 `Token: <token-string>` 以及监听地址 `127.0.0.1:2828`。请记录该 Token 用于网关端配置。

### 步骤 2：网关端配置

在网关端，将上述 Token 绑定到对应的上游中继节点（例如别名为 `hk-node` 的节点）：

```bash
# 绑定 Token 至指定 relay（可直接使用位置参数）
xray-proxya path set hk-node --token <token-string>

# 提交配置变更
xray-proxya apply
```

查看网关端所有节点的 PathLink 绑定状态：

```bash
xray-proxya path list
```

---

## 4. 命令参考

### 4.1 查看状态与列表

* **`xray-proxya path list`**（别名 `path ls`）
  列出当前配置中所有 Relay 节点的 PathLink 凭据绑定状态、监听地址及是否为当前活动出口。
* **`xray-proxya path status [relay]`**
  在服务端查看 `pathd` 服务单元运行状态；在网关端查看指定节点（或当前活动出口）的连接状态、往返时延及隧道上下文。

### 4.2 链路测试命令

链路测试命令在已启用网关且选中绑定了 PathLink 的 Relay 节点上执行：

* **`xray-proxya path ping <target> [flags]`**
  向目标主机发送 ICMP Echo 请求。
  - `-c, --count <n>`：发送数据包数量（默认 1）。
  - `-i, --interval <duration>`：发包间隔时间（默认 1s）。
  - `-s, --size <n>`：ICMP 负载字节大小（范围 8-1024，默认 8）。
  - `-W, --timeout <duration>`：单次探测超时时间（默认 2s）。
  - `--ttl <n>`：出站 ICMP TTL / Hop Limit（默认 64）。
  - `--json`：以 JSON 格式输出结构化结果（包含 Min/Avg/Max/Mdev 及丢包率统计）。

* **`xray-proxya path trace <target> [flags]`**
  逐跳探测从服务端到达目标主机之间的中间路由节点。
  - `-m, --max-hops <n>`：最大探测跳数（默认 16）。
  - `-W, --timeout <duration>`：每跳探测超时时间（默认 2s）。
  - `--json`：以 JSON 格式输出各跳 IP 与响应耗时。

* **`xray-proxya path mtu <target> [flags]`**
  主动探测从服务端到目标主机之间的路径 MTU（Path MTU）。
  - `--min <n>`：探测 MTU 最小值（默认 IPv4 为 576，IPv6 为 1280）。
  - `--max <n>`：探测 MTU 最大值（默认 2000）。
  - `-W, --timeout <duration>`：单次探测超时时间（默认 2s）。
  - `--json`：以 JSON 格式输出结果。

### 4.3 移除配置

* **`xray-proxya path unset <relay>`**
  从 STAGING 暂存区移除指定 Relay 节点的 PathLink 绑定凭据，执行 `apply` 后生效。

---

## 5. 注意事项与排障

1. **权限约束**：
   PathLink 命令必须在完整的 root 环境（`sudo -i`、`su -` 或直接以 root 登录）下执行，不支持单命令 `sudo xray-proxya ...` 跨用户调用。非 root 环境执行时会提示权限不足并拒绝运行。
2. **服务未启动排查**：
   若网关端提示无法连接到 PathLink，首先在服务端执行 `systemctl status xray-proxya-pathd` 或 `xray-proxya path status`，确认守护进程处于 `active (running)` 状态。
3. **回环地址与网络隔离**：
   `pathd` 仅监听 `127.0.0.1:2828`。它不能也不应该被直接配置为监听公网地址。网关到 `pathd` 的通信完全依赖上游代理协议内置的路由转发。
4. **Token 一致性**：
   网关端配置的 `--token` 必须与服务端 `path.token` 完全一致，否则 `pathd` 会因鉴权失败拒绝建立连接。
