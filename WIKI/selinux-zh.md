# Xray-Proxya SELinux（Fedora）配置指南

本文适用于 Fedora Server 等默认启用 SELinux 的系统。以下操作以 `root`
管理的 systemd 服务为前提；请直接使用 root shell，避免以普通用户配置再用
`sudo` 启动服务。

```bash
su -
```

## 工作方式

在 SELinux Enforcing 下，root 并不自动拥有所有权限。Xray-Proxya 将长期
运行的服务放入专用 `xray_proxya_t` 域，并仅允许它：

- 读取和写入自身配置、运行状态及日志；
- 启动同域 Xray 核心；
- 监听 Server 入站端口、连接出站节点；
- 在 Gateway 模式下创建和使用 TUN。

Gateway 的 `nft`、`ip`、`sysctl` 等系统网络改动不由长期服务执行。它们仅在
root 显式运行 `gateway up` 或 `gateway down` 时执行。这样处理外部流量的
长期服务不会长期持有防火墙和策略路由修改权限。

## 安装策略

部署当前版本二进制并完成初始化后，安装项目内置的静态策略：

```bash
xray-proxya selinux install
```

该命令会：

1. 在本机用 Fedora 的 SELinux 参考策略编译项目内置策略；
2. 安装 `xray_proxya` 模块；
3. 标记程序、配置、数据与日志路径；
4. 预创建 systemd 输出日志，避免新配置目录首次启动时出现 `209/STDOUT`。

它**不会**切换全局 Permissive，也不会从历史 `audit.log` 自动生成规则。

若提示缺少工具，请安装：

```bash
dnf install -y selinux-policy-devel policycoreutils-python-utils
```

确认环境：

```bash
getenforce
semodule -lfull | grep xray_proxya
ps -eZ | grep -E 'xray-proxya| xray$'
```

期望 `getenforce` 输出 `Enforcing`，服务进程上下文包含
`system_u:system_r:xray_proxya_t:s0`。

## Server 角色

### 初始化与启动

```bash
xray-proxya init --role server
xray-proxya selinux install
xray-proxya service install
xray-proxya service start
```

修改预设入站、端口或订阅时，先写入暂存配置，再提交：

```bash
xray-proxya presets set 1 --port 443
xray-proxya apply
```

不要直接编辑 `config.json` 或 `config.active.json`。

### 验证

```bash
systemctl is-active xray-proxya
ss -ltnp | grep xray
tail -n 50 /root/.config/xray-proxya/xray.log
ausearch -m AVC,USER_AVC -ts recent -i
```

正常情况下，服务为 `active`，Xray 会监听启用的预设端口和内部 API/Test
端口，且本轮启动没有新增 AVC。

## Gateway 角色

透明 Gateway 只支持 root 管理。先配置上游并通过 `apply` 提交，再启动运行态：

```bash
xray-proxya init --role gateway
xray-proxya selinux install
xray-proxya outbound add remote 'vless://...'
xray-proxya gateway set --relay remote --lan eth0
xray-proxya apply
xray-proxya gateway up
```

`gateway up` 会重启服务以创建 `proxya-tun`，确认设备就绪后再由当前 root
管理命令安装 nftables、策略路由和临时内核网络设置。服务域本身不执行这些
系统工具。

验证透明出口：

```bash
xray-proxya gateway check
xray-proxya gateway test
ip link show proxya-tun
nft list table inet xray_proxya
ip rule show
```

测试结束务必清理：

```bash
xray-proxya gateway down
```

随后 `proxya-tun`、`inet xray_proxya` 和 Gateway 的策略路由都应不存在。

## 排障

先确认策略和进程上下文，再查看本轮 AVC：

```bash
getenforce
systemctl --no-pager --full status xray-proxya
ps -eZ | grep -E 'xray-proxya| xray$'
ausearch -m AVC,USER_AVC -ts recent -i
```

不要通过 `setenforce 0` 后从整份历史审计日志运行 `audit2allow` 来修复问题。
这会混入无关事件并可能放宽错误的域。请保留 Enforcing，记录精确的复现步骤和
对应 AVC，再将经审阅的最小权限加入项目的静态策略。
