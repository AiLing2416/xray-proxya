# Xray-Proxya Server 模式快速入门 (v0.2.1)

本指南旨在帮助用户通过简单的命令行指令，快速搭建起一个具备多租户管理、流量配额限制及 Reality 安全加固的高性能 Xray 服务端。

---

## 1. 快速安装

下载对应架构的二进制文件并赋予执行权限：
```bash
# 以 Amd64 架构为例
wget https://github.com/AiLing2416/xray-proxya/releases/latest/download/xray-proxya-linux-amd64 -O xray-proxya
chmod +x xray-proxya
```

---

## 2. 初始化服务端

将当前机器初始化为 **落地服务器 (Landing Server)**。该命令会自动生成安全的 UUID、Reality 密钥对以及内部通信端口。

```bash
./xray-proxya init --role server
```
*注意：如果需要重置已有配置，请添加 `--force` 参数。*

---

## 3. 租户管理 (Guests)

Xray-Proxya 支持创建多个独立租户，并为每个租户设置独立的流量限额。

### 添加新用户
```bash
./xray-proxya guests add test_user
```

### 设置流量配额 (例如 100GB)
```bash
./xray-proxya guests set test_user --quota 100
```

### 查看用户列表及用量
```bash
./xray-proxya guests list
```

---

## 4. 启动服务

建议将程序安装为系统服务（systemd），以确保其在后台持续运行并自动执行流量配额监控。

```bash
# 1. 安装系统服务 (需要 Root 权限)
sudo ./xray-proxya service install

# 2. 应用配置并生效
sudo ./xray-proxya apply

# 3. 启动服务
sudo ./xray-proxya service start
```

---

## 5. 获取分享链接

为用户生成订阅或导入链接。Xray-Proxya 会自动提供多种协议组合（如 Reality-TCP, XHTTP, VMess-WS 等）。

```bash
# 显示管理员主链接
./xray-proxya show

# 显示特定租户的链接
./xray-proxya show --user test_user
```
*直接将输出的 `vless://...` 或 `vmess://...` 复制到客户端软件即可使用。*

---

## 6. 维护与状态监控

实时查看服务端运行状态及流量统计。

```bash
./xray-proxya status
```

### 临时内核调优

如果当前机器承担最终出口或中转工作，可以使用 Root 专用的 `tune` 子命令做临时 `sysctl` 调优。该功能只修改当前运行期的内核参数，不写入系统持久化配置。

```bash
sudo ./xray-proxya tune profiles
sudo ./xray-proxya tune diff server
sudo ./xray-proxya tune apply server
sudo ./xray-proxya tune verify server
sudo ./xray-proxya tune rollback
```

说明：
- `server` 适合最终出口机。
- `relay` 适合中转机场景。
- `gateway` 适合透明网关。
- 所有调优都遵循“启动后生效，重启失效”的原则。

### 每月用量重置
在月初重置所有用户的流量统计：
```bash
./xray-proxya maintain reset-all-usage
```

---

## 7. 典型操作流程示例

只需 30 秒，即可为朋友开通一个专属账号：

```bash
./xray-proxya init --role server     # 初始化
./xray-proxya guests add friend_name  # 开户
./xray-proxya guests set friend_name --quota 50 # 设配额
sudo ./xray-proxya apply             # 生效
sudo ./xray-proxya service start     # 运行
./xray-proxya show --user friend_name # 拿链接
```

---
*关于透明网关 (Gateway) 等进阶功能，请参考 WIKI_ZH.md 文档。*
