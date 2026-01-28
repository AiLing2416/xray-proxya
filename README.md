# Xray-Proxya

基于 Xray-core 的自动化代理部署与管理脚本，专注于抗量子安全与受限环境兼容性。

### 核心特性
- **先进协议支持**：默认部署 VLESS-XHTTP-KEM768 (抗量子) 、Reality-TLS 及 VMess-WS。
- **转发管理**：支持从 URL 导入自定义出站 (SS, Socks5, VMess, VLESS, WireGuard)。
- **自动化维护**：完善的定时任务接口，支持自动重启、清理日志及核心更新。
- **配置热更新**：手动重启服务时自动刷新配置，无需重新安装。
- **纯中转模式**：一键切换禁用本机出站，仅保留自定义转发通道。
- **跨平台支持**：支持 Debian/Ubuntu 及 Alpine Linux (OpenRC)。

### 快速安装

**标准版** (功能完整)：
```bash
bash <(curl -sSL https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/install.sh)
```

**轻量版** (低内存适配)：
```bash
bash <(curl -sSL https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/lite_install.sh)
```

### 使用指南
- 安装完成后使用 `sudo xray-proxya` 调用管理菜单。
- 推荐使用 `VLESS-XHTTP-KEM768` 实现抗量子安全。
- 若不使用卸载功能就切换版本，可能导致意料之外的后果。

### 协议说明
- **UDP**: 所有 XHTTP 协议均支持 UDP over TCP。
- **安全**: 建议在受限环境下结合 CDN 使用 VMess/VLESS-KEM，或直连使用 Reality。

### 接口绑定 (Interface Binding)

此功能允许 Xray 通过特定的本地网络接口（如 `wg0`, `tun0`）发送流量，适用于将 Xray 作为 VPN 网关的场景。

#### 1. 配置 WireGuard (或其它 VPN)
在使用接口绑定前，请确保您的 VPN 接口已启动且能够正常访问互联网。
**注意**：为了防止路由循环，建议在 WireGuard 配置中禁用自动生成默认路由：
```ini
[Interface]
# 示例配置
PrivateKey = <YOUR_PRIVATE_KEY>
Address = 10.0.0.2/24
DNS = 1.1.1.1
# 关键：禁用自动全局路由
Table = off

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <SERVER_IP>:51820
AllowedIPs = 0.0.0.0/0
```

#### 2. 在 Xray-Proxya 中设置
1. 进入菜单：`5. 自定义出站` -> `4. 绑定本地网络接口 (Interface Bind)`。
2. **接口名**：输入您的网卡名。
3. **绑定 IP**：输入该网卡上的本地 IP。

#### 3. 常见问题排查
- **无法连接**：请检查 VPN 服务端是否开启了 **IP 转发** 与 **NAT**。
- **权限问题**：接口绑定需要 `CAP_NET_ADMIN` 权限，脚本已自动为 Xray 服务配置该能力。
- **RP Filter**：如果还是不通，可以尝试关闭系统的反向路径过滤：
  ```bash
  sysctl -w net.ipv4.conf.all.rp_filter=0
  ```
