# Xray-Proxya

基于 Xray-core 的自动化代理部署与管理脚本，提供直观的 TUI 菜单与灵活的 CLI 命令行操作。

### 核心特性
- **全协议支持**：预设 VLESS-XHTTP-KEM768 (抗量子)、VLESS-Reality (XHTTP/Vision)、VMess-WS 及 Shadowsocks。
- **命令行管理**：支持通过 `xray-proxya inbound` 快速修改端口、启用/禁用指定入站协议。
- **流量统计监控**：集成实时连接数统计、各入站总流量及自定义出站流量监控，支持 API 级热查询。
- **自定义出站 (转发)**：支持从 URL (VMess, VLESS, SS, Socks5) 导入其它服务器作为中转出口。
- **纯中转模式**：支持一键禁用本机直连出站，仅允许流量通过自定义转发通道。
- **接口绑定 (Interface Binding)**：支持将 Xray 流量绑定至特定网卡（如 VPN 接口），实现透明网关级转发。
- **跨平台兼容**：适配 Debian/Ubuntu (systemd) 及 Alpine Linux (OpenRC)。

### 快速安装

```bash
bash <(curl -sSL https://raw.githubusercontent.com/AiLing2416/xray-proxya/main/install.sh)
```

### 管理工具

#### 1. 交互式菜单 (TUI)
输入 `xray-proxya` 进入管理面板。支持安装、重置密钥、管理链接、配置网络优化等。

#### 2. 命令行操作 (CLI)
支持免交互管理入站监听状态：
```bash
sudo xray-proxya help
```

### 技术细节

| 协议类型 | 传输方式 | 安全特征 | 建议场景 |
| :--- | :--- | :--- | :--- |
| **VLESS** | XHTTP (KEM768) | 抗量子安全 (ML-KEM) | 极高安全性需求 |
| **VLESS** | XHTTP (Reality) | 伪装站 TLS 握手 | 强干扰环境直连 |
| **VLESS** | TCP (Vision) | XTLS-Reality 伪装 | 兼容性与性能均衡 |
| **VMess** | WebSocket | 路径伪装 (WS) | 配合 CDN 使用 |
| **Shadowsocks** | TCP/UDP | Aead 加密 | 基础转发与老旧设备 |

### 接口绑定说明
此功能适用于将 Xray 流量转发至特定的网络接口（如 `wg0`）。使用前请确保目标接口已启动，并在管理菜单中选择 `5. 自定义出站` -> `4. 绑定本地网络接口` 进行配置。

### 注意事项
- **根目录权限**：所有管理操作均需 `root` 权限。
- **配置文件**：环境变量存储于 `/etc/xray-proxya/config.env`，建议定期备份。
- **自动化维护**：脚本内置维护工具 `/usr/local/bin/xray-proxya-maintenance`，可用于定时任务。
