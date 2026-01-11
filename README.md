# Xray-Proxya

基于 Xray-core 的自动化代理部署与管理脚本，专注于抗量子安全与受限环境兼容性。

### 核心特性
- **先进协议支持**：默认部署 VLESS-XHTTP-KEM768 (抗量子) 、Reality-TLS 及 VMess-WS。
- **转发管理**：支持从 URL 导入自定义出站 (SS, Socks5, VMess, VLESS, WireGuard)。
- **自动化维护**：完善的定时任务接口，支持自动重启、清理日志及核心更新。
- **性能调优**：内置 `GOMEMLIMIT` 与缓冲区管理，默认使用 Xray 自动管理。
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
- 安装完成后使用 `xray-proxya` 调用管理菜单。
- 推荐使用 `VLESS-XHTTP-KEM768` 实现抗量子安全。
- 若不使用卸载功能就切换版本，可能导致意料之外的后果。

### 协议说明
- **UDP**: 所有 XHTTP 协议均支持 UDP over TCP。
- **安全**: 建议在受限环境下结合 CDN 使用 VMess/VLESS-KEM，或直连使用 Reality。
