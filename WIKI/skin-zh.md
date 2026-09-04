# Authentic Skin v3：真实网盘伪装与主动探测防御架构

## 1. 背景与核心设计理念

在现代网络审查环境中，审查系统和主动探测（Active Probing）工具已经远远超越了基于单一 SNI 或简单 HTTP 404 状态码的识别手段。传统的伪装手段通常存在以下明显短板：
1. **纯 SNI 伪装**：容易被“从机探测”针对 IP 与证书指纹不一致直接标记阻断。
2. **简易静态页或简陋反代**：面对深度的 HTTP 路径扫描、API 端点请求、表单提交等交互探测时会原形毕露。
3. **时序泄露（Timing Discrepancy）**：虚假站点在处理随机账号密码的登录验证时，由于缺少真实的哈希计算过程（如 bcrypt、Argon2 等），通常在几毫秒内即可返回 401/403 响应，而真实系统的验证开销通常在几百毫秒，探测方利用这一显著的时序差异可极高置信度地判定出“蜜罐”或伪装后端。

**Authentic Skin v3** 的核心理念是：**完全可交互、像素级还原、行为不可区分、防时序探测**。系统直接在 Go 进程中内嵌了主流私有云/网盘软件的高保真 Web 副本，并在底层集成了全自动的 Let's Encrypt 证书签发与续期链路。

---

## 2. 支持的伪装载体（Decoy Applications）

Authentic Skin v3 针对以下三款广泛部署的知名企业级/个人网盘系统进行了像素级高保真复刻：

| 伪装类型标识 | 复刻系统及版本 | 特征端点与高保真支持 |
| :--- | :--- | :--- |
| **`nextcloud`** | **Nextcloud Hub (v34)** | • 动态 CSRF Token 生成与 Cookie 轮转<br>• `/login/flow` 握手与 `status.php` 真实状态输出<br>• Capabilities API (`/ocs/v2.php/cloud/capabilities`) 响应<br>• 完整的 Material Design / Vue 前端资源与主题样式 |
| **`filebrowser`** | **File Browser (v2.63)** | • 真实前端打包静态资源与 Webfont<br>• API 探测白名单控制与 `/api/login` 鉴权流程<br>• 对齐官方实例的重定向规范与安全响应头 |
| **`seafile`** | **Seafile Community (v11)** | • 完整 Seahub 登录表单与 CSRF 验证<br>• 真实 404 缺省页与 `/accounts/password/reset/` 重置页<br>• 完整 FontAwesome 图标库与媒体静态资源 |

所有静态资产均通过 Go 1.16+ 的 `embed.FS` 机制直接打包进单个可执行二进制文件中，无需依赖宿主机文件系统中的外部 HTML/CSS 文件夹。

---

## 3. 安全防线与关键机制

### 3.1 时序攻击防御 (Timing-Attack Defense)
为防御基于响应延迟分析的主动探测，Authentic Skin v3 在所有登录认证与凭证提交入口（如 POST 请求）均引入了**拟真延迟注入引擎**：
* 每次接收到非法或探测凭证时，处理流程都会模拟真实的密码哈希计算耗时，施加 **400ms ~ 700ms 的正态随机延迟**。
* 延迟结束后，返回与目标真实软件完全一致的认证错误提示、重定向头或 JSON 响应，使得无论人工或自动化探测工具均无法在时间维度上区分虚假服务与真实实例。

### 3.2 端口分工与 ACME 挑战复用
伪装系统与底层 Xray REALITY / Inbound 协同工作时，采用精细化的端口分工：
1. **Port 80 (HTTP)**：
   * 启动内置的重定向与 ACME 挑战托管服务器。
   * 正常流量被 301 强制跳转至 HTTPS 对应域名。
   * 当 Let's Encrypt 触发 ACME HTTP-01 验证时，在内存中动态劫持 `/.well-known/acme-challenge/*` 并提供实时应答，**实现全自动无感知证书续期**。
2. **Port 443 (外网入站)**：
   * Xray 核心监听外部 443 端口，承接 REALITY / TLS 握手。
   * 正常的代理客户端通过预设秘钥与 UUID 建立代理隧道。
   * 任何未经授权的爬虫、扫描器或主动探测连接，均由 REALITY 的 `dest` 规则 fallback 回退至本地反向代理端口。
3. **本地伪装反代端口 (`skin_port`)**：
   * 默认动态分配一个随机的空闲端口并持久化保存至配置中的 `skin_port`（亦可通过 `--skin-port <port>` 手动自定义）。
   * 仅绑定在 `127.0.0.1:<skin_port>`，对外完全不可见，避免多用户及权限隔离环境下的本地端口冲突。
   * 基于真实域名证书终结 TLS，并分发至对应的高拟真网盘 Web 实例。

### 3.3 证书失效与注销熔断 (Expiration Safety Fuse)
* 预设入站若启用了真实伪装（`--skin`），必须显式绑定拥有有效证书的域名（`--skin-domain`）。
* 系统在后台常驻运行证书健康检查；若绑定的证书被管理员手动注销（`cert remove`）或发生无法自动续签且已过期的异常，系统会自动触发**安全熔断保护**，即刻关闭依赖该域名的预设服务，坚决避免裸露未受保护的连接。

---

## 4. 快速配置指南

> **前置条件**：请确保拥有一个解析至服务器公网 IP 的域名，并已在防火墙/安全组中放通 TCP 80 与 443 端口。

### 步骤 1：申请 Let's Encrypt 证书 (Root 权限)
以 root 身份执行证书申请命令：
```bash
# 自动通过 80 端口完成 HTTP-01 验证并签发 TLS 证书
xray-proxya cert add sea.example.com
```
查看已签发证书状态与有效期：
```bash
xray-proxya cert list
```

### 步骤 2：为预设绑定真实伪装
为服务器角色下的预设（例如 Preset 1：VLESS Reality）配置 Seafile 伪装及已签发证书的域名（系统会自动为其分配并持久化一个随机的本地隔离端口，亦可传入 `--skin-port <port>` 指定）：
```bash
# 配置伪装与域名绑定（写入 STAGING 暂存区）
xray-proxya presets set 1 --skin seafile --skin-domain sea.example.com
```

查看预设配置状态：
```bash
xray-proxya presets list
```
在列表中可清晰查看到 `SKIN` 列已呈现为 `seafile (sea.example.com)`。

### 步骤 3：应用配置生效
通过 `apply` 校验并启动受控服务：
```bash
xray-proxya apply
```
应用生效后，在浏览器中访问 `https://sea.example.com` 即可直接看到高度拟真的 Seafile 登录界面；即使使用错误密码尝试登录，系统也会在逼真的延迟后提示凭证错误，完全阻断主动探测分析。

---

## 5. 运维诊断与排查

* **80 端口冲突**：如果服务器上已运行了 Nginx、Caddy 或 Apache，申请证书或启动服务时会因 80 端口占用报错。建议将此类第三方 Web 服务器停止，或让 Xray-Proxya 独占 80 与 443 端口。
* **环境体检**：使用 `xray-proxya doctor check` 执行自动化体检，可全面扫描端口占用冲突、UDP 连通性以及系统时钟偏差。
