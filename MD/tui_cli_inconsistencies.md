# Xray-Proxya TUI 与 CLI 术语及功能割裂分析

本文档记录了在 `xray-proxya` 项目中，终端交互界面（TUI）与命令行界面（CLI）在设计、术语命名、功能可见性以及底层配置文件结构上存在的割裂与不一致现象。

---

### 1. 出站转发功能命名割裂（Relay vs Outbound）
* **TUI 界面**：侧边栏标签与视图命名为 **`RELAYS`**（如 `RenderRelays`、`fetchRelayDetail`）。
* **CLI 命令行**：对应管理出站代理的命令为 `xray-proxya outbound`（如 `outbound add`、`outbound del`）。
* **JSON 配置文件**：底层结构体中的字段为 `CustomOutbounds`（在 `config.json` 中表现为 `custom_outbounds`）。
* **后果**：用户在界面中配置的是“Relays”，但在通过命令行调试或直接编辑配置文件时却需要使用“outbound”。

### 2. 预设入口命名不一致（Presets vs Presets）
* **TUI 界面**：侧边栏标签及展示页面显示为 **`PRESETS`**（预设）。
* **CLI 命令行**：对应命令为 `xray-proxya presets`（如 `presets list`、`presets set`）。
* **JSON 配置文件**：底层结构体字段为 `Presets`（在 `config.json` 中表现为 `presets`）。
* **后果**：相同的概念在 TUI、CLI 和配置文件中分别使用了三个不同的单词（Presets / presets / presets），增加了新用户的理解成本。

### 3. 状态主页命名不同步（HOME vs Status）
* **TUI 界面**：侧边栏的第一个标签页命名为 **`HOME`**，但代码内部枚举是 `tabStatus`，渲染函数是 `RenderStatus`。
* **CLI 命令行**：查询状态及流量统计的对应命令为 `xray-proxya status`。
* **后果**：用户无法在 CLI 中直观找到“home”命令，而必须使用 `status`。

### 4. 订阅管理功能不对称（TUI 缺失自定义订阅配置）
* **CLI 命令行**：提供了完整的 `sub` 组命令（如 `sub add`、`sub del`、`sub list` 等），允许用户管理独立的出站/客户订阅链接与 UUID 映射。
* **TUI 界面**：完全缺失了对订阅表（`subscriptions`）的管理视图。TUI 中的 `[W]SubURL` 仅用于为 Guest 动态计算出默认的订阅链接，而用户在 CLI 中手动创建的自定义订阅在 TUI 中完全不可见且无法修改。

### 5. 透明网关与 IPv6 模块在 TUI 中的缺位
* **CLI 命令行**：提供了 `gateway` 命令（开启/关闭透明代理网关、配置黑名单）以及 `ipv6` 命令（管理 IPv6 NDP 与轮转池）。
* **TUI 界面**：没有任何关于网关或 IPv6 功能的管理标签页或状态指示。当应用以 Gateway 角色运行时，用户必须退回命令行终端进行所有策略配置。

### 6. 服务管理快捷键与动作命名妥协
* **CLI 命令行**：使用直观的英语单词命令，如 `service start` 与 `service stop`。
* **TUI 界面**：在 `SERVICE` 页面下，由于 `S` 键被启动（Start）占用，停止服务的快捷键被妥协设置为了 **`T`**（Stop），安装/卸载快捷键则分别为 `I`/`U`。
* **后果**：这种快捷键设计降低了用户在键盘交互时的操作直觉。
