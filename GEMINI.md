# Xray-Proxya 开发与安全准则 (v0.2.8)

本项目已完成核心功能加固，当前版本为 v0.2.8。所有开发必须遵循以下准则。

## 1. 核心开发原则 (Core Mandates)

*   **分阶段配置系统 (Staging System)**：
    *   除 `init` 外，所有修改配置的命令均操作 `.staging` 暂存文件。
    *   必须通过 `apply` 命令进行两阶段验证（静态校验 + 随机端口隔离运行测试）后方可合并至正式配置。
*   **权限对等可见性 (Permission Visibility)**：
    *   **Root-Only 隔离**：所有涉及系统级修改（nftables, ip route, 转发）的 `gateway` 命令，其**状态查看与配置修改均仅限 Root 权限**，防止普通用户探测网络拓扑或黑名单泄露。
    *   **服务分权**：Root 运行则管理 Systemd/OpenRC 单元；非 Root 运行则使用 `nohup` 模式及 `xray.pid` 追踪。
*   **安全加固 (Security Hardening)**：
    *   **极简权限**：所有配置文件（`.json`）、暂存文件（`.staging`）、日志（`.log`）及 PID 文件必须强制使用 `0600` 权限。配置目录权限为 `0700`。
    *   **输入洗净**：严禁在 `exec.Command` 或规则拼接中直接使用未经校验的变量。网卡名、别名（Alias）必须通过正则校验（仅限字母、数字、下划线、连字符、点）。
    *   **回环保护**：所有出站（Outbounds）在 Gateway 模式下必须强制打上 `mark 255` 标签，以绕过透明网关拦截。
    *   **身份路由**：使用 `email` (User) 进行流量染色。`service-user` 流量强制走本地直连（防止套娃），`tun-in` 流量强制走 Relay 转发。
    *   **进程身份校验**：通过 `/proc/[pid]/exe` 校验进程身份，防止 PID 循环导致的误杀。

## 2. 核心功能逻辑

*   **透明网关 (Gateway)**：
    *   **纯 TUN DNS 劫持**：使用 `nftables mangle` 规则给 53 端口流量打上 `Mark 1` 标签，配合最高优先级策略路由将其塞入 `proxya-tun`，由 Xray 嗅探并解析。
    *   **原子化规则**：使用 `nft -f` 原子化应用规则文件，拒绝逐条下发，确保防火墙状态一致。
    *   **端口同步**：TProxy 监听端口自动同步 `TestInbound` 配置，消除配置与规则脱节。
    *   **SSH 防失联**：SyncFirewall 会自动探测并排除系统所有活动中的 SSH 监听端口。
*   **多租户管理 (Guests)**：
    *   支持独立流量配额与月度重置。
    *   `maintainQuota` 循环每 5 秒同步流量统计并执行 API/配置双重熔断。
*   **初始化逻辑**：
    *   `init` 命令具备幂等性保护。若检测到现有配置，必须使用 `--force` 才能重置 UUID 和密钥。

## 3. 测试环境与兼容性

*   **架构支持**：Amd64, Arm64 (arm64-v8a)。
*   **编译要求**：`CGO_ENABLED=0` 纯静态链接。
*   **Go 工具链路径**：若当前会话未自动注入 Go 环境，必须将 `/home/ailing/.local/share/go/bin` 加入 `PATH` 后再执行构建、测试或发布命令。
*   **测试节点**：
    *   **Gateway VM**: `gateway` (Debian 13) - 普通用户, 可用 sudo. 用于测试透明代理服务端和网关逻辑。
    *   **Client VM**: `client` (Debian 12) - 普通用户, 可用 sudo. 用于模拟旁路由结构下的受控端测试。
    *   **Alpine VM**: `alpine` (Alpine Linux) - root 用户. 用于验证极简环境下的兼容性。
    *   **Remote VPS**: `remote` (hostname `titanium`) - root 用户, 公网外部节点. 当前已运行 `Xray-Proxya server mode`，systemd `ExecStart=/root/.local/bin/xray-proxya run`，`WorkingDirectory=/root/.local/share/xray-proxya`。后续所有外部上游/回源验证优先使用该节点。
*   **当前推荐测试拓扑**：
    *   `client` 作为透明网关。
    *   `alpine` 作为最终客户端，默认路由指向 `client`。
    *   `gateway` 默认保持空闲，必要时可改作备用上游或对照机。
    *   `remote` 作为公网最上游提供者与外部日志观察点。

## 4. 经验教训 (Lessons Learned)

*   **启动假成功**：后台启动维护必须等待至少 1 秒并显式 `Wait()` 子进程，防止因端口被占用或配置错误导致的瞬间闪退被忽略。
*   **日志覆盖风险**：后台模式必须以 `O_APPEND` 方式打开日志，严禁 `O_TRUNC`，以保留排障现场。
*   **工作目录稳定性**：Systemd 服务的 `WorkingDirectory` 应指向固定的数据目录，而非二进制所在目录，以应对临时执行路径。

## 5. 运行态系统功能原则 (Runtime System Feature Rules)

*   **配置面与运行态分轨**：
    *   Xray 配置变更继续使用 `.staging` + `apply` 提交。
    *   任何直接修改宿主机运行态的功能（如 `sysctl`、路由、转发、内核网络调优）必须使用专用命令，不得混入通用 `apply`。
*   **Root 功能默认临时化**：
    *   所有 Root 专用系统调节功能默认只修改当前运行态。
    *   未经单独设计与明确确认，不得写入 `/etc/sysctl.conf`、`/etc/sysctl.d/*` 或其他系统持久化配置。
*   **能力探测按项处理**：
    *   宿主机内核/系统能力差异必须逐项探测。
    *   对不支持的项应标记为 `unsupported` 并跳过，不因单项缺失而默认整体失败，除非继续执行会破坏安全边界。
*   **系统命令闭环可观测**：
    *   新增的系统级功能默认应提供 `show / diff / apply / verify / rollback` 中的大部分或全部能力。
    *   用户必须能够在执行前看到差异，在执行后验证结果，并在条件允许时回滚。
*   **回滚只依赖已记录旧值**：
    *   回滚逻辑只能恢复本次操作前实际读取到的旧值。
    *   严禁猜测“系统默认值”或发行版理论默认参数。
    *   若缺失运行态记录，应明确提示用户只能通过重启或手工恢复。
*   **以实机行为修正规则**：
    *   对网络、内核、代理链路和透明网关相关功能，抽象设计只作为初稿。
    *   一旦实机验证结果与设计预期冲突，优先修正实现、命令语义和文档，而不是坚持抽象假设。
*   **文档白名单优先**：
    *   本仓库默认不提交任意新增 Markdown 文档。
    *   新增文档前必须先确认是否属于公开文档；必要时同步更新 `.gitignore` 白名单。
    *   本地参考型文档仍应保持默认不推送。
*   **发版必须检查 GitHub 侧状态**：
    *   发布前后除本地 `git` 外，还必须检查 `gh auth status`、release/tag 状态、上传产物及页面结果。
    *   不得将“本地已 commit/push”视为“发布已经完成”。

---
*GEMINI.md v0.2.8 (Synced with CODEX v0.2.8, DNS/UDP hijacking fixed)*
