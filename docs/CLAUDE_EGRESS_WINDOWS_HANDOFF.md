# Claude 固定出口保护：Mac 实施记录与 Windows 交接

记录日期：2026-09-29（Asia/Tokyo）。这是用户批准的个人维护版，不是向上游提交的通用部署方案。本文可直接交给 Windows 电脑的 Codex 阅读。

## 1. 目标与操作边界

用户要求：Claude 的受保护连接只能经过公网出口 `103.5.250.92`；中转节点断开、自动切换或手动选择香港节点时，宁可 Claude 暂时断网，也不能改用其他出口。覆盖 Claude Desktop、Claude Code CLI，以及普通 Chrome / Edge 中的 Claude 网站。

用户明确要求：**不要自行退出、重启、替换正在使用的 Clash。交付更新包，由用户安装并通知后，再检查。** Windows 电脑已经做过一些保护措施；先盘点、备份、验证，再补缺口，不要清空已有规则或重复部署另一套冲突的代理服务。不要用真实 Claude 登录会话测试“错误出口是否能连上”，不要发送收费模型请求。

这里的“固定出口”与“中转节点”是两回事。香港节点可以成为到达 `.92` 的第一跳；Claude 的最后一跳仍是 `.92`。自动恢复不保证零中断，已有 TCP/TLS 会话可能需要应用重连。

## 2. 本仓库新增了什么

### 自动链路

- UI：`src/components/proxy/auto-chain.tsx`、`auto-chain-results.tsx`，入口位于代理页。
- 配置生成：`src-tauri/src/enhance/auto_chain.rs`；后台检测：`src-tauri/src/core/auto_chain.rs`。
- 可配置固定出口、多选中转订阅、目标代理组、全量测试间隔、切换容差和 HTTPS 测试地址。
- 收集所选本地/远程订阅及可读取的 provider 缓存，按连接配置去重；界面保留同一连接的多个节点别名，共享测速结果。节点“名称条数”不等于实际独立链路数量。
- 每个中转生成一个固定出口副本，用 `dialer-proxy` 指向该中转。`CV Auto Chain` 的成员是这些完整链路，而不是裸中转。
- 全量探测由 Mihomo 的 `url-test` 健康检查执行；另一个后台任务并发探测当前链路与最多两条备用链路，每轮完成后等待 2 秒再检测。单次内核探测超时 2 秒，外层调用上限 4 秒。
- 全量间隔默认 15 秒，可设置 5–300 秒；`lazy: false`、`max-failed-times: 1`。后台每 60 秒检查候选目录变化，相关订阅更新也触发重新生成。
- 使用 HTTPS 实际请求测试整条链路，并关闭 `unified-delay` 以保留握手成本。这个数值不是带宽下载测速，也不是 Claude 业务可用性保证。
- 找不到出口或候选时使用 `REJECT`，不添加直连后备。
- 自动链路配置绑定当前订阅；Claude 出口保护是独立的全局开关，不随普通订阅切换失效。

### Claude 出口保护

核心文件：

| 文件 | 作用 |
|---|---|
| `src-tauri/src/enhance/claude_guard.rs` | 保护域名、固定本地出站、最高优先级规则、UDP 拒绝、模式校验 |
| `src-tauri/src/enhance/mod.rs` | 订阅、脚本、合并处理后重新加入保护 |
| `src-tauri/src/config/config.rs` | 写入内核运行配置前再次施加保护，防止运行时链式修改破坏保护出站 |
| `src-tauri/src/feat/config.rs`、`feat/clash.rs` | 配置与模式切换入口限制；启用时关闭已有代理连接以重建路由 |
| `src-tauri/src/cmd/runtime.rs` | `get_claude_guard_status`：读取网关状态和本地端口可达性 |
| `src/components/proxy/claude-guard.tsx`、`src/pages/proxies.tsx` | 开关、状态、域名范围、禁用全局/直连按钮 |

持久化开关：`verge.yaml` 中的 `claude_guard_enabled: true`。默认未启用；2026-09-29 用户安装后的现场检查确认已经启用。

当前个人版固定参数：保护出站名 `CV Claude Protected`；HTTP 网关 `127.0.0.1:17891`；预期出口 `103.5.250.92`。这些参数不是可任意选择的普通代理组。Windows 若端口不同，必须同步调整核心常量、状态读取与界面说明，不能仅修改显示文字。

保护的域名后缀（包括各自子域名）：

- `claude.ai`
- `claude.com`
- `anthropic.com`
- `claudeusercontent.com`
- `anthropicusercontent.com`

生成的规则先拒绝这些域名的 UDP，再把 TCP 路由到保护网关。例如：

```yaml
mode: rule
proxies:
  - name: CV Claude Protected
    type: http
    server: 127.0.0.1
    port: 17891
rules:
  - AND,((DOMAIN-SUFFIX,claude.ai),(NETWORK,UDP)),REJECT
  - DOMAIN-SUFFIX,claude.ai,CV Claude Protected
  # Other protected suffixes follow the same pattern before ordinary rules.
```

显式 UDP 拒绝很重要：不能依赖一个不支持 UDP 的 HTTP 出站自动阻断所有 UDP；需要避免规则被跳过后落入普通分流。该片段只是机制示例，完整规则由代码生成。

模式限制覆盖应用后端、页面、菜单/快捷键所调用的应用入口，不是仅把按钮变灰。**它不是修改 Mihomo 内核来禁止外部控制 API 的所有写操作**；其他程序直接修改内核模式或配置仍是管理面边界，不要把控制接口公开给不可信程序。

## 3. 这台 Mac 的实际部署

### 应用与兼容性

- 应用名：`Clash Verge Auto Chain.app`；应用版本 2.5.6；本次交付稳定 Mihomo 为 1.19.29，Apple Silicon。
- 仍使用 bundle identifier `io.github.clash-verge-rev.clash-verge-rev`，沿用原来的数据目录。
- 数据目录：`~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/`。
- 改名避免安装时覆盖原版的同名应用，但两个版本仍共享数据目录，**不应同时运行或假定配置隔离**。
- 本地构建使用临时 Tauri override 设置产品名；仓库默认产品名仍是 Clash Verge。重建定制包需要显式提供 `productName: "Clash Verge Auto Chain"`，不能仅凭源码默认构建就期待相同安装名称。
- 本地 Mac 包为 ad-hoc 签名，未公证；本记录不是 Windows 构建或运行验收。

### 三层连接结构

```text
Chrome / Edge
  -> 主 Clash :7897
  -> Claude 域名规则
  -> 保护网关 :17891
  -> 独立 Mihomo :17892
  -> 固定 SOCKS5 .92:443（通过主 Clash 提供中转）
  -> Claude

Claude Desktop / CLI
  -> 专用代理环境/启动参数 :17891
  -> 同一保护网关及固定出口

其他浏览器网站
  -> 主 Clash :7897
  -> 原有普通分流
```

独立后端中的 `Clash-Current-Entry` 是 HTTP 代理 `127.0.0.1:7897`；固定 SOCKS5 出站用 `dialer-proxy: Clash-Current-Entry`。后端规则只有 `MATCH,Claude-Fixed-Upstream`，没有可选代理组或直连后备。`.92` 服务器的传输连接回到主 Clash 时，必须避免被重新送入 Claude 网关形成环路。普通节点本身若已经是一条 `.92` 链路，也可能形成重复经过出口的路径；后续优化必须保持最终出口固定。

**仓库中的应用只负责把 Claude 流量送入网关，并读取状态。它不会自动安装下面的独立网关、后端、系统服务和防火墙规则。** 这些是这台 Mac 的本地部署文件，未随本次仓库代码提交，也没有把代理密码、订阅地址、原始运行配置或用户日志上传 GitHub。

### 独立保护网关

位置：`~/ClaudeNetworkGuard/`。

| 本地文件/服务 | 用途 |
|---|---|
| `bin/gate.py` | HTTP CONNECT 保护网关，监听回环地址 17891 |
| `proxy/mihomo`、`proxy/config.yaml` | 独立后端，监听 17892；配置含私有代理凭据，不应上传 |
| `proxy/gate.sb` | 网关进程的 macOS Seatbelt 网络限制，仅允许回环出站 |
| `proxy/client.sb` | CLI 的 Seatbelt 限制，只允许 localhost 的 17891、5180、8080 |
| `bin/claude` | 清空 NO_PROXY，设置大小写代理环境变量，经 sandbox-exec 启动原生 CLI |
| `bin/claude-desktop` | 设置专用代理环境和 Electron 代理启动参数 |
| `status.json` | 网关的近期验证结果，供应用读取 |
| `~/Library/LaunchAgents/local.claude-network-guard.{gate,backend}.plist` | 用户级启动与保活；gate 经 sandbox-exec 启动 |

网关行为：启动默认关闭公网转发；通过固定后端分别查询 `api.ipify.org` 和 `checkip.amazonaws.com`，两者均返回预期 `.92` 才开放。每轮检查结束后等待 5 秒，检查整体最长 10 秒，验证租约最多 12 秒；另有每 0.5 秒运行的过期检查。不能把它写成“每隔精确 5 秒完成一次验证”。

失败、错误 IP 或租约过期时，拒绝新公网连接并关闭已有公网隧道。公共域名通过同一固定后端做 DoH 的 A 记录解析，再 CONNECT 到公网 IPv4；直接 IPv6 目标及无公共 A 记录的目标拒绝。使用 TLS 证书验证，不解密用户 Claude TLS 会话。

状态接口读取 `<home>/ClaudeNetworkGuard/status.json`，要求本地网关可达、`allowed: true`、`expected` 等于预期 IP、`last_ok_unix` 距今不超过 12 秒。`observations` 是出口查询结果，**不是 Claude 服务器看到的每条连接 IP 的直接证明**。

### LuLu 防绕行

检查时为 LuLu 4.5.1，网络扩展 active/enabled。保存规则位置 `/Library/Objective-See/LuLu/`。

- Claude Desktop 与 CLI：已有应用目录/签名身份规则，拒绝直接外连，允许本地保护网关 17891；部分开发入口保留 5180、8080。
- 独立后端 `~/ClaudeNetworkGuard/proxy/*`：拒绝外连，允许 `127.0.0.1:7897`，以迫使其通过主 Clash 建立到出口的传输。
- 本次新增 `/Applications/Google Chrome.app/*` 和 `/Applications/Microsoft Edge.app/*` 的规则：正则地址 `^.*$`、任意端口、Block；另有精确 `127.0.0.1:7897`、Allow。目录覆盖浏览器及包内网络辅助进程。
- 使用正则拒绝而非仅 `*:*`，是为了适配本机 LuLu 的匹配优先级及已有全局 localhost 例外。现有浏览器 Helper 的宽泛允许规则未直接删除；本机实测新规则阻断了不允许的回环连接。未来新增更具体的允许规则仍需重新审计。
- `gate.py` 的防火墙状态检查新增了 Chrome / Edge 这两组规则的存在性检查；规则缺失会让网关关闭。存在性检查不能代替实际过滤验证。
- 结果：浏览器只能通过指定本地 Clash 入口联网；Clash 不运行或端口改变时会失去普通网页访问能力。浏览器对其他本地开发端口的直接访问也可能被阻断，不要无审计地改成允许所有回环端口。

## 4. 已完成的验证与尚未证明的边界

2026-09-29 的证据：

- Rust 编译检查、Clippy（`-D warnings`）、TypeScript、相关 ESLint、前端生产构建通过；Mac 应用构建、签名结构与 DMG 校验通过。
- 自动链路的 4 个单元测试与保护规则/模式的 2 个单元测试通过；独立网关 7 个测试通过，含错误 IP 关闭已有测试 socket。
- 真实订阅此前在隔离内核测试：109 条原始记录去重为 98 条链路；这属于当时样本，不是当前实时节点数量或可用性承诺。
- 本次独立真实 Mihomo + 本地模拟代理测试：普通选择从香港切到日本，受保护域名始终进入网关；关闭模拟网关后返回 502，普通代理没有收到受保护请求；普通网站继续按原选择工作；UDP 日志命中 REJECT。测试没有把真实 Claude 请求发往错误 IP。
- Chrome 与 Edge 在运行中的本地 IPv4/IPv6 18896 测试服务上均显示 `ERR_INVALID_HANDLE`，没有完成 HTTP 请求；独立 curl 正对照能读取服务响应。两浏览器随后访问 IP 查询服务均显示 `.92`。这是本地绕行阻断证据，不等同于所有公网绕行场景验收。
- 用户手动更新后：安装二进制与交付构建一致；开关为 true；内核 API 的规则列表前 10 条确实为保护规则，非仅检查磁盘文件；当前 mode 为 rule；全局/直连按钮禁用；网关两项近期出口观察均为 `.92`。
- 更新后原有 15 条普通分流规则、13 个 rule-provider 定义与更新前备份一致，仅前置保护规则。规则订阅的远程内容仍可随正常更新变化。

明确边界：

1. 域名保护不覆盖未知的新域名、未知第三方域名或无法识别为这些域名的流量。想完全不依赖名单，必须让整个浏览器的公网流量走固定出口，这不是当前采用的范围。
2. 主 Clash 退出/启动、睡眠恢复、升级后的完整公网 IPv4/IPv6 绕行矩阵没有全部实测；没有在用户更新后制造真实断网故障。
3. LuLu 日志曾出现无法识别进程而放行的记录；未归因于 Claude，也不代表已确认泄漏。因此不能宣称 LuLu 对所有异常都是严格失败关闭。
4. macOS PF 运行规则没有取得管理员读取结果，不能声称已验证 PF 兜底。系统自带应用防火墙的入站设置也不等同于 LuLu 出站保护。
5. 网关为本地开发保留了任意 localhost 服务转发（排除 7897、17891、17892）。本地服务如果主动代理公网，可能构成间接绕行；CLI 的 5180/8080 例外也有类似边界。
6. 防火墙规则只约束本地下一跳；公网 NAT 在远端。两个 IP 查询服务的周期验证不能证明远端对每个目的地址使用同一 NAT，也存在验证间隔。核心保障是固定后端不回退，IP 检查是补充。
7. 关闭保护开关、改写文件、操作外部内核控制 API、换浏览器安装路径或停用防火墙属于配置变化，需要重新审计。当前功能不是防管理员篡改系统。

本机证据在仓库忽略目录 `target/claude-guard-test/`，含 `results.json`、`installed-audit.json`、隔离测试脚本、构建日志；另有 `target/auto-chain-real-test/`。它们不会随着 git clone 出现，不要把文档描述误当成 Windows 本地测试结果。

## 5. Windows Codex 的接手顺序

先向用户说明：Mac 的保护措施有部分在仓库之外，Windows 现有措施未知，不能直接安装 Mac 包或复制 plist、Seatbelt、LuLu 规则。

1. 只读盘点 Windows 上当前 Clash/Mihomo 版本、系统代理/TUN、监听端口、服务/计划任务、规则生成脚本、现有固定出口网关、Desktop/CLI 启动包装、Chrome/Edge 路径与网络辅助进程、IPv4/IPv6/UDP 和防火墙策略。不要输出密码或订阅令牌。
2. 备份当前有效配置和规则，记录恢复方法。优先复用已有网关和防绕行措施，找出缺少的环节，而非先卸载或改全局出站默认策略。
3. 确认现有后端是否只包含固定 `.92` 最终出站，是否有 DIRECT、普通节点或全局组后备。检查中转切换只改变第一跳，固定后端的传输不会被再次送入自身。
4. 让本仓库的 Claude 出站对接现有网关。若采用不同端口、目录或状态格式，要同步修改接口。现有 UI 读取 `status.json` 只能展示网关近期观察，不是 Windows 防火墙认证。
5. 适配网关的系统审计、进程限制和后台保活。Mac 网关的 `systemextensionsctl`、plist 解码、LuLu 4.5.1 版本检查及 Seatbelt 均不能照搬到 Windows。未完成替代审计时不要简单删掉检查、然后仍显示“保护完整”。
6. 使用 Windows 实际可用的出站过滤机制限制浏览器、Claude 进程及后端，覆盖 TCP/UDP、IPv4/IPv6、辅助进程及升级路径；验证回环例外本身是否被该机制正确处理。
7. **不要照搬“Block 所有 + Allow 某端口”的 LuLu 组合到 Windows Defender Firewall。** Windows 的显式阻止通常优先于冲突允许；必须设计无重叠的阻止范围或使用经过验证的 WFP 策略，并做实际连接测试。参见 [Microsoft：Windows Firewall rules](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules)。不要假设一条更具体的 Allow 就能覆盖 Block。
8. 用本地受控目标和隔离代理进行测试：固定路径成功、普通节点切换、固定后端不可达、网关停止、配置重载、订阅切换、全局/直连尝试、旧连接处理、浏览器 IPv4/IPv6 和 UDP 绕行、重启/睡眠恢复。每个拒绝测试必须有服务可达的正对照，避免把服务故障当防火墙生效。
9. 完成受控验证后，再经确认的固定出口检查实际 Claude 路由；不必发送模型消息。写明实际测过、只读推断、尚未测过三类结果。更新软件仍由用户操作，不自行关闭在用的 Clash。

Windows 应保留其他网站的现有普通分流，除非用户另行要求全浏览器固定出口。测试不得让 Claude 真实账户先从错误出口访问再观察结果。

## 6. 回滚与敏感信息

Mac 本次备份在 `~/ClaudeNetworkGuard/backups/browser-protection-20260929/`，包含旧定制应用、更新前的 Clash 配置、LuLu rules/preferences 和网关脚本。备份包含敏感配置，仅保留本机，不上传 GitHub。回滚会降低或移除新增保护，需要先告知用户，不能静默操作。

本文没有代理用户名/密码、订阅 URL 或会话令牌。Windows 应从该机已有的受保护配置取得凭据；缺失时向用户获取，不在 GitHub、日志或聊天输出中传播。
