## v2.5.6

<details>
<summary><strong> ✨ 新增功能 </strong></summary>

- 新增「Claude 出口保护」：固定出口访问 Claude，断线不回退到普通节点
- 新增「自动链路」：自选固定出口、多选中转订阅，查看全链路测速结果并在断线后自动切换

</details>

<details>
<summary><strong> 🐞 修复问题 </strong></summary>

- Allow choosing individual automatic-chain relays and recover through verified backups while reconnecting affected traffic.

- Restore original proxy links when disconnecting a manual chain without restarting the application.

- Fix slow automatic chains being rejected, conflicting Claude relay selection, and misleading healthy status.

- Keep automatic chains stable between ten-minute scans and allow pinning a relay until it fails.

- Fix automatic chains passing health checks while traffic bypasses them and their status is shown incorrectly.
- 修复「Claude 出口保护」的 DNS 绕行：加密解析经过固定出口，失败不回退普通 DNS
- 修复「自动链路」误排除同服务器、同端口的不同节点，并在节点页显示当前链路及延迟
- 优化「自动链路」：稳定链路保持连接，连续故障或持续高延迟才切换，支持动态纳入全部订阅
- 修复「代理集合」「规则集合」订阅响应较慢时更新误报失败、且不显示真实失败原因的问题
- 修复读屏软件将普通模式下的侧边栏导航项播报为不可用的可拖拽控件的问题
- 修复订阅包含自定义 DNS 时，确认开启的 DNS 覆写在重启应用后被自动关闭的问题

**🖥️ Windows**

- Fix Claude access after switching to the new fixed-exit profile or renaming its nodes.
- Fix direct-access protection for updated Claude versions and automatically cover new installation paths.
- Fix browser connectivity when enabling the system proxy fails with error `0x80070057`.
- Fix Claude protection for `JP-REALITY-SOCKS` across profile refreshes and restarts without falling back to ordinary nodes.
- Fix LAN access with browser protection enabled while keeping localhost access and Claude routing protected.
- 修复 Windows 部分未安装服务的用户以普通权限运行时，内核无法启动的问题
- 修复 Windows 系统隔离权限被误判，导致服务模式和 TUN 无法使用的问题
- 修复 Windows 旧版服务状态残留导致无法重装的问题，自动备份可识别的残留并恢复安装
- 修复 Windows 服务已停止时，启动要等约两分钟才显示窗口的问题
- 优化 Windows 服务安全检查失败提示：用易懂的文字说明原因，并提供修复文档链接

**🍎 macOS**

- Fix Claude protection losing its verified gateway after subscription or relay changes.

- macOS 修复编辑规则时「规则内容」输入的首字母被自动转为大写的问题
- macOS 修复残留的服务进程导致内核无法启动、「继续使用 Sidecar」失败且无法修复的问题
- macOS 修复部分账户安装或修复服务时提示无法解析用户组而失败的问题
- macOS 优化用户目录在外置磁盘时服务拒绝启动内核的提示：说明原因并给出修复命令
- macOS 修复服务模式内核意外停止后，系统代理仍指向失效端口导致无法上网的问题

</details>

<details>
<summary><strong> 🚀 优化改进 </strong></summary>

- 优化「自动链路」：选择出口和订阅后即可自动连接，代理流量及 Claude 保护统一使用固定出口
- 优化版本更新：默认关闭自动检查，关闭后不再提示安装缓存更新，保留手动检查入口
- 优化内核启动失败和服务模式内核意外停止的提示：显示具体原因，并在窗口恢复后提示尚未解决的错误

</details>
