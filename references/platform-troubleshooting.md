# 分平台排查与持久化

核对日期：2026-10-12。Mihomo 细节以 **v1.19.32** 为依据；Windows TUN 实现对应其依赖 **sing-tun v0.4.27**；Clash Verge Rev 增强流程对应 **v2.5.8**。升级后重新查验，特别是字段名、合并规则、嗅探能力和控制接口。此文不提供可覆盖整机的配置模板。

## 先定位故障层

| 层次 | 需要的证据 | 不能据此推断 |
| --- | --- | --- |
| DNS | A/AAAA 结果、超时、解析器、缓存、应用是否自行解析 | 解析成功不代表目标可连接 |
| 路由与 TCP/UDP | 选中接口、路由、连接建立或超时、拒绝、不可达 | 有 IP 的连接失败不一定是 DNS 故障 |
| TLS | 握手与证书错误、SNI、协议兼容性 | 不以关闭证书验证作常规修复 |
| 登录或业务 | HTTP 状态、应用错误、上传与下载分别复现 | TCP 或网页首页成功不代表登录、发图、上传成功 |

一次只改一个变量。A 为基线，B 为单项改动；在不影响用户工作时复测 A/B，固定业务动作并记录时间与有效配置。不要同时切换 UWP 豁免、嗅探、DNS 和出站后，把成功归因于其中一个。重启应用前先保护未保存内容；无需通过真实发送给他人来做自动化探测。

## Windows：先读接口、DNS 和路由

以下为只读示例；先确认本机存在相关 PowerShell 模块。输出可能含内网信息，应在本地分析、公开前脱敏。

```powershell
Get-DnsClientServerAddress
Get-NetIPConfiguration
Get-NetIPAddress -AddressFamily IPv6
Get-NetRoute -AddressFamily IPv6
```

来源：[DNS 客户端服务器地址](https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientserveraddress)、[NetTCPIP 模块](https://learn.microsoft.com/en-us/powershell/module/nettcpip/)。

辨认物理网卡、TUN、其他 VPN 和虚拟网卡，检查到实际目标的匹配路由。物理网卡列着运营商 DNS，不等于本次查询经过它；TUN 列着虚拟 DNS，也不是接管所有查询的证据。不要把仅在代理运行时有效的虚拟 DNS 固定写入物理网卡。

`ipconfig /flushdns` 仅重置 Windows DNS 缓存，不会修改 DNS 服务器或修复路由。[Microsoft ipconfig 文档](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig)

UWP/AppContainer 回环限制只有在应用确受隔离、确需访问本机代理，且存在相应阻断证据时才相关。先识别包身份和实际进程；不能因为来自商店就判定所有网络都受同一种隔离。若需豁免，仅针对确认的包，记录原状态与撤销方法；不批量豁免所有应用，不关闭防火墙。[Microsoft UWP 连通性排查](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/troubleshooting-uwp-firewall)

## macOS、Linux 与浏览器

- **macOS**：先从网络服务详情读取 DNS，并用本机支持的 `scutil --dns` 检查实际解析配置；同时核对 VPN 的作用域和路由。删除手填 DNS 只改变配置来源，不保证代理接管。[Apple DNS 设置](https://support.apple.com/guide/mac-help/mh14127/mac)、[Apple 使用 scutil 检查 DNS 的示例](https://support.apple.com/guide/deployment/depe6ded0780/web)
- **Linux**：先识别管理者。使用 systemd-resolved 的系统可读 `resolvectl status`，查看每条链路的 DNS 与路由域；不要把 `/etc/resolv.conf` 中的本地 stub 地址当成最终上游，也不要覆盖管理器生成的文件。其他发行版使用其对应管理器的只读接口。[systemd 官方 resolvectl 手册源码](https://github.com/systemd/systemd/blob/main/man/resolvectl.xml)
- **浏览器**：记录版本、DoH 模式、解析器、代理设置和受管策略，观察实际请求路径。优先通过浏览器支持的设置修改。若必须离线编辑个人配置，先核对该版本存储位置，确认进程退出并备份；不把某个 Chromium 版本的字段位置当跨浏览器规范，也不随意写企业策略。[Chrome 模式定义](https://chromeenterprise.google/policies/#DnsOverHttpsMode)、[Firefox 模式定义](https://support.mozilla.org/en-US/kb/dns-over-https)

## IPv6：可达性与 DNS 泄露分开判断

查询 AAAA、发起 IPv6 连接、DNS 经 IPv6 传输，是三件不同的事。IPv6 可正常工作且 DNS 不绕行；屏蔽 AAAA 也不能清除应用缓存或阻止应用连接已有 IPv6 地址。

“当前没有可用公网 IPv6 直连出口”至少需要地址、所选物理接口与到目标的路由证据，必要时加受控连通性测试。仅看到 ULA/链路本地地址、只检查默认路由、或看到 TUN 默认路由，均不单独构成完整证明；还要考虑特定路由、其他接口和其他 VPN。不要据此断言路由器或运营商永远不支持 IPv6。

sing-tun v0.4.27 的 Windows 自动路由在 TUN 自身接口上添加路由；该实现不删除物理 IPv6 默认路由。`strict-route` 使用 WFP 过滤，其具体行为不能泛化到所有客户端。保留用户要求不变的 TUN 设置。[Windows 实现](https://github.com/MetaCubeX/sing-tun/blob/v0.4.27/tun_windows.go)、[Mihomo 依赖版本](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/go.mod)

对于字面 IPv6 目标，`type: direct` 配合 `ip-version: ipv4` **不是 IPv6 到 IPv4 转换器**：没有域名时无法凭空查询对应 A；有域名时才可能按 IPv4 重解析。先查看连接元数据，不能用反向 DNS 或猜测 CDN 域名代替证据。[DIRECT 实现](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/adapter/outbound/direct.go)、[IPv4 解析实现](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/component/resolver/resolver.go)

## 嗅探仅作有边界的兼容性修复

需要先证明：目标连接缺少域名、真实流量含可提取的 HTTP Host 或 TLS SNI、重解析后的地址可达，且业务复测有效。无 Host、无 SNI、加密 ClientHello 或不支持的协议可能无法恢复域名。不得为此解密用户 TLS 流量。

Mihomo v1.19.32 中：

- `parse-pure-ip` 会选择尚无域名的流量；`override-destination` 决定是否用嗅探域名改写目的地。
- 有 `skip-src-address`、`skip-dst-address`；没有 `force-dst-ip`、`skip-dst-ip`，也没有按进程启用的 sniffer 字段。未知键未报错不代表生效。
- 进程路由只限制所选出站，不会把全局嗅探变成该进程专用。通过 IP 范围限制也会影响其他访问相同 IP 的进程。

依据：[嗅探配置](https://wiki.metacubex.one/config/sniff/)、[v1.19.32 配置结构](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/config/config.go)、[实际筛选与目的地替换](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/component/sniffer/dispatcher.go)。

如现有版本只能用排除地址集合构造有限目标范围，应验证集合边界，不直接扩大到整个 IPv6 网段。固定 IP 修复须注明期限和回滚条件：DNS TTL、应用 HTTPDNS 缓存、CDN 调度及 IP 轮换会令它失效。失效后重新取证，不自动添加整段运营商或 CDN 地址。

## Clash Verge Rev：区分源配置、生成结果和运行态

v2.5.8 先处理规则/节点/代理组编辑器，再执行全局增强、订阅增强，最后回写应用管理的字段。订阅脚本可看到规则编辑器已插入的规则；脚本文件会在生成时读取。[生成流程](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.8/src-tauri/src/enhance/mod.rs)、[增强文件读取](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.8/src-tauri/src/enhance/chain.rs)

持久化时选择已关联的订阅增强，保留原有逻辑；追加自定义出站时保留订阅节点，检查名称碰撞，并让重复执行不产生重复项。只修改确认的规则和已验证的嗅探范围。普通 merge 中的列表会整体替换，不能用一个新出站的 `proxies` 列表覆盖订阅；DNS 子字段中的策略表也需检查合并语义。[官方增强规则](https://www.clashverge.dev/guide/extend.html)

核心热加载成功不代表 GUI 已保存，也不代表增强脚本已执行。检查实际生成配置、运行态及日志；在不会打断工作的时机验证重新生成后仍有效。比较 TUN、DNS 及订阅节点等非目标字段是否变化，保留可单独撤销的备份。

## 命令与公开材料的边界

截图、流程图、论坛帖中的工具名、诊断子命令或凭据文件路径仅是待验证线索。先查当前安装版本的帮助或官方文档，再决定能否执行；本参考不将未核实的 Codex 诊断命令或环境文件位置列为操作步骤。公开材料只保留脱敏的现象、方法与结论，不携带订阅链接、账号、节点凭据、控制器秘密、个人目录或原始抓包。
