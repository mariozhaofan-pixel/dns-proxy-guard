# 已验证规则配方：国内应用直连与海外代理 DNS

**条件入口（2026-10-28）：只有中国软件或国内网页出现联网不稳定时才使用本配方。正常环境不预置以下规则；兼容修复完成后返回 [DNS/WebRTC 双项验收](acceptance.md)。**

整理日期：2026-10-16。来自一次 Windows、Clash Verge Rev v2.5.8、Mihomo v1.19.32 的应用兼容修复。此前用户确认微信发图、剪映、国内网页及浏览器海外网页均正常；本次只核对配置仍与已验收版本一致，没有重新测试真实业务或 DNS 泄露。

这是**有适用条件的案例配方**，不是默认配置。以下保留公开软件进程、服务域名与公共解析器，省略订阅身份、代理节点、出口地址、原始日志和观测到的故障 IPv6 地址。代码块均为局部摘录，不能覆盖完整配置或直接附加到任意订阅。

## 适用条件与参数

- 用户接受加密分流：国内软件/指定国内域名可以直连，海外 DNS 经指定代理；节点引导解析允许指定直连 DoH。这不满足“全部 DNS 都经代理”的严格目标。
- 保留现有 TUN、代理节点、组与有效业务规则。本例已经使用 fake-ip，不要求其他环境切换模式。
- `PROXY_GROUP_FROM_CURRENT_PROFILE` 必须替换为本次实际存在且经过出口验证的代理组；检查选择链与回退，不能从旧订阅复制名称或默认选择 DIRECT。
- `Weixin-Direct-IPv4` 是本例自定义直连出站名。若存在同名且不相同的出站或代理组，先处理冲突；不得覆盖已有节点。
- 域名集合和 IPv4 例外来自已观察的失败业务，跨版本迁移须重查进程、子进程与域名。仅软件名相同不足以证明需要同样的 IPv4 限制。

## 业务流量：八条应用/国内规则

本例使用以下规则。它们描述已验证的分流意图，不规定在其他配置中的固定行号：

```yaml
rules:
  - PROCESS-NAME,JianyingPro.exe,DIRECT
  - PROCESS-NAME,JianyingProTray.exe,DIRECT
  - PROCESS-NAME,Weixin.exe,Weixin-Direct-IPv4
  - PROCESS-NAME,WeChatAppEx.exe,DIRECT
  - DOMAIN-SUFFIX,jianying.com,DIRECT
  - DOMAIN,imagex.bytedanceapi.com,DIRECT
  - DOMAIN,tos-mya2hl.vodupload.com,DIRECT
  - GEOSITE,cn,DIRECT
```

合并时先检查已存在的明确代理例外和规则集，再决定插入位置。需要代理的具体域名不能被靠前的宽泛 `GEOSITE,cn,DIRECT` 或进程 DIRECT 抢先匹配；地理域名集会变化，也不等于“所有中国网页”。保留原列表的其他规则和次序，不用上面八行替换整份规则，不自动把它们全部放到列表最前面。

浏览器不加入全进程 DIRECT：本例已移除过 `PROCESS-NAME,quark.exe,DIRECT`，否则海外服务会绕过后续域名代理规则。Chrome、夸克等继续使用订阅的域名/规则集分流；Fish Audio、Hugging Face 和 ChatGPT 沿用既有代理策略。本例没有为了这些网页新加全浏览器代理或一组猜测的服务域名。更多对照方法见 [浏览器排查](platform-troubleshooting.md)。

## DNS：解析器与出站分别指定

下列公共解析器是本例经过验证的选择，**不是代理服务提供的专属 DNS**。换网络或用户指定其他解析器时，重新确认 TLS、延迟、可达性和隐私目标，不能仅为复用案例就替换用户的指定解析器。

| 字段 | 本例的值/处理 | 迁移时要核对 |
| --- | --- | --- |
| `nameserver` | Cloudflare `https://1.1.1.1/dns-query#PROXY_GROUP_FROM_CURRENT_PROFILE` 与 Google `https://8.8.8.8/dns-query#PROXY_GROUP_FROM_CURRENT_PROFILE` | 两条均显式经已验证代理组；组名占位符不能保留 |
| `default-nameserver` | `https://223.5.5.5/dns-query` | 解析器自身的引导；独立核查真实出站，不能把它当已代理 |
| `proxy-server-nameserver` | `https://223.5.5.5/dns-query#DIRECT` | 节点域名引导例外；代理未建立前须能工作 |
| `direct-nameserver` | `https://223.5.5.5/dns-query#DIRECT`、`https://223.6.6.6/dns-query#DIRECT` | DIRECT 重新解析仍用加密上游，但解析器可见本地出口 |
| `direct-nameserver-follow-policy` | `true` | DIRECT 再解析继承下面的局部域名策略 |
| `respect-rules` | `true` | 不代表 DNS 自动全部走代理；仍须检查上游后缀及命中路由 |
| `fallback` | 空列表 | 本例移除了旧回退上游；其他环境先检查需求，不盲删可用的备用路径 |
| `proxy-server-nameserver-policy` | 空映射 | 本例没有节点专属域名策略；已有有效策略需要合并，不能直接清空 |

不要把 `proxy-server-nameserver` 指回同一个内核的 DNS 监听端口：节点解析可能再依赖尚未建立的代理，形成自引用或循环。若本地端口是另一个独立解析服务，应追踪其依赖再判断，不能仅因地址是回环就断言有循环。配置语义见 [Mihomo DNS 文档](https://wiki.metacubex.one/config/dns/)；通用目标边界见 [DNS 与分流](dns-routing.md)。

`#DIRECT` 仅选择出站，不能自动解决 DoH 主机名本身的引导依赖。使用 IP 形式的 DoH 仍须证书校验有效且链路可达；不得关闭 TLS 校验。缓存命中时成功不能证明无缓存启动可用；在合适时机单独验证节点引导和解析器引导，没有执行就标记未测。

### 十四项局部 DNS 例外

本例对以下每个键使用同一组两条上游：

```yaml
- https://223.5.5.5/dns-query#DIRECT&disable-ipv6=true
- https://223.6.6.6/dns-query#DIRECT&disable-ipv6=true
```

`nameserver-policy` 中的键按以下顺序列于宽泛国内策略之前：

```text
+.jianying.com
imagex.bytedanceapi.com
tos-mya2hl.vodupload.com
+.qq.com
+.qpic.cn
+.qlogo.cn
+.weixinbridge.com
+.weixin.com
+.wechat.com
+.ulikecam.com
+.byteacctimg.com
dig.bdurl.net
open.douyin.com
lf-zt.douyin.com
```

最后是本例的 `geosite:cn` → `https://223.5.5.5/dns-query#DIRECT`。迁移时也要审查更早的现有域名策略，避免覆盖企业内网、指定代理 DNS 等用户例外；不能简单替换整张 `nameserver-policy` 表。

这十四项也加入本例的 `fake-ip-filter`，保留其他已有排除项，避免受影响业务拿到虚拟地址。该处理只适用于已核实的 blacklist 语义；其他过滤模式先重新设计，不直接追加。本例的 `disable-ipv6=true` 只针对这些上游策略返回的 AAAA，不关闭系统/TUN IPv6，也不影响已有字面 IPv6 或应用自带 HTTPDNS 缓存。

## 微信出站与嗅探必须区分作用

本例追加了下面的出站，保留所有原节点：

```yaml
proxies:
  - name: Weixin-Direct-IPv4
    type: direct
    ip-version: ipv4
```

对原始目标仅有字面 IPv6 的失败连接，必须先恢复真实域名并取得可达 A 记录，才可能经此出站改走 IPv4；该出站不负责 IPv6 到 IPv4 的地址转换。本例另有日志证明两个具体 IPv6 上传目标存在问题，并以限定目的地址的 **HTTP 80** 嗅探恢复 Host 后重解析；撤回这组规则时失败，恢复相同组合后用户确认发图成功。不能将成功归因于同时操作的 UWP 豁免。

跨机器复用时，从新的连接记录取得准确 `/128` 目标，用 [离线生成器](helper-tools.md) 构造补集排除列表。没有这些证据就不添加该嗅探补丁，也不根据产品名称猜测地址。嗅探只限制目标地址和端口，其他进程访问相同目标也可能受影响；出站的进程规则不使嗅探变成微信专用。无 HTTP Host、不可用的 IPv4 结果或目标地址轮换都需要重新取证。

已有 sniffer 与候选不同（包括显式禁用）时，先审查冲突或明确合并；不能在应用 DNS/规则之后才抛错，留下部分改动。需要记录 `force-dns-mapping`、解析纯 IP 的设置及排除集合，确认嗅探没有扩大到其他 IPv4/IPv6 目标。

剪映的应用内 DNS 设置是另一层问题。本例曾经备份后关闭特定版本的内置 HTTPDNS 选项；这不是上述代理规则的一部分，不将私有配置键或固定路径当通用步骤。只有代理/DNS 路径已经正确而业务仍失败时，才按 [平台与应用排查](platform-troubleshooting.md) 继续定位。

## 验收和持久化

必须分别证明默认/海外 DNS 经代理、获准国内 DNS 加密直连、目标进程命中预期出站，以及用户真实登录/上传成功。网页出现某个解析器所在地只是线索；通过一次网页检测不等于全机所有查询隐身。直接业务仍使用本地出口。

把通过验证的同一组规则和 DNS 配套策略写入实际生效的持久层，避免只保存其中一半。全局与订阅组合、客户端字段覆盖、重复执行和未知配置的处理，按 [持久化与配置漂移](persistence.md) 验证。发布和安装该 skill 仅提供规则知识，不自动修改网络；实际应用需要在用户本机重新完成这些检查。
