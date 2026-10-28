# WebRTC：限制地址暴露、验证与回滚

本流程的页面验收目标是 [Net.Coffee Claude 检测页](https://ip.net.coffee/claude/) 中 DNS 显示“未检测到泄露”，WebRTC 显示“已禁用或无泄露”。必须等待本次检测完成，分别记录两项结果。**“已禁用或无泄露”只描述这个页面的本次测试，不证明 WebRTC API 已完全关闭，也不证明其他浏览器、配置文件或原生应用没有泄露。** DNS 与 WebRTC 是独立检查项，不能用其中一项通过替代另一项。

## 先确认范围和 TUN 路径

按主流程引导关闭 Clash 的系统代理、启用 TUN，同时保持 Clash 内核和所选节点运行。“关闭系统代理”不是退出 Clash，也不是关闭内核。本文件不另行重写 TUN、全局 UDP 或国内软件规则；只有中国软件出现不稳定时，再进入独立的应用兼容修复。

TUN 在操作系统层接管符合条件的流量，不等同于浏览器配置了显式 HTTP/SOCKS 代理，也不等于每个连接最终都通过远端节点。WebRTC 的 STUN/TURN 或对端连接仍需核对实际路由、IPv4/IPv6、规则及出站；`DIRECT`、排除路由或未接管的接口可能产生不同出口。页面的 HTTPS 出口与 WebRTC 出口应分别核实。IETF 明确区分应用代理与 VPN/多接口路由，并说明 STUN 可以发现与 HTTP 不同的地址；这里不能仅凭 TUN 开关推导结果。[RFC 8828 第 3、5 节](https://datatracker.ietf.org/doc/html/rfc8828)

修改前记录目标浏览器的产品名、实际版本、配置文件、普通/隐私窗口、现有 WebRTC 设置及控制来源。只读取必要字段；不要导出完整 Preferences、启动命令行或浏览历史。字段缺省、扩展未显示控制项、没有候选地址，都不能直接记为“已禁用”。还要区分网站脚本异常、测试服务器不可达和真实限制生效。

## 按浏览器版本选择机制

下表是能力边界，不是默认安装扩展或写入企业策略的操作清单。先查目标版本及厂商支持，优先使用已有且可回滚的入口；一次只试一项。

| 浏览器与机制 | 已核对的版本信息 | 作用与边界 |
|---|---|---|
| Chrome 扩展 API `privacy.network.webRTCIPHandlingPolicy` | Chrome 48 起 | `disable_non_proxied_udp` 限制非代理 UDP；保留 WebRTC，并可能使用 TCP。它需要扩展权限，不能在普通网页控制台直接当设置接口使用。 |
| Chrome 管理策略 `WebRtcIPHandling` | Chrome 91 起 | 支持相同的 IP handling 值。仅在已授权的管理环境使用，不默认新增注册表/企业策略。 |
| Chrome 管理策略 `WebRtcIPHandlingUrl` | Chrome 133 起 | 可按 origin 配置，依列表顺序首个匹配生效；URL 路径不参与匹配。例外会改变其覆盖范围。 |
| Firefox 扩展 API `privacy.network.webRTCIPHandlingPolicy` | Firefox 54 起；70 起语义有变化 | 70 起 `disable_non_proxied_udp` 在未配置浏览器代理时仍允许连接；不能把该值直接当作 TUN 环境下禁止直出的保证。 |
| Firefox `privacy.network.peerConnectionEnabled` | Firefox 55 起 | 设为 `false` 禁用 `RTCPeerConnection` 接口；`getUserMedia()` 不受这个设置影响。 |
| Edge、其他 Chromium 派生浏览器、移动版 | 单独查厂商与当前版本 | 不将 Chrome 的版本号、界面、参数或策略支持自动套用；缺少受支持入口时先验证，不能猜写同名字段。 |

版本与 API 来源：[Chrome privacy API](https://developer.chrome.com/docs/extensions/reference/api/privacy)、[MDN privacy.network](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/privacy/network)、[MDN 浏览器兼容性数据](https://github.com/mdn/browser-compat-data/blob/main/webextensions/api/privacy.json)。策略版本来源：[Chromium WebRtcIPHandling 定义](https://github.com/chromium/chromium/blob/main/components/policy/resources/templates/policy_definitions/WebRtc/WebRtcIPHandling.yaml)、[Chromium WebRtcIPHandlingUrl 定义](https://github.com/chromium/chromium/blob/main/components/policy/resources/templates/policy_definitions/WebRtc/WebRtcIPHandlingUrl.yaml)。这些文档会更新，执行时重新核对目标版本。

### Chromium：限制非代理 UDP，不宣称完全禁用

若现有设置入口支持，候选值是 `disable_non_proxied_udp`。官方策略定义允许在配置的代理支持时使用 UDP，否则使用 TCP；这既不是 WebRTC 总开关，也不是保证所有 TCP 经代理的开关。`default_public_interface_only` 也不能称为“无泄露”：限制接口/私网候选不等于隐藏公网出口。[Chromium 策略定义](https://github.com/chromium/chromium/blob/main/components/policy/resources/templates/policy_definitions/WebRtc/WebRtcIPHandling.yaml)

没有现成界面而需做可逆试验时，先核对目标版本是否仍支持 Chromium 的启动参数：

```text
--force-webrtc-ip-handling-policy=disable_non_proxied_udp
```

上游源码存在这个覆盖 IP handling policy 的参数；它不是所有派生浏览器的稳定承诺。只在获准的目标浏览器启动入口中试用，保存原启动参数；先保存用户工作并正常退出目标浏览器，再启动新进程，避免已有进程复用导致参数未生效。在版本页本地核实该参数及目标配置文件，并重新检测，不能以命令执行成功替代结果。不要输出完整命令行，也不自动改所有快捷方式或强制结束会话。[Chromium 启动参数定义](https://github.com/chromium/chromium/blob/main/content/public/common/content_switches.cc)

已有扩展控制该项时，读取有效值及 `levelOfControl`；企业策略或另一扩展可以覆盖写入。仅看到 `set()` 成功不足以证明生效。不要默认安装“防泄露”扩展，不向所有网页注入脚本去伪造 API 缺失，也不要默认写管理策略。[Chrome 设置控制说明](https://developer.chrome.com/docs/extensions/reference/api/privacy)

### Firefox：保留通话或关闭 PeerConnection

需要视频会议、浏览器语音或数据通道时，先保留 `RTCPeerConnection`，验证实际出站与候选地址。Firefox 70 起，`disable_non_proxied_udp` 在没有配置浏览器代理时仍允许连接；本流程关闭系统代理后，不能假定 TUN 会被识别为该选项所需的代理。更严格的 `proxy_only` 要求经代理的 TURN/TCP，若仅有 TUN 或网站未提供合适的 TURN，可能无法通话；它不适合作为通用默认值。[MDN 兼容性说明](https://github.com/mdn/browser-compat-data/blob/main/webextensions/api/privacy.json)、[MDN 模式说明](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/privacy/network)

用户选择禁用 PeerConnection、且接受相关会议/语音功能受影响时，在支持 `about:config` 的 Firefox 版本中，查找已存在的布尔项 `media.peerconnection.enabled`，记录原值及是否为用户修改值，再设为 `false`。重新载入测试页面，必要时正常重启目标浏览器并复核。找不到该项时先核对平台与版本，不自行创建一个同名项就声称生效。Mozilla 将此项描述为控制 `RTCPeerConnection` 创建能力；不要把它扩大解释为所有音视频采集 API 都关闭。[Mozilla WebRTC 隐私说明](https://wiki.mozilla.org/Media/WebRTC/Privacy)、[Firefox 配置编辑器](https://support.mozilla.org/en-US/kb/about-config-editor-firefox)

`no_host`、mDNS 地址隐藏、只使用默认接口等措施与禁用 PeerConnection 不同：减少局域网地址信息并不自动隐藏 STUN 发现的公网地址。Mozilla 的隐私页包含历史选项，不能把其中旧版扩展钩子照搬到当前版本；实际执行以当前版本为准。[Mozilla 候选地址选项说明](https://wiki.mozilla.org/Media/WebRTC/Privacy)

## 保留会议功能并确认结果

1. 在用户实际使用的浏览器和配置文件打开目标检测页，等待 DNS 与 WebRTC 测试各自完成。记录时间、浏览器/版本、窗口模式、两项原文状态，以及出口是否符合预期的脱敏结论。读取网页源码或远端抓取结果不等于在用户浏览器完成检测。
2. 页面持续加载、脚本报错、STUN/TURN 超时、服务不可达、测试被拦截或状态未更新时，记为“未完成/无法判定”。即使界面因未收到候选地址给出“已禁用或无泄露”，有这些异常也不能据此验收无泄露，应先排除检测失败。
3. 若仍出现不符合目标的地址，区分 host、server-reflexive、relay 候选和实际连接出口。只记录地址类别、候选类型、协议及与预期出口是否一致；原始 IP、SDP、ICE 凭据、Cookie、认证头和完整 URL 查询串留在本机，不放进公开报告。必要的 NetLog 读取遵守 [平台排查中的最小化规则](platform-troubleshooting.md)。
4. 保留会议功能的方案还须由用户在其会议服务中确认加入、双向音视频、所需屏幕共享/数据功能正常。麦克风预览或一次 TCP 握手不能代替通话验证；不要擅自呼叫联系人。TCP 回退可能降低媒体质量，也可能因服务能力限制失败。[RFC 8828 第 5、7 节](https://datatracker.ietf.org/doc/html/rfc8828)
5. 用户要求覆盖其他浏览器、配置文件或隐私窗口时，分别验证；不为当前浏览器的验收强制扩大任务。没有测试就标明未覆盖，不推广为整台电脑、所有应用或未来网络切换后的保证。页面通过但 API 仍可用是可能的，按“本次未观察到泄露”交付，不写“WebRTC 已彻底关闭”。

不要为了页面变绿而一键阻断全机 UDP、删除全部 ICE/TURN 配置、默认禁用 IPv6或修改无关应用规则。若需要会议站点例外，只在当前机制支持、作用范围清楚并已获授权时使用；Chrome 按 URL 的管理策略只匹配 origin，不可承诺只放行某个会议路径。例外站点与检测页应分别复测，检测页通过不代表例外站点也受同样限制。

## 精确回滚

保存“原值、原先是否缺省、控制来源、修改范围、恢复动作”，不要只记一个默认值。撤回启动参数时只移除本次新增项，正常重启并复核；已有扩展或策略控制的设置通过原控制入口恢复，不清除用户原有策略。Firefox 原先采用默认值的项目使用该项的重置操作；原先为用户设置则恢复原值，不重置整个配置文件。[Firefox 单项重置说明](https://support.mozilla.org/en-US/kb/about-config-editor-firefox)

会议回归或试验无效时，只撤销本次 WebRTC 变更，再检查会议与检测页；不顺带回滚已验证的 DNS、TUN 或中国软件兼容修复。最终记录使用的是“路由保护”“限制非代理 UDP”还是“禁用 PeerConnection”，并保留检测范围、未完成项及功能代价。
