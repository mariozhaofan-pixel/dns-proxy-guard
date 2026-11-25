# Windows：管理员 PowerShell 与可回滚的 DNS 试验

本流程将截图中“修改活动网卡 DNS → 清缓存 → 检查解析 → 必要时恢复”的思路用于实际故障排查。**截图的网卡名称和地址被截断，不能据此猜测。** 只有证据表明当前解析路径需要调整、且用户授权网络修复时才执行，不作为每次运行的默认改动。

## 管理员执行方式

优先使用运行环境提供的命令执行工具调用 PowerShell；需要提升权限时，采用该环境支持的提权机制，或在已具备管理员权限的会话中执行。先检查有效权限；工具可独立完成的步骤直接完成。Windows 弹出 UAC 时由用户处理；无提权能力、被拒绝或访问受限时说明具体阻碍，提供准确命令供用户执行，并在其完成后复核。不要通过界面自动化工具操作被其规则禁止的终端窗口，也不要声称本 skill 能解除工具或系统的权限限制。

## 确认接口、保存原状和解析器

1. 读取活动物理接口、接口索引、相关路由，以及 IPv4 和 IPv6 的现有 DNS 服务器。核实配置的来源：DHCP 自动获取或静态地址；如 IPv4/IPv6 来源不同，分别记录。只读 `Get-DnsClientServerAddress` 的地址不一定足以判断来源；用系统可支持的方法交叉确认。接口名称可能改变，修改前核对接口索引和名称。
2. 将实际接口、地址顺序、每个地址族的配置来源、相关 DNS 设置以及恢复命令保存在本机私有备份中；不覆盖已有用户配置。原状或恢复方式无法确定时不执行。IPv4/IPv6 来源混合且没有经过验证的逐族恢复方法时，默认停止网卡 DNS 试验；不要假定这两个 DNS cmdlet 可以按地址族独立重置。
3. 确认 Clash/Mihomo、TUN 与 DNS 接管工作正常，查当前内核配置和系统实际监听/路由，验证候选 DNS IP 从将要修改的接口可达、能正确应答且查询确经预期路径。TUN 地址、虚拟网卡地址和 DNS 监听地址可能不同；不要把 TUN 地址或 fake-ip 地址自动当成 DNS 服务器。截图未显示的 DNS 地址、接口别名及具体命令参数必须来自当前机器，不能杜撰。
4. 确认代理退出或网络切换时如何恢复；仅在能够恢复的前提下进行临时试验。不修改其他接口，不附带更改系统 IPv6、TUN 配置、全局 UDP 或国内应用路由。

## 应用、测试和恢复

管理员 PowerShell 的语法示例如下；`<接口索引>`、`<已验证的DNS地址>` 仅作占位，必须先替换成实测值，不可照抄：

```powershell
Set-DnsClientServerAddress -InterfaceIndex <接口索引> -ServerAddresses @('<已验证的DNS地址>')
ipconfig /flushdns
```

`-ServerAddresses` 写入的是静态设置，会覆盖该接口的 DHCP DNS；`ipconfig /flushdns` 只清理 Windows DNS 缓存，不会配置服务器或修复路由。执行后重新读取接口与地址，检查解析器和出站，再按主流程在内置浏览器完成 DNS 与 WebRTC 检测；如指定了其他浏览器，也分别复测。DNS 试验无效、造成联网问题或无法验证其作用时，恢复原状并复核；仅 WebRTC 仍失败时，不因此撤销已验证有效的 DNS 修复，而是单独排查。检测未完成则不能声称有效；保留可证实的独立修复，无法验证的试验恢复原状。已有正常国内软件不应顺手改其路由。

原来为 DHCP 自动获取且确认重置范围符合备份时，可对同一接口使用：

```powershell
Set-DnsClientServerAddress -InterfaceIndex <接口索引> -ResetServerAddresses
ipconfig /flushdns
```

`-ResetServerAddresses` 是恢复 DHCP 默认来源，**不能恢复原来静态填写的 DNS**。原先为静态或不同地址族来源混合时，按备份和当前系统支持的具体方式逐项恢复原地址、顺序和来源，必要时借助 Windows 网络设置；不确定重置对另一地址族的影响时先停止。恢复后再读取 IPv4/IPv6 的来源与地址并验证网络。实验成功也要说明其依赖 Clash/TUN 运行以及原状恢复位置，不把它悄悄当作永久 DNS。

来源：[Microsoft Set-DnsClientServerAddress](https://learn.microsoft.com/en-us/powershell/module/dnsclient/set-dnsclientserveraddress)、[Microsoft Get-DnsClientServerAddress](https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientserveraddress)、[Microsoft ipconfig](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig)、[Mihomo TUN](https://wiki.metacubex.one/config/inbound/tun/)。
