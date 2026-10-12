# 离线辅助脚本

脚本只读取显式提供的文件或生成一个新文件，不自动寻找用户配置，不访问网络、控制器或操作系统 DNS。输入和输出可能包含网络信息，放在仓库外的私有目录。不要将完整配置作为 issue 附件。

## 审查配置与保留项

```sh
python scripts/audit_mihomo.py /private/path/baseline.json
python scripts/audit_mihomo.py /private/path/baseline.yaml --compare /private/path/candidate.yaml --allow-process ExampleApp.exe --allow-outbound APP-DIRECT-IPV4
```

JSON 使用标准库；YAML 需要安装 PyYAML。参数中的路径只是位置示意，要替换为本机私有路径。

输出只包含数量、布尔值、字段类别和保留检查；不回显解析器 URL、节点地址、controller secret、原始异常或输入路径。报告固定包含 `dns_leak_status: not_tested`：这是离线配置审查，不是网络或泄露检测。

比较检查：TUN 不变、已有节点对象和顺序保留、代理组与 provider 不变、其他配置不变。规则只允许列出的进程从原有 DIRECT 改向列出的出站；其他规则及次序必须保留。新增出站、DNS 和 sniffer 的变化仍需人工审查，不能把“保留检查通过”当成整体配置获准或安全证明。

DNS 字典采用保序比较，以发现域名策略优先级改变；无害的非策略 DNS 字典重排也会保守报告变化。其他普通对象不会仅因键顺序变化而报告差异。

退出码 0 表示摘要读取成功或保留检查通过；2 表示输入无法安全处理或保留检查失败。重复键、重复或循环的 YAML 容器别名及超过 16 MiB 的输入会被拒绝；标量别名可以使用。严格解析可能拒绝某些依赖 YAML 覆盖合并的复杂文件，可在私有目录使用客户端导出的规范 JSON 再比较。拒绝重复容器别名是为了避免短小 YAML 被指数展开。

## 生成 IPv4 兼容例外

仅当实际日志证明字面 IPv6 连接失败，且有可提取的 Host/SNI 和可用 IPv4 路径时使用。它不是完整 DNS 保护配置，也不替用户决定是否修改 TUN。

下面命令只演示接口；`2001:db8::10` 是文档保留地址，**不能当作实际修复地址**。真实使用时从本次故障证据中选取目标，填入实际进程、协议和端口。

```sh
python scripts/build_ipv4_exception.py --process ExampleApp.exe --ipv6 2001:db8::10 --protocol TLS --port 443 --outbound APP-DIRECT-IPV4 --output /private/path/ipv4-exception.js
```

`--process`、`--ipv6`、`--port` 可重复；`--protocol` 只选 HTTP 或 TLS。目标只接受 IPv6 单地址或 `/128`，不接受宽网段。所有关键参数都必须明确提供，没有真实进程或 IP 默认值。

生成的 `main(config)`：

- 追加命名的 `type: direct` / `ip-version: ipv4` 出站，保留已有节点。
- 只转换已存在的指定 `PROCESS-NAME,...,DIRECT` 规则，保留规则顺序。缺少规则时拒绝，已有同名但不同出站或代理组冲突时拒绝。
- 用 IPv6 `/128` 集合的 CIDR 补集和整个 IPv4 空间作为排除项，限定嗅探的目标地址、协议及端口。
- 显式设置 `force-dns-mapping: false`、`force-domain: []`。TUN、DNS、订阅节点和无关规则不变。
- 既有 sniffer 若与生成结果不一致则拒绝覆盖；生成脚本重复运行应得到同一结果。输出文件已存在且内容不同也不会被静默覆盖。

**范围区别：**路由按进程限缩，嗅探按目标 IP 和端口限缩。其他程序访问相同地址/端口也可能被嗅探。无 Host/SNI、ECH 或不支持的协议仍可能失败；仅强制 IPv4 不能转换纯 IPv6 地址。地址随 CDN/网络变化时须重新取证。

脚本是独立入口，不能直接覆盖含有其他逻辑的现有扩展。先备份、检查名称及 sniffer 冲突，再将逻辑合并到客户端支持的扩展层；测试最终生成配置与运行态。运行态的热加载不会自动执行 JavaScript，也不等于扩展已持久化。

## 测试

```sh
python -m unittest discover -s tests -v
```

测试只使用合成数据和临时目录。Node.js 可用时验证真实 JavaScript 执行、幂等性、原输入不变及配置保全；PyYAML 可用时覆盖 YAML 读取。缺少这些可选依赖时相关测试会跳过，需要检查输出，不能把跳过项当成通过。它们不证明真实软件、上游 DNS 或网络可用。
