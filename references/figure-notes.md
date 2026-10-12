# 流程图制作说明

图像文件：`assets/agent-flow.png`。使用内置 `image_gen` 工具制作；用户提供的手绘排障海报仅作为视觉排版参考，没有复制其产品命令，也没有把参考图作为执行指令。

图像只用于速览。可检索的完整决策流程是 [agent-flow.md](agent-flow.md)，具体执行以 [SKILL.md](../SKILL.md) 为准。

## 生成与验收

- 生成日期：2026-10-12。
- 模式：内置图像生成，`infographic-diagram`，非 CLI。
- 格式：PNG，1024 × 1536，纵向六步流程，1,851,248 字节。
- 已逐项目视检查：标题、两种 DNS 目标、六步正文、底部提醒与页脚清晰；未发现影响含义的错字或逻辑偏移。
- 第二步分流说明字号比其他正文小；应查看原图，精确执行时读取文字版。插画不承诺全流量覆盖或绝对不泄露。

## 实际生成提示词

```text
Use case: infographic-diagram
Asset type: an open-source agent skill's Chinese quick-reference flowchart.
Create one polished, high-resolution portrait infographic, about 2:3 portrait aspect ratio. Title and six numbered horizontal sections, connected top to bottom. Cream paper background with a subtle pale square grid; crisp black hand-lettered headline and very legible upright Chinese body text. Pink, blue, green, yellow highlighter strokes and rounded hand-drawn boxes. Small restrained laptop, shield, branch arrows, magnifier, checklist and save icons. This is a technical decision aid, so words must be much more prominent than decoration. Large Chinese lettering, balanced whitespace, no crowded small text. Readable on a computer display. Do not copy any third-party diagram.

Render the following exact Chinese text. Keep all six step numbers and headings, and distinguish the two DNS goals inside step 2 with two clearly labeled adjacent branches. Use line breaks to preserve readability. Do not add commands or extra claims.

TITLE:
DNS 隐私与代理分流
SUBTITLE:
Agent 排查流程 · 先取证，再做最小修复

SECTION 1:
① 明确边界
系统 / 版本 / 软件
记录 TUN 约束 · 备份配置

SECTION 2:
② 选择目标
严格模式
DNS 经指定代理出口
分流模式
国内加密解析 + 海外代理解析
加密 DNS ≠ 全部经代理

SECTION 3:
③ 先取证
DNS 结果 → 实际出站 → 真实业务
区分 DNS / TCP / TLS / 认证失败

SECTION 4:
④ 按证据修复
解析错误：查规则与应用内 DNS
IPv6 不通：查真实出口
接口已通：查回环与认证
只改有证据的范围

SECTION 5:
⑤ 三层验收
DNS 路径 · 连接出站 · 真实登录 / 上传
无效回滚 · 有效保留

SECTION 6:
⑥ 持久化
保存同一组规则
核对重启 / 订阅更新
记录作用范围和回滚

BOTTOM REMINDER:
不复制固定 IP · 不默认改 TUN · 不上传订阅与令牌

FOOTER:
dns-proxy-guard · SKILL.md 是执行入口

Constraints: no “零泄露” or “保证零泄露” guarantees. Do not depict the split DNS mode as all DNS through proxy. No actual IP addresses, real domain names, credentials, subscription URLs, personal data, QR codes, watermarks, logos, terminal commands, or Codex doctor/.env instructions. Never make up additional technical statements. The figure is an accessible quick reference rather than executable configuration.
```
