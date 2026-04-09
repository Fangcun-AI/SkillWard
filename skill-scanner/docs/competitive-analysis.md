# AI Agent/Skill Security Scanner 竞品对比分析

> 更新日期: 2026-03-24

## 一、竞品概览

| 维度 | FangcunGuard Skill Scanner (我们) | Snyk Agent Scan | Tencent AI-Infra-Guard |
|------|--------------------------|-----------------|----------------------|
| **产品定位** | AI Agent Skill 安全扫描器 | AI Agent/MCP/Skill 安全扫描器 | AI 全栈红队平台 |
| **开源情况** | 开源 (Apache 2.0) | 开源 (GitHub) | 开源 (GitHub) |
| **核心技术** | 静态分析 + YARA + LLM-as-Judge + 行为数据流分析 | LLM Judges + 确定性规则 + 云端API | ReAct AI Agent 驱动 + 多Agent协作 |
| **UI 界面** | Guardian UI (Next.js, 自研) | Skill Inspector Web UI (labs.snyk.io) | Web Dashboard (localhost:8088) |
| **MCP 扫描** | 通过 Cloud Defense 集成 | 原生支持 (MCP server 扫描) | 原生支持 (MCP server + 远程URL扫描) |
| **CI/CD 集成** | SARIF + GitHub Actions + pre-commit | CLI + Background Mode (MDM) | CLI + API |
| **商业产品** | FangcunGuard Cloud Defense (企业版) | Snyk Evo (企业监控) | 无明确商业版 |

---

## 二、Snyk Agent Scan 详细介绍

### 2.1 产品概述
Snyk Agent Scan 是 Snyk（2025年收购 Invariant Labs 后）推出的 AI Agent 安全扫描器。提供 CLI 工具和 Web UI 两种使用方式。企业级产品为 **Evo AI-SPM** (AI Security Posture Management), 于 2026年3月23日 RSA 大会上发布 GA 版。

### 2.2 核心检测技术
- **LLM-based Judges**: 多个定制化 LLM judge 分析自然语言指令 (如 SKILL.md), 检测 prompt injection、tool poisoning、tool shadowing、toxic flows
- **确定性规则**: 传统模式匹配和静态检查, 用于硬编码密钥、凭证处理、已知恶意 payload
- **云端 API 验证**: 本地检查 + Snyk 云端 API 深度分析
- **自动发现**: 扫描本机 agents 配置文件, 自动发现 Claude Code/Desktop, Cursor, VS Code, Windsurf, Gemini CLI, OpenClaw, Kiro, Codex 等
- **后台模式**: MDM/Crowdstrike 集成, 定期扫描上报 Snyk Evo 平台

### 2.3 检测能力 (15+ 风险类型)
**MCP 相关:** Prompt Injection, Tool Poisoning, Tool Shadowing, Toxic Flows

**Skill 相关:** Prompt Injection, Malware Payloads, Untrusted Content, Credential Handling, Hardcoded Secrets

**宣称性能:** CRITICAL 级检测器 **90-100% recall**, 在 skills.sh Top 100 合法 skill 上 **0% 误报率**

### 2.4 UI 界面
- **Skill Inspector** (https://labs.snyk.io/experiments/skill-scan/): 免费在线 Web 工具, 粘贴 skill 即可获得 8 个威胁类别的即时评估
- **CLI**: `uvx snyk-agent-scan@latest`, 支持 `--json`、`--skills` 等参数 (**注意: 需要 Snyk API token, 依赖云端**)
- **Snyk Platform Dashboard**: 企业版提供完整的 Evo AI-SPM 仪表盘, 含 AI-BOM、风险评分、策略执行
- **Registry 嵌入**: 安全评分直接显示在合作伙伴 registry 的 skill 页面上

### 2.5 开源模式
- CLI 代码 Apache-2.0 开源 (~2,000 stars), 但 **不接受外部贡献**
- **依赖 Snyk 云端 API**, 离线无法使用 (关键差异!)
- 代码 89.7% Python, 5.8% JavaScript
- 企业版 Evo AI-SPM 为商业产品

### 2.6 重要研究成果
- **ToxicSkills 研究** (2026年2月): 扫描 ClawHub + skills.sh 上 3,984 个 skills
  - 13.4% (534个) 含至少一个 Critical 级问题
  - 1,467 个恶意 payload
  - 36% 存在 prompt injection 风险

### 2.7 合作伙伴与生态
- **Vercel**: skills.sh 上每次 `npx skills` 安装前自动触发 Snyk 扫描
- **Tessl**: Registry 中每个公开 skill 都带 Snyk 安全评分
- **Evo AI-SPM**: 包含 Discovery Agent、Risk Intelligence Agent、Policy Agent 三个组件

### 2.8 ⚠️ 重要: Snyk 对 pattern-matching scanner 的攻击
Snyk 于 2026年3月发布博客 **["Why Your 'Skill Scanner' Is Just False Security"](https://snyk.io/blog/skill-scanner-false-security/)**, 直接批评基于 pattern-matching 的社区 scanner (点名 SkillGuard, Skill Defender, Agent Tinman), 认为:
- 纯模式匹配无法理解上下文
- 需要行为分析才能抓到真正威胁
- 社区 scanner 无法检测真实恶意 skill, 还经常把自己标记为恶意

**回应策略**: 我们的 skill-scanner 不是纯 pattern-matching — 我们有 LLM-as-Judge、行为数据流分析、Meta-Analyzer 二次验证等多引擎。但需要在对外宣传中明确强调这一点, 避免被误归类为 "纯规则匹配" 工具。

**来源:**
- [GitHub - snyk/agent-scan](https://github.com/snyk/agent-scan)
- [Skill Inspector](https://labs.snyk.io/experiments/skill-scan/)
- [ToxicSkills 研究](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)
- [Snyk + Vercel](https://snyk.io/blog/snyk-vercel-securing-agent-skill-ecosystem/)
- [Snyk + Tessl](https://snyk.io/blog/snyk-tessl-partnership/)
- [Why Your Skill Scanner Is Just False Security](https://snyk.io/blog/skill-scanner-false-security/)
- [Snyk RSA 2026: Evo AI-SPM](https://snyk.io/news/snyk-launches-agent-security-solution/)
- [From SKILL.md to Shell Access](https://snyk.io/articles/skill-md-shell-access/)

---

## 三、Tencent AI-Infra-Guard 详细介绍

### 3.1 产品概述
腾讯朱雀实验室 + Keen Security Lab 联合开发的 AI 全栈红队平台 (A.I.G), 当前版本 **V4.0**。使用 **Go** 语言编写, **MIT 许可证**开源。已从最初的 AI 基础设施漏洞扫描扩展为完整的自主 Agent 生态安全平台, 覆盖 OpenClaw 安全扫描、Agent Scan、Skills Scan、MCP Scan、AI Infra Scan、LLM 越狱评估等方向。

### 3.2 核心检测技术

**A. ReAct (Reasoning + Acting) AI Agent 框架:**
不依赖纯静态规则匹配, 而是用 AI Agent 自主驱动安全评估:
1. 攻击面映射 — 分析项目文档、目录结构、关键代码
2. 风险模型匹配 — 与预定义安全风险类别交叉比对
3. 动态测试 — 自主执行命令模拟攻击者技术确认可利用性
4. 报告生成 — 输出详细风险报告和修复建议

**B. 多 Agent 协作扫描 (Agent-Scan 模块):**
多个专业化子 Agent 协同工作: 主 Agent、SSRF Agent、配置扫描 Agent、漏洞检测 Agent、Agent 安全审查员、数据泄露检测 Agent。覆盖 OWASP ASI 合规、授权绕过、间接注入、工具滥用、数据泄露等。

**C. MCP 安全检测:** 14 大类安全风险 (tool poisoning, 数据窃取/泄露, 命令注入, 供应链攻击, 硬编码密钥, 不安全配置, 隐私泄露等), 支持源码和远程 URL 两种扫描方式

**D. AI 基础设施扫描:** 指纹识别 43+ AI 框架组件 (Ollama, ComfyUI, vLLM, n8n, Triton, Dify, NextChat, LobeChat 等), 覆盖 589+ 已知 CVE 漏洞

**E. OpenClaw 安全扫描 (ClawScan 模块):** 一键 OpenClaw 安全风险评估 (不安全配置、Skill 风险、CVE 漏洞、隐私泄露)

**F. LLM 越狱评估:** Prompt 输入检测, 测试 LLM 安全性

### 3.3 UI 界面
- **Web Dashboard** (localhost:8088): 现代化 Web 界面, 一键扫描, 实时进度追踪
- **中英文双语**: 完整的国际化支持
- **统一设置面板**: 插件管理、模型管理合并到统一面板
- **Docker 部署**: 支持容器化快速部署
- **CLI + REST API**: 完整的命令行和 API 接入
- **API 文档**: 内置 Swagger (localhost:8088/docs/index.html)
- **在线托管版**: matrix.tencent.com/clawscan/skill.md (OpenClaw Skill 扫描)
- 官网: https://tencent.github.io/AI-Infra-Guard/

### 3.4 生态支持
- **OpenClaw**: 一等公民支持, ClawScan 模块
- **MCP Servers**: 源码 + 远程 URL 扫描
- **Agent 平台**: 支持 Dify、Coze 等平台上运行的 Agent workflow
- **AI 框架**: 43+ 组件 (Ollama, ComfyUI, vLLM, n8n, Triton 等)

### 3.5 版本演进
- **V2 (2025)**: 引入 ReAct AI Agent 框架做 MCP 安全分析, 新增 100+ AI 组件 CVE
- **V4 (2025-2026)**: 从 AI 基础设施扫描扩展为完整自主 Agent 生态安全平台, 新增 OpenClaw Scan、Agent-Scan、Skills Scan 模块
- **2026年3月**: 腾讯将微信 10 亿用户接入 OpenClaw AI Agent, ClawScan 安全扫描随之变得更重要

### 3.6 实战成果
- 对主流 MCP 市场和腾讯内部业务进行自动化扫描, 发现 **4000+** 新 AI 安全风险
- 发现 React2Shell 漏洞 (CVE-2025-55182) 影响 Dify、NextChat、LobeChat

### 3.7 关联项目
- **AICGSecEval (A.S.E)**: 腾讯悟空代码安全团队的代码安全评估 benchmark, 支持评估 agentic programming 工具

**来源:**
- [GitHub - Tencent/AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)
- [中文 README](https://github.com/Tencent/AI-Infra-Guard/blob/main/README_CN.md)
- [官方文档](https://tencent.github.io/AI-Infra-Guard/)
- [DeepWiki - UI 文档](https://deepwiki.com/Tencent/AI-Infra-Guard/8-user-interfaces)
- [V2 技术评测 (Medium)](https://medium.com/@foraisec/a-technical-review-of-ai-infra-guard-v2-new-mcp-server-security-analysis-tool-6733a7f319e0)
- [CSDN 博客 - MCP 安全检测](https://blog.csdn.net/Tencent_SRC/article/details/147796460)
- [腾讯微信接入 OpenClaw](https://www.technology.org/2026/03/23/tencent-connects-wechats-billion-users-to-openclaw-ai-agent/)

---

## 四、FangcunGuard Cloud Defense (商业版) 详细介绍

### 4.1 产品概述
FangcunGuard Cloud Defense 是企业级 AI 安全平台, 2025年1月发布, 通过 **FangcunGuard Security Cloud Control** 管理。Skill Scanner 是其开源组件之一。平台覆盖 AI 安全全生命周期, 已在 AWS Marketplace 上线。

### 4.2 四大核心支柱
1. **AI Cloud Visibility**: 自动发现分布式云环境中的 AI 资产 (模型、Agent、MCP server), 映射 MCP 连接的 workflow 和 agent-to-tool 交互
2. **AI Supply Chain Risk Management**: 扫描 AI 模型文件、数据集、仓库和 MCP server, 检测恶意代码、投毒数据、不安全工具
3. **AI Model & Application Validation**: 算法红队测试, 几分钟内完成 (手动需数周), 支持 200+ 风险子类别, 多语言多轮对抗测试
4. **AI Runtime Protection**: 实时护栏, 检查 MCP 流量和 Agent 行为, 防护 prompt injection、DoS、数据泄露、未授权工具使用

### 4.3 DefenseClaw (开源安全 Agent 框架)
2026年3月 RSA 发布的开源框架, 捆绑 **五个扫描引擎**:
- **skill-scanner** (就是我们)
- **mcp-scanner**
- **a2a-scanner**
- **CodeGuard** 静态分析
- **AI Bill-of-Materials 生成器**

DefenseClaw 在执行前扫描每个 skill、tool、plugin 和生成的代码, 并提供运行时内容扫描。

### 4.4 UI 界面
通过 **FangcunGuard Security Cloud Control** Dashboard 管理:
- **主仪表盘**: AI 安全健康状况全局视图, 风险评分和建议
- **Assets 面板**: AI 模型、应用、Agent、MCP server 的发现和管理
- **Validation 面板**: 算法红队测试配置和结果
- **Runtime Protection 面板**: 护栏设置和监控
- **AI Events 屏幕**: 策略触发时的执行动作记录
- **AI BOM**: 所有 AI 软件资产的集中视图
- **Explorer Edition** (免费自助版): RSA 2026 发布, 同一个红队测试引擎, ~20分钟完成模型测试, 零成本

Gartner Peer Insights 评价: "直观" "易于导航", 可自动标记可疑活动并建议纠正措施。

### 4.5 时间线

| 日期 | 事件 |
|------|------|
| 2025年1月 | Cloud Defense 发布 |
| 2025年3月 | GA 正式上线 |
| 2026年2月 | 重大扩展: AI BOM、MCP Catalog、Agentic 护栏、高级红队、AI-Aware SASE |
| 2026年3月 GTC | FangcunGuard Secure AI Factory with NVIDIA |
| 2026年3月23日 RSA | **DefenseClaw** 开源框架、**Explorer Edition** 免费版、Zero Trust for AI Agents、身份治理 |

### 4.6 竞争定位
- FangcunGuard 聚焦**网络层/基础设施级** AI 安全 — 无需在端点安装 agent, 通过网络可见性发现和保护
- Snyk 聚焦**开发者优先**的应用安全
- 两者互补多于直接竞争: FangcunGuard 保护 AI 基础设施/运行时, Snyk 保护开发工作流

**来源:**
- [FangcunGuard Cloud Defense 官网](https://www.fangcunguard.com)
- [FangcunGuard Cloud Defense Data Sheet](https://www.fangcunguard.com/c/en/us/products/collateral/security/cloud-defense/cloud-defense-ds.html)
- [Cloud Defense 发布 (2025.01)](https://newsroom.fangcunguard.com/c/r/newsroom/en/us/a/y2025/m01/fangcunguard-unveils-cloud-defense-to-secure-the-ai-transformation-of-enterprises.html)
- [Agentic Era 扩展 (2026.02)](https://newsroom.fangcunguard.com/c/r/newsroom/en/us/a/y2026/m02/fangcunguard-redefines-security-for-the-agentic-era.html)
- [Agentic Workforce (2026.03)](https://newsroom.fangcunguard.com/c/r/newsroom/en/us/a/y2026/m03/fangcunguard-reimagines-security-for-the-agentic-workforce.html)
- [DefenseClaw 公告](https://blogs.fangcunguard.com/ai/fangcunguard-announces-defenseclaw)
- [Explorer Edition](https://blogs.fangcunguard.com/ai/introducing-fangcunguard-explorer)
- [RSA 2026 报道 (SiliconANGLE)](https://siliconangle.com/2026/03/23/fangcunguard-debuts-new-ai-agent-security-features-open-source-defenseclaw-tool/)
- [Gartner Peer Insights](https://www.gartner.com/reviews/product/fangcunguard)

---

## 五、深度对比分析

### 5.1 检测引擎对比

| 检测技术 | FangcunGuard Skill Scanner | Snyk Agent Scan | Tencent AI-Infra-Guard |
|---------|-------------------|-----------------|----------------------|
| YAML 签名规则 | ✅ 丰富的签名库 | ❌ 不明确 | ❌ 不明确 |
| YARA 规则 | ✅ 14+ YARA 规则文件 | ❌ | ❌ |
| LLM-as-Judge | ✅ 多模型支持, 共识模式 | ✅ 多个定制 LLM Judge (云端) | ✅ ReAct AI Agent 驱动 |
| 行为数据流分析 | ✅ AST/dataflow + bash taint | ❌ | ✅ 代码数据流分析 |
| Meta 二次验证 | ✅ 降低误报 | ❌ | ❌ |
| 字节码分析 | ✅ .pyc 完整性检查 | ❌ | ❌ |
| Pipeline 分析 | ✅ Shell 命令链风险 | ❌ | ❌ |
| MCP Server 扫描 | 通过 Cloud Defense 集成 | ✅ 原生支持 | ✅ 原生支持 |
| VirusTotal 集成 | ✅ | ❌ | ❌ |
| 多语言支持 | Python + Bash 为主 | 不明确 | ✅ Python/TS/Java/Kotlin/C# |

### 5.2 UI/UX 对比

| 维度 | FangcunGuard Skill Scanner | Snyk Agent Scan | Tencent AI-Infra-Guard |
|-----|-------------------|-----------------|----------------------|
| Web UI | ✅ Guardian UI (Next.js) | ✅ Skill Inspector (Web) | ✅ Web Dashboard |
| CLI | ✅ | ✅ | ✅ |
| API | ✅ FastAPI | ✅ Cloud API | ✅ REST API |
| 在线免费扫描 | ❌ | ✅ labs.snyk.io | ❌ (需本地部署) |
| 国际化 | Guardian UI 有 i18n | 英文 | ✅ 中英双语 |
| 四阶段可视化 | ✅ (静态/LLM/沙箱/追踪) | ❌ | ❌ |
| 扫描历史 | ✅ Guardian UI history | 通过 Snyk Evo | 有 |

### 5.3 生态与集成对比

| 维度 | FangcunGuard Skill Scanner | Snyk Agent Scan | Tencent AI-Infra-Guard |
|-----|-------------------|-----------------|----------------------|
| GitHub Actions | ✅ 可复用 workflow | ❌ (CLI 集成) | ❌ |
| Pre-commit Hook | ✅ | ❌ | ❌ |
| SARIF 输出 | ✅ GitHub Code Scanning | ❌ | ❌ |
| 企业后台监控 | FangcunGuard Cloud Defense | Snyk Evo + MDM | ❌ |
| Agent 自动发现 | ❌ | ✅ (Cursor/Claude/Gemini/Windsurf) | ❌ |
| 策略系统 | ✅ 丰富 (strict/balanced/permissive + 自定义) | 有限 | 有限 |

---

## 六、我们的差异化优势

### 独有优势
1. **多引擎深度检测**: 10个分析器 (静态/字节码/Pipeline/行为/LLM/Meta/VT/Cloud Defense/Trigger/Cross-Skill), 远超竞品
2. **Meta-Analyzer 降噪**: 二次 LLM 验证过滤误报, 竞品没有这个能力
3. **YARA 规则引擎**: 专业级恶意代码签名匹配
4. **丰富的策略系统**: strict/balanced/permissive 预设 + 完全自定义 YAML 策略
5. **四阶段扫描流水线** (Guardian UI): 静态 -> LLM -> 沙箱 -> 追踪, 可视化完整
6. **CI/CD 深度集成**: SARIF + GitHub Actions + pre-commit, DevSecOps 友好
7. **FangcunGuard AI Security Framework 威胁分类**: 专业的 AITech 威胁体系

### 关键差异化: 离线 vs 云端依赖
- **我们**: 完全离线运行, 不依赖任何云端服务 (LLM 可本地部署)
- **Snyk**: CLI 必须依赖 Snyk 云端 API, 离线无法使用 — 这对企业内网/合规场景是硬伤
- **腾讯**: 可本地部署, 但需要 LLM 配置

### 需要改进/追赶的地方
1. **Agent 自动发现**: Snyk 可以自动扫描本机上所有 agent 配置, 我们还没有
2. **在线免费扫描**: Snyk 有 Skill Inspector 在线版, 腾讯有 matrix.tencent.com, 降低使用门槛
3. **MCP 原生扫描**: Snyk 和腾讯都直接支持连接 MCP server 进行扫描
4. **多语言支持**: 腾讯的 AI Agent 驱动方式支持更多编程语言
5. **Registry 嵌入**: Snyk 已嵌入 Vercel skills.sh 和 Tessl Registry, 形成供应链卡点
6. **对外叙事**: Snyk 正在通过博客攻击 "pattern-matching scanner", 我们需要在宣传中明确强调多引擎架构, 避免被误归类

---

## 七、演示思路建议

### 7.1 推荐演示 Skills

**恶意 Skill 演示 (检测能力展示):**
| Skill | 攻击类型 | 演示亮点 |
|-------|---------|---------|
| `evals/skills/data-exfiltration/environment-secrets` | 数据泄露 | 读取环境变量并外发 |
| `evals/skills/command-injection/eval-execution` | 命令注入 | eval() 执行用户输入 |
| `evals/skills/prompt-injection/jailbreak-override` | Prompt 注入 | 越狱覆盖系统指令 |
| `evals/skills/obfuscation/base64-payload` | 代码混淆 | Base64 编码恶意代码 |
| `evals/skills/backdoor/magic-string-trigger` | 后门 | 魔术字符串触发后门 |
| `test_script/toxic_skills/special/dev-env-doctor` | 凭证窃取 | 伪装成诊断工具偷 API key |
| `test_script/toxic_skills/special/content-watchdog` | 内容劫持 | 伪装成监控工具抓取任意URL |
| `evals/skills/adversarial/*` | 对抗性 Skill | 20个伪装成正常工具的恶意 skill |

**安全 Skill 演示 (误报率展示):**
| Skill | 说明 |
|-------|------|
| `evals/skills/safe-skills/simple-math` | 简单数学运算, 应判定为安全 |
| `evals/skills/safe-skills-2/file-validator` | 文件验证器, 应判定为安全 |

### 7.2 视频演示脚本建议

**场景一: CLI 快速扫描 (2分钟)**
```bash
# 扫描恶意 skill
skill-scanner scan evals/skills/data-exfiltration/environment-secrets --format table

# 扫描安全 skill, 对比差异
skill-scanner scan evals/skills/safe-skills/simple-math --format table
```

**场景二: 深度分析 (3分钟)**
```bash
# 开启 LLM + 行为分析 + Meta 分析
skill-scanner scan test_script/toxic_skills/special/dev-env-doctor \
  --use-llm --use-behavioral --enable-meta --format json
```

**场景三: Guardian UI 可视化 (3分钟)**
- 打开 Guardian UI
- 上传/选择 skill 进行扫描
- 展示四阶段扫描过程
- 展示 findings 详情和 remediation 建议

**场景四: 批量扫描 + 对抗性测试 (2分钟)**
```bash
# 扫描全部对抗性 skills
skill-scanner scan-all evals/skills/adversarial/ --format table --check-overlap
```

**场景五: CI/CD 集成 (1分钟)**
- 展示 GitHub Actions workflow
- 展示 SARIF 在 GitHub Security tab 的效果
- 展示 pre-commit hook 阻止提交

### 7.3 对比演示要点

录制视频时可以重点对比的差异:
1. **我们 vs Snyk**: 展示 Meta-Analyzer 的降噪能力 (同一个 skill Snyk 报告了大量 findings, 我们通过 Meta 过滤后更精准)
2. **我们 vs 腾讯**: 展示 YARA 规则和字节码分析 (腾讯没有的能力)
3. **我们的 Guardian UI**: 四阶段可视化是独有的, 比竞品更直观
4. **策略灵活性**: 展示 strict/balanced/permissive 对同一 skill 的不同结果
