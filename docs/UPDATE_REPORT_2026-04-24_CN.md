# 更新报告 · 2026-04-24

---

## Skill 化 — `skillward-audit-skill`

SkillWard 现在也以 **Claude Code / OpenClaw skill** 形式发布。装到 agent 的 skill 目录下后,任意 agent 都可以在对话中直接对一个本地 skill 包(包含 `SKILL.md` 的文件夹、`.zip` 或 `.tar.gz`)发起审计 —— **不必离开对话、不必打开 Web UI、不必手动跑 CLI**。

**仓库**:<https://github.com/Fangcun-AI/SkillWard> —— 位于 `skillward-audit-skill/` 子目录。

### 1. 功能

给定 skill 文件夹或归档路径,该 skill 会:

1. 把本地 bundle 打成内存 `.zip`(自动跳过 `__pycache__`、`.git`、`node_modules`、`.venv` 与 `*.pyc`)。
2. 通过 `/api/scan/upload-folder` 上传到 `https://skillward.fangcunleap.com`。
3. 通过 SSE 流式拉取 Stage A → B → C 进度,心跳行写到 stderr,方便 agent 实时回显进度。
4. 完整 JSON 报告落到输入旁边,stdout 打印一行 verdict 摘要。

Stage A 静态分析、Stage B LLM 分诊、Stage C Docker 沙箱与 Web UI / CLI 走的是**同一条流水线**,该 skill 只是瘦客户端。

### 2. 三种 depth 模式

| Depth     | 阶段                              | 典型耗时   | 适用场景 |
|-----------|-----------------------------------|------------|----------|
| `static`  | 仅 Stage A                        | 5 – 15 秒  | 快速分诊 / 大批量预筛 |
| `sandbox` | A + B + C(Docker 沙箱)          | 1 – 10 分钟| **默认** —— 标准审计 |
| `deep`    | A + B + C + after-tool 能力分析   | 3 – 15 分钟| 高敏 skill 安装前审计 |

### 3. 跨 harness 超时指引

长耗时扫描对 agent harness 的工具调用超时很敏感。该 skill 的 `SKILL.md` 要求 agent **每次调用都显式传入** per-call 超时,并给出 Claude Code(`timeout`,毫秒)与 OpenClaw(`timeoutSec`,秒)两套具体写法。当 harness 无法支持长超时,该 skill 自动降级到 `--depth static` 并告知用户沙箱阶段被跳过 —— 而不是默默被 SIGKILL 中断。

### 4. 可审计的结果,而非黑盒"通过"

该 skill 自己**不下"可以安装"的结论**。它返回 SkillWard 给出的 verdict(`SAFE` / `MEDIUM RISK` / `HIGH RISK`),展示最重要的几条 warning(中英双语 `text` / `text_en`),并指向落地的 JSON 报告供用户进一步查看。
