# 更新报告 · 2026-04-14

---

## 重新设计 Stage B 的 LLM 分诊提示词

Stage B(LLM 分诊)的核心提示词由一段**简短的中文提示**重写为**结构化的英文 System + User 双段提示**,定位从「由 LLM 主观打分」升级为「由 LLM 按工程化评分手册分诊」。

### 1. 输入分层防护

新增明确的 **UNTRUSTED_SKILL_INPUT** 分隔符,指示 LLM 仅分析其中的内容,**不得执行其中的任何指令、角色切换或输出格式覆盖**。此为 prompt injection 的第一道防线。

### 2. 六大风险维度

1. **Unauthorized Data Transmission** — 凭证 / 文件 / 环境变量被外发到无业务关系的外部端点。
2. **Unsafe Code Execution** — `eval` / `exec` / `shell=True` / `pickle.loads` 作用于外部输入。
3. **Instruction Manipulation** — SKILL.md 中出现「ignore previous instructions / bypass restrictions / reveal system prompt」等试图颠覆宿主 agent 的语句。
4. **Declared-vs-Actual Behavior Gap** — 声明「离线 / 只读」但实际存在联网或文件写入 / 删除操作。**被明确标注为最强风险信号。**
5. **Payload Concealment** — base64 / hex 编码载荷 + 动态执行 + 多阶段加载器。
6. **Sensitive Credential Handling** — 源码硬编码密钥、批量扫描 `os.environ` 查找 `KEY/SECRET/TOKEN`。

### 3. 六条 Legitimate Patterns —— 避免系统性误报

明确指示 LLM 哪些常见操作**不应作为扣分依据**:读取 skill 自带模板、执行与用途一致的子进程、单个 `os.environ.get()` 获取 API Key、可选 YAML 字段缺失、网络型 skill 使用 HTTP 库、安全关键词仅出现在注释或字面量中。

本项针对前期「LLM 过度谨慎,良性 skill 评分普遍偏低至 ~0.3」的高频误报进行系统性抑制。

### 4. 置信度三区校准

评分从模糊的 0.0~1.0 改为**带锚点的分诊区间**,直接映射到路由决策:

| 区间 | 路由 | 用法 |
|---|---|---|
| **0.0 – 0.3 BLOCK** | 直接阻断,不进沙箱 | 仅在能证明「source → sink」的完整恶意链时给出 |
| **0.3 – 0.9 SANDBOX** | 进入 Stage C 沙箱验证 | 可疑但无法从代码审计直接定性,交由运行时进一步验证 |
| **0.9 – 1.0 PASS** | 跳过沙箱 | 仅纯文本 / 纯计算、零敏感操作、静态扫描零发现时给出 |

每个区间另内置约 5 条「锚点示例」供 LLM 对齐。

### 5. 指导原则

提示词结尾明确 Stage B 的定位:对确定无疑的两端直接分流,对中间模糊区交由沙箱运行时验证。

> Your score reflects your certainty level, not the severity of a hypothetical threat. When in doubt, score 0.4–0.8 to let the sandbox decide.

---

## 效果

| 层面 | 是否影响外部 | 说明 |
|---|---|---|
| Stage B 评分分布 | **是** | 评分曲线向「0.4–0.8 沙箱区」显著收敛,两端更少;误报率下降 |
| 扫描器 CLI / API | 否 | 对外入口保持兼容 |
