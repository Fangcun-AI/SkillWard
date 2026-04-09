# 使用说明

`guardian.py` 为 SkillWard 的命令行入口，提供 Skill 安全扫描的完整流水线。

---

## 一、整体流程

<details>
<summary><b>Stage A · 静态分析</b>：秒级完成，快速发现已知恶意模式和可疑信号</summary>

通过 YARA 规则和正则表达式扫描 Skill 代码和配置，识别已知恶意模式（凭证窃取、代码注入等），校验 Skill 声明的权限和能力是否与实际代码行为一致，检测隐藏文件、编码混淆、提示词投毒等特征。

</details>

<details>
<summary><b>Stage B · LLM 研判</b>：语义推理，判断意图并给出安全置信度</summary>

在静态信号之上加入语义推理，能够高置信度分类的 Skills 在此阶段直接完成判定；仍存在不确定性的 Skills 进入 Stage C 沙箱验证。

</details>

<details>
<summary><b>Stage C · 沙箱验证</b>：实际运行可疑 Skill，让隐藏风险无处遁形</summary>

容器内 Agent 端到端执行 Skill，定制化 Guard 全程监控。预置蜜罐诱饵引诱恶意 Skill 主动暴露凭证窃取、数据外泄、供应链攻击等隐藏行为。
</details>

---

## 二、快速开始

环境要求：Python 3.10+ / Docker（运行沙箱）。

```bash
# 克隆仓库

git clone https://github.com/Fangcun-AI/SkillWard.git
cd SkillWard

# 安装依赖
pip install -r requirements.txt && pip install -e ./skill-scanner

# 拉取 Docker 镜像
# x86_64
docker pull fangcunai/skillward:amd64
# Apple Silicon / ARM
docker pull fangcunai/skillward:arm64

# 配置 .env
cp guardian-api/.env.example guardian-api/.env
```

配置 `guardian-api/.env`  [configuration_CN.md](configuration_CN.md)。

```bash
# 完整流程
python guardian-api/guardian.py -i /path/to/skills-dir -o ./output --enable-after-tool --parallel 4 -v

# 仅运行预扫描（静态匹配+LLM分析）
python guardian-api/guardian.py -i /path/to/skills-dir --stage pre-scan -o ./output -v

# 仅运行沙箱检测
python guardian-api/guardian.py -i /path/to/skills-dir --stage runtime -o ./output --enable-after-tool --parallel 4
```

---


Stage C 在预构建镜像中启动 Agent，运行 `--stage runtime` 或完整流程前必须先拉取镜像。

| 架构 | 适用平台 | 镜像 tag |
|---|---|---|
| `amd64` (x86_64) | Intel / AMD CPU、Linux 服务器、Windows / WSL、Intel Mac | `fangcunai/skillward:amd64` |
| `arm64` (aarch64) | Apple Silicon Mac (M1/M2/M3/M4)、ARM Linux、树莓派 4+ | `fangcunai/skillward:arm64` |

```bash
# x86_64
docker pull fangcunai/skillward:amd64

# Apple Silicon / ARM
docker pull fangcunai/skillward:arm64
```

校验：

```bash
docker image ls fangcunai/skillward
```

---

## 三、参数说明

### 输入 / 输出

| 参数 | 必填 | 说明 |
|---|---|---|
| `-i, --skills-dir <path>` | ✅ | 待扫描的 Skills 目录，每个子文件夹为独立 skill 包（包含 `SKILL.md`） |
| `-o, --output-dir <path>` | ✅ | 扫描结果输出目录 |

### 阶段控制

| 参数 | 默认 | 说明 |
|---|---|---|
| `--stage {pre-scan,runtime,full}` | `full` | `pre-scan`：仅静态分析 + LLM 评分；`runtime`：仅 Docker 沙箱检测；`full`：依次执行两阶段 |
| `--enable-after-tool` | 关闭 | 是否启用内容检测 |

### 范围过滤

| 参数 | 说明 |
|---|---|
| `-n, --max-count <N>` | 仅扫描目录中前 N 个 skill（按目录名字典序） |
| `-s, --skills <name1,name2,...>` | 仅扫描指定名称的 skill（逗号分隔，名称为 skill 文件夹名） |

### 并发与沙箱调优

| 参数 | 默认 | 说明 |
|---|---|---|
| `--parallel <N>` | `1` | 阶段 3 并行运行的 Docker 沙箱数量，建议范围 4–8 |
| `--image <name>` | `fangcunai/skillward:amd64` | 阶段 3 使用的 Docker 镜像 |
| `--phase1-timeout <秒>` | `300` | Phase 1（环境准备）超时时间 |
| `--phase2-timeout <秒>` | `300` | Phase 2（执行 skill）超时时间 |
| `--max-retries <N>` | `2` | agent 在沙箱内崩溃时的重试次数 |
| `--retry-delay <秒>` | `10` | 重试之间的等待秒数 |


### 其他

| 参数 | 默认 | 说明 |
|---|---|---|
| `--safety-threshold <float>` | `0.3` | 阶段 2 LLM 安全置信度阈值，范围 0.0–1.0，数值越高判定越严格 |
| `--sandbox-threshold <float>` | `0.9` | 阶段 2 LLM 安全置信度上界|
| `-v, --verbose` | 关闭 | 输出详细日志（包含静态规则命中明细、LLM 请求摘要等） |

---

## 四、常见用法示例

### 1. 完整流程

```bash
python guardian-api/guardian.py -i ./my_skills -o ./scan_result --enable-after-tool --parallel 4
```

### 2. 仅静态 + LLM 评分（无需 Docker）

```bash
python guardian-api/guardian.py -i ./my_skills -o ./scan_result --stage pre-scan
```

### 3. 禁用内容监测

```bash
python guardian-api/guardian.py -i ./my_skills -o ./scan_result
```

### 4. 调试指定 skill

```bash
python guardian-api/guardian.py -i ./my_skills -o ./scan_result \
    -s aces1up_redditrank,adisinghstudent_trump-code-market-signals
```

### 5. 抽样扫描前 5 个 skill

```bash
python guardian-api/guardian.py -i ./my_skills -o ./scan_result -n 5
```

### 6. 提高安全阈值

```bash
python guardian-api/guardian.py -i ./my_skills -o ./scan_result --safety-threshold 0.7
```

---

## 五、输出文件

`-o` 指定的输出目录下：

| 文件 / 目录 | 说明 |
|---|---|
| `guardian_report.json` | 总报告，包含每个 skill 的 prescan / runtime 结果、状态、命中数、耗时 |
| `safe-skills/` | 阶段 2 判定为 SAFE 的 skill 副本（阶段 3 输入） |
| `skill_<name>_phase1.txt` | 沙箱 Phase 1（环境准备）的 agent 输出日志 |
| `skill_<name>.txt` | 沙箱 Phase 2（执行 skill 主功能）的 agent 输出日志 |

`guardian_report.json` 中 runtime 字段含义：

| 字段 | 含义 |
|---|---|
| `status` | `PASSED` / `WARNING` / `ERROR` |
| `elapsed_sec` | 沙箱执行总耗时（秒） |
| `blacklist_hits` | hook 拦截到的黑名单命中次数 |
| `blocks` | 实际拦截次数 |
| `content_risks` | 内容风险计数 |
| `agent_crashed` | agent 是否在沙箱内崩溃 |
| `details` | 命中详情列表（含规则、上下文） |



