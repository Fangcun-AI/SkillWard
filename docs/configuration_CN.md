# 配置说明

SkillWard 从 `guardian-api/.env` 文件（或 shell 环境变量）读取配置。

## 快速配置

```bash
cp guardian-api/.env.example guardian-api/.env
```

复制完成后，编辑 `guardian-api/.env` 并填入下文所列字段的值。

## 必填变量

### 统一配置

`GUARDIAN_PROVIDER` 同时驱动 **Stage A + B（litellm）** 和 **Stage C（容器内 Agent）**。

| 变量 | 说明 |
|---|---|
| `GUARDIAN_PROVIDER` | Provider 简称。可选：`azure` / `openai` / `anthropic` / `gemini` / `zhipu` / `zai` / `glm` / `minimax` / `minimax-cn` / `minimaxi` / `moonshot` / `kimi` / `qwen` / `dashscope` / `tongyi` / `deepseek` / `doubao` / `ark` / `volcengine` / `xai` / `grok` / `groq` / `openrouter` / `mistral` / `ollama`（详见 `config.py`） |
| `GUARDIAN_MODEL_ID` | 模型名（`gpt-5.4`、`glm-4.6`、`MiniMax-M2.5`、`claude-3-5-sonnet-latest`） |
| `GUARDIAN_API_KEY` | API key |
| `GUARDIAN_GUARD_PLUGIN_API_URL` / `API_KEY` | 沙箱内 Guard 监测模型的 API URL 和 Key，提供三种配置方式（[详见 沙箱安全监控](#沙箱安全监控)） |

例如：

```bash
GUARDIAN_PROVIDER=zai
GUARDIAN_MODEL_ID=glm-4.5-flash
GUARDIAN_API_KEY=your-api-key
GUARDIAN_API_BASE=
GUARDIAN_API_VERSION=

GUARDIAN_GUARD_PLUGIN_API_URL=http://api.fangcunleap.com/v1/guardrails/skill-audit
GUARDIAN_GUARD_PLUGIN_API_KEY=api key of guard
````

Azure 额外需要GUARDIAN_API_BASE & GUARDIAN_API_VERSION，比如：

```bash
GUARDIAN_PROVIDER=azure
GUARDIAN_MODEL_ID=gpt-5.4
GUARDIAN_API_KEY=your-api-key
GUARDIAN_API_BASE=https://your-resource.openai.azure.com
GUARDIAN_API_VERSION=2025-04-01-preview

GUARDIAN_GUARD_PLUGIN_API_URL=http://api.fangcunleap.com/v1/guardrails/skill-audit
GUARDIAN_GUARD_PLUGIN_API_KEY=api key of guard
````

### 分阶段独立配置（可选）

如果 Stage A + B 和 Stage C 需要使用不同的模型或 Provider，可以通过以下变量分别覆盖：

| 变量 | 说明 |
|---|---|
| `GUARDIAN_LLM_MODEL` | 覆盖 Stage A + B 使用的模型名 |
| `GUARDIAN_LLM_BASE_URL` | 覆盖 Stage A + B 的 API 地址 |
| `GUARDIAN_DOCKER_MODEL` | 覆盖 Stage C（沙箱内 Agent）使用的模型名 |
| `GUARDIAN_DOCKER_API_URL` | 覆盖 Stage C 的 API 地址 |

这些变量优先级高于 `GUARDIAN_PROVIDER` 的自动推导。未设置时，两个阶段共用统一配置。

例如，Stage A + B 用 GPT 做研判，Stage C 用 Claude 驱动沙箱 Agent：

```bash
# 统一 Provider（作为基础配置）
GUARDIAN_PROVIDER=openai
GUARDIAN_MODEL_ID=gpt-4o
GUARDIAN_API_KEY=your-openai-key

# Stage C 单独使用 Claude
GUARDIAN_DOCKER_MODEL=claude-sonnet-4-20250514
GUARDIAN_DOCKER_API_URL=https://api.anthropic.com/v1
```

---

## Provider 对照表

| `GUARDIAN_PROVIDER` | `GUARDIAN_MODEL_ID` 示例 |
|---|---|
| `azure` | `gpt-5.4` |
| `openai` | `gpt-4o-mini` |
| `anthropic` | `claude-3-5-sonnet-latest` |
| `gemini` | `gemini-2.0-flash` |
| `zhipu` | `glm-4.6` |
| `minimax` | `MiniMax-M2.5` |
| `moonshot` | `kimi-k2-0711-preview` |
| `qwen` | `qwen-max` |
| `deepseek` | `deepseek-chat` |
| `doubao` | `doubao-1-5-pro-32k` |
| `xai` | `grok-2-latest` |
| `groq` | `llama-3.3-70b-versatile` |
| `openrouter` | `anthropic/claude-3.5-sonnet` |
| `mistral` | `mistral-large-latest` |
| `ollama` | `llama3.1` |

---


## 沙箱安全监控

沙箱容器内置 Guard 插件，负责在 Skill 执行过程中实时拦截和审查工具调用与文件内容。Guard 需要一个后端 LLM 来完成安全判定。以下提供三种配置方式，按需选择。

### 方案一：使用 SkillWard 托管 API（即将开放）

我们正在搭建托管 API 平台，届时注册即可获取 API Key，无需部署任何模型。

> 注册平台即将开放，敬请期待。

### 方案二：自部署安全检测模型（完全私有化）

如果你有 GPU 资源，可以自行部署安全分类或语义分析模型，然后将 Guard 插件指向你的服务。你可以在 HuggingFace 上寻找合适的模型，例如：

- [HuggingFace — 文本分类模型](https://huggingface.co/models?pipeline_tag=text-classification)
- [HuggingFace — 文本生成模型](https://huggingface.co/models?pipeline_tag=text-generation)

**部署步骤（以 vLLM 为例）：**

```bash
# 1. 安装 vLLM
pip install vllm

# 2. 启动模型服务（替换为你选择的模型）
vllm serve your-model-name --port 8000 --host 0.0.0.0
```

```env
# 3. 将 Guard 插件指向你的模型服务
GUARDIAN_GUARD_PLUGIN_API_URL=http://localhost:8000/v1/guardrails
GUARDIAN_GUARD_PLUGIN_API_KEY=your-local-key
```

### 方案三：使用通用 LLM API 替代（灵活接入）

Guard 插件也支持接入任意兼容 OpenAI 格式的通用大语言模型 API。这种方式无需自建服务，只要你有一个可用的 LLM API Key 即可。

```env
GUARDIAN_GUARD_PLUGIN_API_URL=https://open.bigmodel.cn/api/paas/v4/guardrails
GUARDIAN_GUARD_PLUGIN_API_KEY=your-api-key
```

**支持的模型示例：**

| 模型 | Provider |
|------|----------|
| GLM-4.5-Flash | 智谱 AI |
| MiniMax-M2.5 | MiniMax |
| DeepSeek-Chat | DeepSeek |

---
