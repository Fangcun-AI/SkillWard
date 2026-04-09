# Configuration Guide

SkillWard reads its configuration from the `guardian-api/.env` file (or from shell environment variables).

## Quick Setup

```bash
cp guardian-api/.env.example guardian-api/.env
```

After copying, edit `guardian-api/.env` and fill in the values for the fields listed below.

## Required Variables

### Unified Configuration

`LLM_PROVIDER` drives **both Stage A + B (litellm)** and **Stage C (in-container Agent)**.

| Variable | Description |
|---|---|
| `LLM_PROVIDER` | Provider shortcut. One of: `azure` / `openai` / `anthropic` / `gemini` / `zhipu` / `zai` / `glm` / `minimax` / `minimax-cn` / `minimaxi` / `moonshot` / `kimi` / `qwen` / `dashscope` / `tongyi` / `deepseek` / `doubao` / `ark` / `volcengine` / `xai` / `grok` / `groq` / `openrouter` / `mistral` / `ollama` (see `config.py`) |
| `LLM_ID` | Model name (`gpt-5.4`, `glm-4.6`, `MiniMax-M2.5`, `claude-3-5-sonnet-latest`) |
| `LLM_API_KEY` | API key |
| `GUARDIAN_GUARD_PLUGIN_API_URL` / `API_KEY` | API URL and key for the in-sandbox Guard monitoring model, three options available ([see Sandbox Security Monitoring](#sandbox-security-monitoring)) |

For example:

```bash
LLM_PROVIDER=zai
LLM_ID=glm-4.5-flash
LLM_API_KEY=your-api-key
LLM_API_BASE=
LLM_API_VERSION=

GUARDIAN_GUARD_PLUGIN_API_URL=http://api.fangcunleap.com/v1/guardrails/skill-audit
GUARDIAN_GUARD_PLUGIN_API_KEY=api key of guard
````

Azure additionally requires `LLM_API_BASE` & `LLM_API_VERSION`, for example:

```bash
LLM_PROVIDER=azure
LLM_ID=gpt-5.4
LLM_API_KEY=your-api-key
LLM_API_BASE=https://your-resource.openai.azure.com
LLM_API_VERSION=2025-04-01-preview

GUARDIAN_GUARD_PLUGIN_API_URL=http://api.fangcunleap.com/v1/guardrails/skill-audit
GUARDIAN_GUARD_PLUGIN_API_KEY=api key of guard
````

### Per-Stage Override (Optional)

If Stage C (in-sandbox Agent) needs a different model or provider, provide a second set of variables with the `AGENT_` prefix — same format as the unified config:

| Variable | Description |
|---|---|
| `AGENT_PROVIDER` | Provider shortcut for Stage C (same options as `LLM_PROVIDER`) |
| `AGENT_ID` | Model name for Stage C |
| `AGENT_API_KEY` | API key for Stage C |
| `AGENT_API_BASE` | API base URL for Stage C |
| `AGENT_API_VERSION` | API version for Stage C (Azure only) |

These take priority over the auto-derived values from `LLM_PROVIDER`. When not set, both stages share the unified configuration.

For example, use GPT for Stage A + B evaluation and Claude for the Stage C sandbox Agent:

```bash
# Unified provider (Stage A + B)
LLM_PROVIDER=openai
LLM_ID=gpt-4o
LLM_API_KEY=your-openai-key

# Stage C uses Claude independently
AGENT_PROVIDER=anthropic
AGENT_ID=claude-sonnet-4-20250514
AGENT_API_KEY=your-anthropic-key
```

---

## Provider Reference

| `LLM_PROVIDER` | `LLM_ID` example |
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

---

## Sandbox Security Monitoring

The sandbox container includes a built-in Guard plugin that intercepts and inspects tool calls and file content in real-time during Skill execution. The Guard needs a backend LLM to make security decisions. Three configuration options are available.

### Option 1: Use SkillWard Hosted API (Coming Soon)

We are building a hosted API platform. Once available, you can register and get an API key with zero model deployment.

> The registration platform is coming soon — stay tuned.

### Option 2: Self-Deploy a Security Detection Model (Fully Private)

If you have GPU resources, you can deploy your own classification or semantic analysis model and point the Guard plugin to your service. You can find suitable models on HuggingFace, for example:

- [HuggingFace — Text Classification Models](https://huggingface.co/models?pipeline_tag=text-classification)
- [HuggingFace — Text Generation Models](https://huggingface.co/models?pipeline_tag=text-generation)

**Deployment steps (using vLLM):**

```bash
# 1. Install vLLM
pip install vllm

# 2. Start model service (replace with your chosen model)
vllm serve your-model-name --port 8000 --host 0.0.0.0
```

```env
# 3. Point the Guard plugin to your model service
GUARDIAN_GUARD_PLUGIN_API_URL=http://localhost:8000/v1/guardrails
GUARDIAN_GUARD_PLUGIN_API_KEY=your-local-key
```

### Option 3: Use Any LLM API (Flexible Integration)

The Guard plugin also supports any OpenAI-compatible LLM API. No self-hosting needed — just provide an API key from any supported provider.

```env
GUARDIAN_GUARD_PLUGIN_API_URL=https://open.bigmodel.cn/api/paas/v4/guardrails
GUARDIAN_GUARD_PLUGIN_API_KEY=your-api-key
```

**Supported model examples:**

| Model | Provider |
|-------|----------|
| GLM-4.5-Flash | Zhipu AI |
| MiniMax-M2.5 | MiniMax |
| DeepSeek-Chat | DeepSeek |

