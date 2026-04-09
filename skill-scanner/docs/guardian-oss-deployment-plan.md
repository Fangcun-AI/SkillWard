# Guardian 开源部署方案

> 目标：让外部用户可以完整部署和运行 Guardian 三阶段 Skill 安全扫描系统，不依赖我们的任何私有后端服务。

---

## 一、现状（我们自己用的版本）

```
用户浏览器
  │
  ▼
guardian-ui (:3001)          ← Next.js 前端
  │
  ▼
guardian-api (:8899)         ← FastAPI 后端（扫描流程调度）
  │
  ├── Stage 1: skill-scanner 静态分析（本地）
  │             + Infini-AI LLM API 语义评分（远程，我们的 key）
  │
  ├── Stage 2: docker run openclaw:fangcun-guard-arm64
  │             → OpenClaw Agent 执行 skill
  │             → FangcunGuard 插件拦截工具调用
  │                 ├── blacklist.ts 本地规则匹配
  │                 └── api.ts → 调防城云 API (162.14.139.55:9051)
  │                                → Qwen3Guard-Gen-8B 模型推理
  │                                → 返回 risk_level 0-3
  │
  └── Stage 3: 跨阶段校验，生成报告
```

### 不能直接给别人用的部分

| 组件 | 原因 |
|------|------|
| Infini-AI LLM API key | 我们的 key，不能公开 |
| 防城云 content_check API (162.14.139.55:9051) | 我们的服务器 |

### 可以开源的部分

| 组件 | 说明 |
|------|------|
| skill-scanner | 静态分析引擎（YARA + 签名 + Python 检查） |
| guardian.py + guardian_api.py | 扫描流程调度 + 后端 API |
| guardian-ui | 前端界面 |
| FangcunGuard 后端 | 已开源 Apache 2.0，含 Qwen3Guard-Gen-8B 模型 |
| FangcunGuard OpenClaw 插件 | blacklist.ts + api.ts + safety-guard.ts 等 |

---

## 二、开源版架构

### 核心改动：一行代码

FangcunGuard 插件的 `config.ts`：

```typescript
// 现在（调我们的远程服务器）
API_BASE_URL: "http://162.14.139.55:9051"

// 开源版（调用户本地的 FangcunGuard）
API_BASE_URL: process.env.GUARD_API_URL || "http://fangcunguard:5001"
```

接口格式、请求参数、返回结构完全不变，因为用户本地跑的是同一套 FangcunGuard 代码。

---

### 版本 A：GPU 版（完整体验，4 个容器）

适合有 GPU 服务器的团队。所有组件本地运行，零外部依赖。

```
docker-compose -f docker-compose.gpu.yml up

┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  容器 1                容器 2               容器 3              │
│  ┌────────────┐       ┌────────────┐       ┌─────────────────┐ │
│  │ guardian-ui │       │ guardian   │       │  fangcunguard   │ │
│  │  (Next.js) │──────→│   -api     │       │  (:5001)        │ │
│  │   :3001    │       │  (FastAPI) │       │                 │ │
│  │            │       │   :8899    │       │ detection_service│ │
│  └────────────┘       └─────┬──────┘       │ Qwen3Guard-Gen  │ │
│                             │              │ -8B (vLLM, GPU) │ │
│                             │              │ PostgreSQL       │ │
│                             │              └────────┬────────┘ │
│                        Stage 1:                     │          │
│                        静态分析（本地）               │          │
│                        + LLM分析                     │          │
│                        (也调容器3的模型)              │          │
│                             │                        │          │
│                        Stage 2:                      │          │
│                        启动沙箱容器                    │          │
│                             │                        │          │
│                        容器 4（按需启动，扫完销毁）     │          │
│                       ┌─────┴──────────────┐         │          │
│                       │ sandbox             │         │          │
│                       │ OpenClaw Agent     │         │          │
│                       │ + FangcunGuard 插件 │─────────┘          │
│                       │   blacklist.ts     │  调容器3            │
│                       │   api.ts → :5001   │  content_check     │
│                       └────────────────────┘                    │
│                                                                 │
│                        Stage 3:                                 │
│                        跨阶段校验                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**用户需要提供**：GPU 服务器（推荐 16GB+ 显存）、Docker
**不需要提供**：任何 API key（全部本地运行）

---

### 版本 B：无 GPU 版（轻量版，3 个容器）

适合普通 Mac/PC 开发者。没有容器 3，Guard 仅用黑名单规则。

```
docker-compose up

┌──────────────────────────────────────────────────────┐
│                                                      │
│  容器 1                容器 2                        │
│  ┌────────────┐       ┌────────────┐                │
│  │ guardian-ui │──────→│ guardian   │                │
│  │   :3001    │       │   -api     │──→ 用户的 LLM API
│  │            │       │   :8899    │   (OpenAI 等)  │
│  └────────────┘       └─────┬──────┘                │
│                             │                        │
│                        Stage 2:                      │
│                        启动沙箱容器                    │
│                             │                        │
│                        容器 3（按需启动，扫完销毁）     │
│                       ┌─────┴──────────────┐        │
│                       │ sandbox             │        │
│                       │ OpenClaw Agent     │        │
│                       │ + FangcunGuard 插件 │        │
│                       │   blacklist.ts     │        │
│                       │   (仅规则，不调模型) │        │
│                       └────────────────────┘        │
│                                                      │
└──────────────────────────────────────────────────────┘
```

**用户需要提供**：Docker、LLM API key（用于 Stage 2 分析）
**Guard 检测**：仅黑名单规则，不跑模型

---

## 三、两个版本的能力对比

| 能力 | GPU 版 | 无 GPU 版 | 我们自己的版本 |
|------|--------|----------|--------------|
| Stage 1 静态分析（YARA + 签名 + Python 检查） | 完整 | 完整 | 完整 |
| Stage 2 LLM 分析 | 本地 Qwen3Guard 模型 | 用户自带 API key | Infini-AI |
| Stage 3 Guard 黑名单规则 | 有 | 有 | 有 |
| Stage 3 Guard 内容安全模型 | 本地 Qwen3Guard-Gen-8B | 无 | 防城云 API |
| Stage 4 跨阶段校验 | 有 | 有 | 有 |
| 需要 GPU | 是（16GB+ 显存） | 否 | 否（云端） |
| 需要 API key | 否 | 是 | 否（我们的） |
| Guard 准确率 | 高（规则 + 模型） | 中（仅规则） | 最高（规则 + 防城云） |

---

## 四、代码仓库结构

### 现有代码分布

```
代码仓库 1：skill-scanner-main/
├── skill_scanner/                ← 静态分析引擎（YARA、签名、Python 检查）
├── test_script/
│   ├── guardian.py               ← 三阶段扫描流程逻辑
│   ├── guardian_api.py           ← 后端 API（FastAPI，SSE 推送）
│   └── toxic_skills/             ← 测试用恶意 skill 样本
├── guardian-ui/                  ← 前端 UI（Next.js）
└── llm-guardian/                 ← 开源版 Guard 插件雏形（纯 LLM，无黑名单）

代码仓库 2：FangcunGuard/
├── backend/
│   ├── detection_service.py      ← content_check API（端口 5001）
│   ├── services/guardrail_service.py ← 核心检测逻辑
│   └── ...                       ← 用户管理、数据库等
├── frontend/                     ← 管理界面
└── 模型：Qwen3Guard-Gen-8B       ← vLLM 推理

Docker 镜像：openclaw:fangcun-guard-arm64
└── /root/.openclaw/extensions/openclaw-fangcun-guard/
    ├── index.ts                  ← 插件入口（打包压缩版）
    └── src/                      ← 完整源码
        ├── config.ts             ← API 地址配置
        ├── api.ts                ← 调防城云 API 的 HTTP 接口
        ├── blacklist.ts          ← 本地黑名单规则（纯正则）
        ├── safety-guard.ts       ← Agent 安全守卫（M0-M7 防御模块）
        ├── prompt-injection.ts   ← Prompt 注入检测
        ├── system-prompt-guard.ts← 系统提示词保护
        ├── sensitive.ts          ← 敏感信息检测
        ├── security-audit-runner.ts ← 安全审计
        ├── types.ts              ← 类型定义
        └── utils.ts              ← 工具函数
```

### 开源后的统一仓库结构

```
guardian/
├── guardian-ui/                   ← 前端（Next.js，端口 3001）
│   ├── Dockerfile
│   └── src/
│
├── guardian-api/                  ← 后端 API（FastAPI，端口 8899）
│   ├── Dockerfile
│   ├── guardian.py                ← 三阶段扫描流程
│   ├── guardian_api.py            ← SSE 接口
│   └── skill_scanner/             ← 静态分析引擎
│
├── guardian-guard/                ← FangcunGuard OpenClaw 插件（开源版）
│   ├── src/
│   │   ├── config.ts             ← API 地址改为环境变量
│   │   ├── api.ts                ← 调本地 FangcunGuard（不再调远程）
│   │   ├── blacklist.ts          ← 黑名单规则（不用改）
│   │   ├── safety-guard.ts       ← 安全守卫（不用改）
│   │   ├── prompt-injection.ts   ← Prompt 注入检测（不用改）
│   │   └── ...
│   └── Dockerfile.sandbox        ← 沙箱镜像：OpenClaw + 此插件
│
├── docker-compose.yml            ← 无 GPU 版（3 个容器）
├── docker-compose.gpu.yml        ← GPU 版（4 个容器）
├── .env.example                  ← 配置模板
│
├── evals/                        ← 测试用 skill 样本
│   └── toxic_skills/
│
└── docs/
    ├── deploy-gpu.md             ← GPU 版部署指南
    ├── deploy-nogpu.md           ← 无 GPU 版部署指南
    └── configuration.md          ← 配置说明
```

---

## 五、代码改造工作

### 5.1 FangcunGuard 插件：config.ts 改一行

```typescript
// src/config.ts

// 改前
export const CONFIG = {
  API_BASE_URL: "http://162.14.139.55:9051",
  CACHE_DIR: ".openclaw/fangcun",
  ID_FILE: "user_id",
};

// 改后
export const CONFIG = {
  API_BASE_URL: process.env.GUARD_API_URL || "http://fangcunguard:5001",
  CACHE_DIR: ".openclaw/fangcun",
  ID_FILE: "user_id",
};
```

其余文件（blacklist.ts、api.ts、safety-guard.ts 等）**全部不用改**。
api.ts 调的接口格式跟 FangcunGuard 后端完全一致，因为本来就是同一套系统。

无 GPU 版额外需要：当 `GUARD_API_URL` 未配置时，api.ts 的调用直接跳过，只走 blacklist.ts 规则。

```typescript
// src/api.ts 加一个判断
export async function checkContent(...) {
  if (!CONFIG.API_BASE_URL) {
    // 无 GPU 版：不调模型，返回默认安全
    return { code: 0, result: { is_safe: true, risk_level: 0, ... } };
  }
  // 原有逻辑不变
  return safeFetch<ContentCheckResponse>(`${CONFIG.API_BASE_URL}/api/v1/content_check`, ...);
}
```

### 5.2 guardian-api：去硬编码

```python
# guardian_api.py 需要改的地方：

# 改动 1：LLM 配置从硬编码改为环境变量
# 改前
parser.add_argument("--llm-model", default="openai/glm-5")
parser.add_argument("--llm-api-key", default="sk-c7je7zeezd5nazvo")
# 改后
parser.add_argument("--llm-model",
    default=os.getenv("LLM_ID", ""))
parser.add_argument("--llm-api-key",
    default=os.getenv("LLM_API_KEY", ""))

# 改动 2：Docker 镜像名可配置
# 改前
SANDBOX_IMAGE = "openclaw:fangcun-guard-arm64"
# 改后
SANDBOX_IMAGE = os.getenv("GUARDIAN_SANDBOX_IMAGE", "guardian-sandbox:latest")

# 改动 3：Guard API 地址透传
# 启动 Docker 沙箱时传入环境变量
docker run -e GUARD_API_URL=http://host.docker.internal:5001 ...

# 改动 4：无 LLM 降级
if not args.llm_api_key:
    # Stage 2 LLM 分析跳过，直接进入 Stage 3
```

### 5.3 Docker 镜像构建

#### guardian-ui 镜像

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./
EXPOSE 3000
CMD ["npm", "start"]
```

#### guardian-api 镜像

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install -e ".[all]"
COPY guardian.py guardian_api.py ./
EXPOSE 8899
CMD ["python", "guardian_api.py"]
```

#### guardian-sandbox 镜像

```dockerfile
FROM openclaw-base:latest
# 移除原有插件
RUN rm -rf /root/.openclaw/extensions/openclaw-fangcun-guard
# 安装开源版插件
COPY guardian-guard/ /root/.openclaw/extensions/openclaw-fangcun-guard/
```

---

## 六、docker-compose 编排

### 无 GPU 版 `docker-compose.yml`（3 个容器）

```yaml
services:
  ui:
    image: guardian-ui:latest
    ports:
      - "3001:3000"
    environment:
      - NEXT_PUBLIC_GUARDIAN_API=http://localhost:8899
    depends_on:
      - api

  api:
    image: guardian-api:latest
    ports:
      - "8899:8899"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - LLM_PROVIDER=${LLM_PROVIDER:-openai}
      - LLM_ID=${LLM_ID:-gpt-4o-mini}
      - LLM_API_KEY=${LLM_API_KEY}
      - GUARDIAN_SANDBOX_IMAGE=guardian-sandbox:latest
      - GUARDIAN_GUARD_API_URL=           # 留空 = 不调模型，仅规则
    env_file:
      - .env

  # sandbox 容器由 api 按需启动，不在 compose 中定义
```

### GPU 版 `docker-compose.gpu.yml`（4 个容器）

```yaml
services:
  ui:
    image: guardian-ui:latest
    ports:
      - "3001:3000"
    environment:
      - NEXT_PUBLIC_GUARDIAN_API=http://localhost:8899
    depends_on:
      - api

  api:
    image: guardian-api:latest
    ports:
      - "8899:8899"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - LLM_ID=${LLM_ID:-qwen3guard}
      - LLM_API_BASE=http://fangcunguard:5001
      - GUARDIAN_SANDBOX_IMAGE=guardian-sandbox:latest
      - GUARDIAN_GUARD_API_URL=http://fangcunguard:5001
    depends_on:
      - fangcunguard

  fangcunguard:
    image: fangcunguard:latest
    ports:
      - "5001:5001"
    environment:
      - MODEL_NAME=Qwen3Guard-Gen-8B
    volumes:
      - model-data:/app/models
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]

  # sandbox 容器由 api 按需启动，不在 compose 中定义

volumes:
  model-data:
```

### `.env.example`

```bash
# ===== Guardian 开源版配置 =====

# ── 无 GPU 版：填写你的 LLM API key ──
LLM_PROVIDER=openai
LLM_ID=gpt-4o-mini
LLM_API_KEY=sk-your-key-here

# ── GPU 版：无需填写，全部本地运行 ──
# 使用 docker-compose.gpu.yml 即可
```

---

## 七、用户部署指南

### 无 GPU 版（5 分钟）

```bash
git clone https://github.com/yourorg/guardian.git
cd guardian
cp .env.example .env
# 编辑 .env，填入 OpenAI / Anthropic API key
docker compose up -d
open http://localhost:3001
```

### GPU 版（10 分钟）

```bash
git clone https://github.com/yourorg/guardian.git
cd guardian
docker compose -f docker-compose.gpu.yml up -d
# 首次启动等待模型下载
docker compose -f docker-compose.gpu.yml logs -f fangcunguard
open http://localhost:3001
```

---

## 八、工作量估算

| 任务 | 说明 | 工作量 |
|------|------|--------|
| config.ts 改一行 | Guard 插件 API 地址改为环境变量 | 0.5天 |
| api.ts 加降级逻辑 | 无 GPU 版跳过模型调用 | 0.5天 |
| guardian_api.py 去硬编码 | LLM key、镜像名、Guard URL 配置化 | 1天 |
| 写 3 个 Dockerfile | ui、api、sandbox | 1.5天 |
| 写 2 个 docker-compose | 无 GPU 版 + GPU 版 | 1天 |
| 整理仓库结构 | 合并代码到统一仓库 | 1天 |
| 测试完整流程 | 两个版本分别测试 | 2天 |
| 撰写部署文档 | 部署指南 + 配置说明 | 1天 |
| 推送镜像到 Docker Hub | 公开发布 | 0.5天 |
| **合计** | | **约 9 天** |

### 执行优先级

```
第 1 周：代码改造 + 打包
  - config.ts + api.ts 改造
  - guardian_api.py 去硬编码
  - 写 Dockerfile + docker-compose
  - 整理仓库结构

第 2 周：测试 + 发布
  - GPU 版完整流程测试
  - 无 GPU 版完整流程测试
  - 撰写文档
  - 推送镜像 + 发布
```

---

## 九、后续演进（可选）

| 方向 | 说明 |
|------|------|
| 自定义规则包 | 用户可以添加自己的 blacklist 规则 |
| CI/CD 集成 | 提供 GitHub Action，在 PR 中自动扫描 skill |
| 云端托管版 | SaaS 版本，用户不需要部署任何东西 |
| Guard 规则市场 | 社区贡献和共享检测规则 |
| 模型微调指南 | 教用户用自己的数据微调 Qwen3Guard |
