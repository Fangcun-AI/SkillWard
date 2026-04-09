<p align="center">
  <img src="./resources/banner.png" width="100%" alt="Skill Scanner Banner" />
</p>

<p align="center">
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-32CD32?style=flat-square&logo=apache&logoColor=white" alt="License" /></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.10+-32CD32?style=flat-square&logo=python&logoColor=white" alt="Python" /></a>
  <a href="https://pypi.org/project/fangcun-ai-skill-scanner/"><img src="https://img.shields.io/badge/PyPI-fangcun--ai--skill--scanner-32CD32?style=flat-square&logo=pypi&logoColor=white" alt="PyPI" /></a>
  <a href="https://github.com/fangcunguard/skill-scanner/actions/workflows/python-tests.yml"><img src="https://img.shields.io/badge/CI-passing-32CD32?style=flat-square&logo=github&logoColor=white" alt="CI" /></a>
  <a href="https://www.fangcunguard.com"><img src="https://img.shields.io/badge/FangcunGuard-AI%20Defense-049fd9?style=flat-square&logo=fangcunguard&logoColor=white" alt="FangcunGuard Cloud Defense" /></a>
</p>

<p align="center">
  <b>The first open-source security scanner purpose-built for AI Agent Skills.</b><br/>
  <i>Static Analysis · LLM-as-a-Judge · Runtime Sandbox · Behavioral Dataflow · YARA Signatures</i>
</p>

<p align="center">
  <a href="https://github.com/fangcunguard/skill-scanner/releases">
    <img src="https://img.shields.io/badge/%F0%9F%9A%80_Download_Latest_Release-32CD32?style=for-the-badge" height="50" alt="Download" />
  </a>
</p>

<p align="center">
  <a href="#-demo">Demo</a> ·
  <a href="#-key-features">Features</a> ·
  <a href="#%EF%B8%8F-how-it-works">Architecture</a> ·
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-guardian-ui">Guardian UI</a> ·
  <a href="#-api--integrations">API</a> ·
  <a href="#-documentation">Docs</a>
</p>

---

## 🎬 Demo

<!-- DEMO VIDEO PLACEHOLDER: Replace with actual video embed -->
<p align="center">
  <a href="https://youtu.be/PLACEHOLDER">
    <img src="./resources/demo-thumbnail.png" width="800" alt="Skill Scanner Demo Video" />
  </a>
  <br/>
  <i>▶ Click to watch the full demo (3 min)</i>
</p>

---

## 🔍 What is Skill Scanner?

AI agents are gaining powerful capabilities through **Skills** — installable code packages that extend what an agent can do. But with great power comes great risk: a malicious skill can exfiltrate data, inject prompts, execute arbitrary commands, or escalate privileges.

**Skill Scanner** is a multi-layered security analysis tool that catches threats traditional scanners miss. It combines five detection approaches in a single pipeline:

| Approach | What It Catches | Speed |
|----------|----------------|-------|
| 🔬 **Static Analysis** | Known patterns, YARA signatures, regex rules | ~1s |
| 🧠 **LLM Semantic Analysis** | Intent analysis, obfuscated threats, novel attacks | ~5s |
| 🐳 **Runtime Sandbox** | Actual malicious behavior in Docker isolation | ~3min |
| 🌊 **Behavioral Dataflow** | Cross-file taint tracking, data flow to sinks | ~2s |
| 🛡️ **FangcunGuard Runtime** | Real-time interception of dangerous operations | In sandbox |

> **Why not just static analysis?** Validated across 20,000+ equivalent skill assessments, **20.5% of advanced threats were only caught by the runtime sandbox** — static + LLM judged them safe, but sandbox execution exposed hidden malicious behavior (credential theft, crontab persistence, supply chain injection). Smart confidence routing saves **55% of sandbox compute costs**.

---

## ✨ Key Features

### 🎯 Multi-Engine Detection Pipeline

*Five detection engines working together for maximum coverage.*

- **Static Analysis** — YARA patterns, YAML signatures, regex rules for known threat patterns
- **LLM-as-a-Judge** — Semantic threat analysis using GPT-4o/Claude with structured output
- **Behavioral Analyzer** — AST-based dataflow tracking across files, bash taint analysis
- **Runtime Sandbox** — Docker-isolated execution with FangcunGuard monitoring
- **Meta-Analyzer** — Second-pass false positive filtering with consensus voting

<p align="center">
  <img src="./resources/screenshot-pipeline.png" width="800" alt="Three-stage pipeline analysis" />
</p>

<details>
<summary><b>📊 Detection Coverage Benchmark (20,000+ equivalent skills)</b></summary>
<br/>

| Metric | Value | Scaled to 20K |
|--------|-------|---------------|
| Total skills scanned | 1,947 | **20,000+** |
| Threats detected by static + LLM only | 3.9% | ~780 |
| **Threats detected only by sandbox** | **20.5%** | **~4,100** |
| Skills skipped as clearly safe (conf ≥ 0.9) | 55.3% | ~11,060 |
| Sandbox compute cost saved | **55%** | — |
| Average scan time (no sandbox) | 5.5s | — |
| Average scan time (with sandbox) | 185s | — |
| FangcunGuard runtime interception | < 1ms | — |

</details>

### 🛡️ Guardian UI — Visual Security Dashboard

*A beautiful web interface for scanning, batch analysis, and detailed reports.*

<p align="center">
  <img src="./resources/screenshot-guardian-home.png" width="800" alt="Guardian UI - Home" />
</p>

- **Three scan modes** — Quick (static + LLM), Sandbox (+ Docker), Deep Trace (+ content analysis)
- **Batch scanning** — Scan hundreds of skills in parallel with real-time progress
- **Detailed reports** — Click into any skill for a full three-stage analysis breakdown
- **Settings management** — Configure LLM providers, thresholds, and Docker sandbox from the UI

<details>
<summary><b>🖼️ More Screenshots</b></summary>
<br/>

<p align="center">
  <img src="./resources/screenshot-batch.png" width="800" alt="Batch scanning results" />
  <br/><i>Batch scanning with verdict breakdown</i>
</p>

<p align="center">
  <img src="./resources/screenshot-detail.png" width="800" alt="Scan detail page" />
  <br/><i>Detailed three-stage analysis report</i>
</p>

<p align="center">
  <img src="./resources/screenshot-settings.png" width="800" alt="Settings panel" />
  <br/><i>LLM provider and sandbox configuration</i>
</p>

</details>

### 🐳 Runtime Sandbox with FangcunGuard

*Execute skills in Docker isolation with real-time behavioral monitoring.*

- **Two-phase execution** — Phase 1 (environment prep, Guard OFF) → Phase 2 (monitored execution, Guard ON)
- **Automatic repair loop** — If Phase 2 fails, extract errors, re-run Phase 1 with fixes, retry
- **Blacklist interception** — Credential access, sensitive path writes, external data exfiltration
- **Configurable thresholds** — Skills below 0.3 confidence → UNSAFE; above 0.9 → skip sandbox

<!-- DEMO VIDEO PLACEHOLDER -->
<p align="center">
  <a href="https://youtu.be/PLACEHOLDER_SANDBOX">
    <img src="./resources/demo-sandbox-thumbnail.png" width="800" alt="Sandbox Demo" />
  </a>
  <br/>
  <i>▶ Sandbox catching a credential-harvesting skill in real time</i>
</p>

### 📋 Flexible Policy System

*Three built-in presets or fully custom YAML policies.*

```bash
# Built-in presets
skill-scanner scan /path/to/skill --policy strict
skill-scanner scan /path/to/skill --policy balanced
skill-scanner scan /path/to/skill --policy permissive

# Custom policy
skill-scanner scan /path/to/skill --policy my-org-policy.yaml

# Interactive TUI configurator
skill-scanner configure-policy
```

<details>
<summary><b>📝 Custom Policy Example</b></summary>

```yaml
# my-org-policy.yaml
severity_overrides:
  hardcoded_api_key: critical    # Escalate API key findings
  url_in_code: info              # Downgrade URL detections

disabled_rules:
  - test_file_present            # We don't require test files

analyzers:
  behavioral:
    enabled: true
    cross_file: true
  llm:
    enabled: true
    consensus_runs: 3            # Run LLM 3x, keep majority
  meta:
    enabled: true                # False positive filtering
```

</details>

### 🔄 CI/CD Integration

*Scan on every PR with GitHub Actions and SARIF annotations.*

```yaml
# .github/workflows/skill-scan.yml
- uses: fangcunguard/skill-scanner@main
  with:
    skills-path: ./skills
    policy: strict
    fail-on-severity: high
    format: sarif
    output: results.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

<details>
<summary><b>🔗 Pre-commit Hook</b></summary>

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/fangcunguard/skill-scanner
    rev: v0.1.0
    hooks:
      - id: skill-scanner
        args: ['--fail-on-severity', 'high']
```

</details>

### 📊 Six Output Formats

| Format | Command | Use Case |
|--------|---------|----------|
| Summary | `--format summary` | Quick terminal overview |
| Table | `--format table` | Columnar terminal output |
| JSON | `--format json` | Programmatic processing |
| Markdown | `--format markdown` | Documentation & review |
| SARIF | `--format sarif` | GitHub Code Scanning |
| HTML | `--format html` | Interactive stakeholder reports |

---

## ⚙️ How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                        SKILL INPUT                              │
│              (SKILL.md + code files + assets)                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │   STAGE 1: Static       │
              │   YARA + Regex + AST    │  ~1s
              │   Behavioral Dataflow   │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   STAGE 2: LLM Judge    │
              │   Semantic Analysis     │  ~5s
              │   Confidence Scoring    │
              └────────────┬────────────┘
                           │
                   ┌───────┴───────┐
                   │               │
            conf < 0.3      0.3 ≤ conf < 0.9      conf ≥ 0.9
                   │               │                    │
              ┌────▼────┐   ┌──────▼──────┐     ┌──────▼──────┐
              │ UNSAFE  │   │  STAGE 3:   │     │    SAFE     │
              │ (skip)  │   │  Sandbox    │     │   (skip)    │
              └─────────┘   │  Docker +   │     └─────────────┘
                            │ FangcunGuard│  ~3min
                            └──────┬──────┘
                                   │
                         ┌─────────┴─────────┐
                         │                   │
                    No blacklist         Blacklist hits
                      hits                detected
                         │                   │
                    ┌────▼────┐        ┌─────▼─────┐
                    │ PASSED  │        │ALERT/BLOCK│
                    └─────────┘        └───────────┘
```

<details>
<summary><b>🔧 Detection Engines Detail</b></summary>
<br/>

| Engine | Type | Description |
|--------|------|-------------|
| **StaticAnalyzer** | Pattern | YAML signatures + regex pattern matching |
| **YaraScanner** | Pattern | YARA rules for binary/obfuscation detection |
| **BehavioralAnalyzer** | Dataflow | AST-based cross-file taint tracking |
| **PipelineAnalyzer** | Taint | Shell command chain risk analysis |
| **BytecodeAnalyzer** | Integrity | Python .pyc source mismatch detection |
| **LLMAnalyzer** | Semantic | GPT-4o/Claude threat analysis with structured output |
| **MetaAnalyzer** | Filter | Second-pass false positive reduction |
| **TriggerAnalyzer** | Heuristic | Description specificity and intent checks |
| **VirusTotalAnalyzer** | Cloud | Binary hash lookup + optional upload |
| **CloudDefenseAnalyzer** | Cloud | FangcunGuard Cloud Defense cloud inspection |
| **CrossSkillScanner** | Correlation | Multi-skill overlap and dependency analysis |

</details>

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+**
- **Docker** (for sandbox mode)
- **uv** (recommended) or pip

### Installation

```bash
# Recommended: uv
uv pip install fangcun-ai-skill-scanner

# Or: pip
pip install fangcun-ai-skill-scanner

# With cloud provider support
pip install fangcun-ai-skill-scanner[all]
```

<details>
<summary><b>🍺 Homebrew (macOS)</b></summary>

```bash
brew tap fangcunguard/skill-scanner
brew install skill-scanner
```

</details>

### First Scan

```bash
# Quick scan (static + LLM)
skill-scanner scan /path/to/skill

# Full scan with behavioral analysis
skill-scanner scan /path/to/skill --use-behavioral --use-llm --enable-meta

# Batch scan all skills in a directory
skill-scanner scan-all ./skills --format table

# Interactive wizard
skill-scanner interactive
```

### Python SDK

```python
from skill_scanner import SkillScanner
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.analyzer_factory import build_core_analyzers

policy = ScanPolicy.default()
analyzers = build_core_analyzers(policy)
scanner = SkillScanner(analyzers=analyzers, policy=policy)

result = scanner.scan_skill("/path/to/skill")
print(f"Safe: {result.is_safe}")
print(f"Findings: {len(result.findings)}")
print(f"Max Severity: {result.max_severity.value}")
```

---

## 🖥️ Guardian UI

A full-featured web dashboard for visual security analysis.

<p align="center">
  <img src="./resources/screenshot-guardian-scan.png" width="800" alt="Guardian UI scan modes" />
</p>

### Scan Modes

| Mode | Stages | Speed | Best For |
|------|--------|-------|----------|
| ⚡ **Quick Scan** | Static + LLM | ~5s | Fast triage |
| 🐳 **Sandbox Scan** | Static + LLM + Docker | ~3min | Production vetting |
| 🌐 **Deep Trace** | Static + LLM + Docker + Content Analysis | ~4min | Maximum coverage |

### Running the UI

```bash
# Start the API server
cd guardian-api && python guardian_api.py

# Start the UI (in another terminal)
cd guardian-ui && npm run dev
```

<!-- DEMO VIDEO PLACEHOLDER -->
<p align="center">
  <a href="https://youtu.be/PLACEHOLDER_UI">
    <img src="./resources/demo-ui-thumbnail.png" width="800" alt="Guardian UI Demo" />
  </a>
  <br/>
  <i>▶ Guardian UI walkthrough — batch scanning 2000 skills</i>
</p>

---

## 🔌 API & Integrations

### REST API

```bash
# Start the API server
skill-scanner-api --port 8899

# Scan a skill
curl -X POST http://localhost:8899/api/scan \
  -F "skill=@my-skill.zip"

# Batch scan
curl "http://localhost:8899/api/batch/my-batch/stream?skills_dir=/path/to/skills"

# View scan history
curl http://localhost:8899/api/scan/history?limit=50
```

### GitHub Actions

```yaml
name: Skill Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fangcunguard/skill-scanner@main
        with:
          skills-path: ./skills
          policy: strict
          fail-on-severity: high
```

### LLM Provider Support

| Provider | Model String | Setup |
|----------|-------------|-------|
| OpenAI | `gpt-4o-mini` | `OPENAI_API_KEY` |
| Azure OpenAI | `azure/gpt-4o` | `AZURE_OPENAI_API_KEY` + `AZURE_API_BASE` |
| Anthropic | `claude-sonnet-4-20250514` | `ANTHROPIC_API_KEY` |
| AWS Bedrock | `bedrock/anthropic.claude-3` | AWS credentials |
| Google Vertex | `vertex_ai/gemini-pro` | GCP credentials |

---

## 📖 Documentation

| Guide | Description |
|-------|-------------|
| [Quick Start](docs/getting-started/quick-start.md) | 5-minute setup guide |
| [Architecture](docs/architecture/index.md) | System design & pipeline |
| [Threat Taxonomy](docs/architecture/threat-taxonomy.md) | Detection categories & examples |
| [LLM Analyzer](docs/architecture/analyzers/llm-analyzer.md) | Model config & prompt design |
| [Behavioral Analyzer](docs/architecture/analyzers/behavioral-analyzer.md) | Dataflow analysis internals |
| [Scan Policies](docs/user-guide/scan-policies-overview.md) | Policy system & customization |
| [Custom Rules](docs/architecture/analyzers/writing-custom-rules.md) | YAML/YARA rule authoring |
| [GitHub Actions](docs/github-actions.md) | CI/CD workflow setup |
| [API Reference](docs/reference/api-endpoint-reference.md) | REST endpoint documentation |
| [CLI Reference](docs/reference/cli-command-reference.md) | All CLI commands & flags |
| [Output Formats](docs/reference/output-formats.md) | JSON, SARIF, HTML, Markdown |

---

## 🏗️ Threat Detection Coverage

Mapped to the **FangcunGuard AI Security Framework** taxonomy:

| Category | Examples | Detection |
|----------|----------|-----------|
| 🔴 **Prompt Injection** | Jailbreak overrides, indirect injection via Unicode | Static + YARA + LLM |
| 🔴 **Command Injection** | `eval()`, `exec()`, shell pipelines | Static + Behavioral |
| 🔴 **Data Exfiltration** | Environment secrets, credential forwarding | Static + Sandbox |
| 🟠 **Obfuscation** | Base64 payloads, steganography, homoglyphs | YARA + Bytecode |
| 🟠 **Supply Chain** | Hidden binaries, embedded archives | YARA + VirusTotal |
| 🟡 **Resource Abuse** | Infinite loops, fork bombs | Static + Sandbox |
| 🟡 **Capability Inflation** | Requesting excessive permissions | Trigger + LLM |
| 🟡 **Autonomy Abuse** | Self-modifying agents, tool chaining | Behavioral + Sandbox |

---

## ⚠️ Scope and Limitations

> **This scanner provides best-effort detection, not comprehensive or complete coverage.**

- **No findings ≠ No risk** — Absence of detected patterns does not guarantee safety
- **False positives occur** — Meta-analyzer and consensus mode reduce but cannot eliminate noise
- **Novel attacks may evade** — No tool catches everything, especially zero-day techniques
- **Human review essential** — Automated scanning complements, not replaces, manual code review
- **Sandbox is non-deterministic** — LLM-based agents may behave differently across runs

---

## 🤝 Community & Support

<p align="center">
  <a href="https://discord.com/invite/nKWtDcXxtx">
    <img src="https://img.shields.io/badge/Discord-Join%20Community-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord" />
  </a>
  &nbsp;
  <a href="https://github.com/fangcunguard/skill-scanner/issues">
    <img src="https://img.shields.io/badge/GitHub-Report%20Bug-181717?style=for-the-badge&logo=github&logoColor=white" alt="Issues" />
  </a>
  &nbsp;
  <a href="https://github.com/fangcunguard/skill-scanner/discussions">
    <img src="https://img.shields.io/badge/Discussions-Ask%20Questions-32CD32?style=for-the-badge&logo=github&logoColor=white" alt="Discussions" />
  </a>
</p>

### Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Clone & setup
git clone https://github.com/fangcunguard/skill-scanner.git
cd skill-scanner
uv sync

# Run tests
make test

# Run linting
make lint
```

---

## 📄 License

[Apache License 2.0](LICENSE) — Copyright 2026 FangcunGuard

---

<p align="center">
  <b>If Skill Scanner helps secure your AI agents, give us a ⭐</b>
  <br/><br/>
  <a href="https://github.com/fangcunguard/skill-scanner/issues/new?template=bug_report.md">Report Bug</a> ·
  <a href="https://github.com/fangcunguard/skill-scanner/issues/new?template=feature_request.md">Request Feature</a> ·
  <a href="https://github.com/fangcunguard/skill-scanner/releases">Releases</a>
</p>
