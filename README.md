·<p align="center">
  <img src="./resources/banner.png" alt="SkillWard Banner" width="100%" />
</p>

<h1 align="center">SkillWard</h1>

<p align="center">
  <a href="https://github.com/Fangcun-AI"><img src="./resources/skillward-badge.svg" alt="SkillWard" height="20" /></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-4B8BBE?style=flat-square&logo=apache&logoColor=white" alt="License" /></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" /></a>
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/Version-1.0.0-32CD32?style=flat-square" alt="Version" />
</p>

<p align="center"><i>SkillWard is a security scanner for AI Agent Skills that combines static analysis, LLM evaluation, and sandbox verification to comprehensively identify potential risks in Agent Skills.</i></p>

<p align="center">
  <a href="#highlights">Highlights</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#skillward-ui">UI</a> ·
  <a href="#benchmark">Benchmark</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#repository-structure">Structure</a> ·
  English | <a href="./README_CN.md">中文</a>
</p>

> **"Five scanners on 238,180 Skills showed highly inconsistent results, only 0.12% were flagged by all five, with individual flag rates ranging from 3.79% to 41.93%."**
> — Holzbauer et al., [*Malicious Or Not: Adding Repository Context to Agent Skill Classification*](https://arxiv.org/abs/2603.16572), 2026

**SkillWard** enables security review of AI Agent Skills before they are published or deployed, reducing the potential risks of Agent usage. Beyond static analysis and LLM evaluation, it executes suspicious Skills in **isolated Docker sandboxes**, replacing uncertain warnings with runtime evidence. Across 5,000 real-world Skills, ~**25%** were flagged as unsafe; among the ~**38%** suspicious samples that entered the sandbox, ~**one-third** revealed runtime threats that review-only pipelines could not catch.

### How does SkillWard address this challenge?

We ran two existing open-source scanning tools on the same dataset as reference baselines (see [Comparison](docs/comparison.md) for details). Here are three real-world cases:

- **Unique Detection:** Threats missed by other tools, precisely caught by SkillWard — see [ai-skill-scanner](docs/cases/ai-skill-scanner.md)
- **Low False Positives:** Compliant content wrongly blocked by other tools, correctly cleared by SkillWard — see [roku](docs/cases/roku.md)
- **Deeper Analysis:** For threats all tools detect, SkillWard provides more complete risk tracing and evidence — see [amber-hunter](docs/cases/amber-hunter.md)

---

## Highlights

- **Three-Stage Security Coverage** - Static analysis, LLM evaluation, and sandbox execution turn obvious threats and ambiguous warnings into high-confidence decisions
- **Autonomous Sandbox Execution** - An in-container Agent provisions environments, installs dependencies, repairs common failures, and drives Skills end-to-end with up to **99% deployment success**
- **Runtime Security Guard** - A purpose-built Guard monitors Agent runtime behavior, capturing clear evidence for exfiltration, suspicious network access, sensitive writes, and hidden credential risks
- **Ready Out of the Box, Extensible on Demand** - Single-skill or batch scans, Quick Scan / Sandbox Scan / Deep Trace modes, tunable via environment variables, LLM provider configuration, and Docker settings
- **Evidence-Rich Results** - Every scan returns real-time logs, three-stage findings, threat evidence, and remediation guidance that security and platform teams can act on immediately

---

## Architecture

<img src="./resources/architecture.png" width="100%" alt="System Architecture" />

SkillWard uses a static + dynamic three-stage analysis approach:

<details>
<summary><b>Stage A · Static Analysis</b>: Runs in seconds, catches known malicious patterns and suspicious signals</summary>

Scans Skill code and configuration using YARA rules and regex to identify known malicious patterns (credential theft, code injection, etc.), validates that a Skill's declared permissions and capabilities match its actual code behavior, and detects hidden files, encoding obfuscation, prompt poisoning, and other suspicious characteristics.

</details>

<details>
<summary><b>Stage B · LLM Evaluation</b>: Semantic reasoning to judge intent and assign safety confidence</summary>

Adds semantic reasoning on top of static signals. Skills that can be confidently classified are resolved here; Skills that remain uncertain advance to Stage C for sandbox verification.

</details>

<details>
<summary><b>Stage C · Sandbox Verification</b>: Actually runs suspicious Skills, leaving hidden risks nowhere to hide</summary>

An in-container Agent executes the Skill end-to-end, with a custom Guard monitoring throughout. Pre-planted honeypot decoys lure malicious Skills into revealing credential theft, data exfiltration, supply chain attacks, and other hidden behavior.

</details>

---

## SkillWard UI

> **Try it online:** [skillward.fangcunleap.com](https://skillward.fangcunleap.com/)

SkillWard UI provides a clean, intuitive web interface, supporting single or batch Skill submission, three scan modes (Quick Scan / Sandbox Scan / Deep Trace), and comprehensive scan results display.

<table>
<tr>
<td width="50%" align="center"><b>Single Skill Scan</b></td>
<td width="50%" align="center"><b>Batch Scan</b></td>
</tr>
<tr>
<td><img src="./resources/demo.webp" width="100%" alt="Single Skill Scan Demo" /></td>
<td><img src="./resources/batch-demo.webp" width="100%" alt="Batch Scan Demo" /></td>
</tr>
</table>

### Detailed Analysis Report

<table>
<tr>
<td width="50%" align="center"><b>Report Overview + Three-Stage Analysis</b></td>
<td width="50%" align="center"><b>Threat Details + Detection Evidence + Recommendations</b></td>
</tr>
<tr>
<td><img src="./resources/screenshot-detail.png" width="100%" alt="Analysis Report Details" /></td>
<td><img src="./resources/screenshot-detail2.png" width="100%" alt="Analysis Report - Threats & Recommendations" /></td>
</tr>
</table>

Each report includes: **Analysis Results** (three-stage verdicts, confidence scores, threat levels), **Issue Location** (file path, line number, highlighted code snippets), and **Remediation Suggestions** (actionable security recommendations).

---

## Benchmark

We evaluated SkillWard on a real-world AI Agent Skills dataset containing Skills collected from [ClawHub](https://clawhub.ai/) and known-malicious samples curated from security communities.

### Pipeline Results

#### Stage A + B: Static Scan + LLM Evaluation

Combining **YARA rules, regex-based static analysis, and LLM semantic evaluation**, all Skills are quickly triaged: safe ~49%, unsafe ~13%, suspicious ~38%, where suspicious Skills are escalated to Stage C for sandbox verification.

#### Stage C: Sandbox Verification

After executing this batch of suspicious Skills end-to-end inside an isolated Docker sandbox, roughly **one-third** revealed potential threats that **neither static analysis nor LLM evaluation could catch**, including:

- **Credential exfiltration** that only surfaces along the execution path
- **Persistence backdoors** via `crontab` / `SSH` / startup scripts
- **Postinstall supply-chain attacks** triggered during package installation
- **Outbound exfiltration chains** identifiable only after correlating multi-step operations

Stage C verdict breakdown for these suspicious Skills:

| Level | Meaning | % of suspicious |
|---|---|---|
| **safe** | Confirmed safe after sandbox verification | **~69%** |
| **medium risk** | Medium-risk behavior (undeclared external requests, env-var harvesting, etc.) | **~17%** |
| **high risk** | High-risk behavior (credential theft, persistence backdoors, remote code execution, etc.) | **~14%** |

#### Overall

Across all stages: Stage A + B directly blocked ~**13%** unsafe Skills, and ~**38%** suspicious Skills entered the sandbox; among those suspicious Skills, ~**17%** were judged medium risk and ~**14%** were judged high risk.

#### Common Threat Patterns (% of unsafe Skills)

| Pattern | Occurrences |
|---------|------------|
| Credential theft (API keys, passwords, private keys) | 36% |
| Undeclared external network requests | 24% |
| Env var / `.env` harvesting | 15% |
| Remote code download and execution | 9% |
| Persistence backdoor (crontab / SSH / startup) | 8% |
| Supply chain and privilege escalation | 8% |

> For detailed case studies and comparison, see [How does SkillWard address this challenge?](#how-does-skillward-address-this-challenge) above.

---

## Quick Start

**Requirements:** Python 3.10+ / Docker (sandbox) / Node.js 18+ (UI mode)

### 1. Install & Configure

```bash
# Clone the repository
git clone https://github.com/Fangcun-AI/SkillWard.git
cd SkillWard

# Install dependencies
pip install -r requirements.txt && pip install -e ./skill-scanner

# Pull Docker sandbox image
docker pull fangcunai/skillward:amd64    # Intel/AMD
docker pull fangcunai/skillward:arm64    # Apple Silicon/ARM

# Configure environment variables (.env.example lists all available options — fill in as needed)
cp guardian-api/.env.example guardian-api/.env
```

> For detailed configuration, see [Configuration Guide](docs/configuration.md)

### 2. Run Scans

```bash
# Full pipeline (static + LLM + sandbox)
python guardian-api/guardian.py /path/to/skills-dir -o ./output --enable-after-tool --parallel 4 -v

# Stage A + B only (static + LLM, no Docker required)
python guardian-api/guardian.py /path/to/skills-dir --stage pre-scan -o ./output -v

# Stage C only (Docker sandbox)
python guardian-api/guardian.py /path/to/skills-dir --stage runtime -o ./output --enable-after-tool --parallel 4
```

### 3. Common Scenarios

```bash
# Scan specific Skills only
python guardian-api/guardian.py /path/to/skills-dir -s skill-a,skill-b -o ./output

# Quick test run (first 10 Skills)
python guardian-api/guardian.py /path/to/skills-dir -n 10 -o ./output

# Increase sandbox timeout for complex Skills
python guardian-api/guardian.py /path/to/skills-dir --timeout 900 --prep-timeout 600 -o ./output
```

> For more options and usage details, see [CLI Guide](docs/cli.md)

> [!TIP]
> **Optional: Launch Web UI**
> ```bash
> cd guardian-api && python guardian_api.py       # API server
> cd guardian-ui && npm install && npm run dev    # Frontend
> ```

---

## Repository Structure

```
SkillWard/
├── docs/                        # Documentation (config, CLI, cases, comparison)
├── guardian-api/                 # Backend: scanning pipeline & API server
│   ├── guardian.py               # Core three-stage scanning engine
│   └── guardian_api.py           # FastAPI server (SSE streaming)
├── guardian-ui/                  # Frontend: Next.js web dashboard
├── skill-scanner/                # Static analysis engine (15 analyzers)
├── models/                      # Data model definitions
├── services/                    # Business logic services
├── utils/                       # Utility functions
├── resources/                   # Banner, screenshots, demo assets
├── requirements.txt
├── README.md
└── README_CN.md
```

| Guide | Description |
|-------|-------------|
| [Configuration](docs/configuration.md) | Quick start, LLM model providers, sandbox security monitoring, optional tuning |
| [CLI Guide](docs/cli.md) | Full command-line reference, common usage, and output files |
| [Showcase](docs/showcase.md) | Real-world detection cases, how SkillWard catches threats in public Skills |
| [Comparison](docs/comparison.md) | Side-by-side analysis with two open-source scanning tools |

---

## 📋 Changelog

| Date | Summary | Details |
|------|---------|---------|
| 2026-04-22 | 🛑 **UI refresh** — batch-scan progress is persisted automatically; added a scan-result reuse mechanism | [docs/UPDATE_REPORT_2026-04-21.md](docs/UPDATE_REPORT_2026-04-21.md) |
| 2026-04-14 | 🧠 **Stage B prompt redesign** — Stage B LLM triage prompt upgraded to a structured System + User two-part prompt | [docs/UPDATE_REPORT_2026-04-14.md](docs/UPDATE_REPORT_2026-04-14.md) |
| 2026-04-10 | 🔒 **Sandbox gateway stability fix** — fixed the OpenClaw Gateway daemon not starting, resolving the exec-approval failure | [docs/UPDATE_REPORT_2026-04-10.md](docs/UPDATE_REPORT_2026-04-10.md) |

---

## License

[Apache License 2.0](LICENSE)
