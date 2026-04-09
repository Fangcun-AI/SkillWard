# CLI Guide

`guardian.py` is the command-line entry point of SkillWard, providing the full skill security scanning pipeline.

---

## 1. Pipeline Overview

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

## 2. Quick Start

Requirements: Python 3.10+ / Docker (for the sandbox stage).

```bash
# Clone the repository
git clone https://github.com/Fangcun-AI/SkillWard.git
cd SkillWard

# Install dependencies
pip install -r requirements.txt && pip install -e ./skill-scanner

# Pull the Docker image
# x86_64
docker pull fangcunai/skillward:amd64
# Apple Silicon / ARM
docker pull fangcunai/skillward:arm64

# Configure .env
cp guardian-api/.env.example guardian-api/.env
```

Edit `guardian-api/.env`, see [configuration.md](configuration.md).

```bash
# Full pipeline
python guardian-api/guardian.py -i /path/to/skills-dir -o ./output --enable-after-tool --parallel 4 -v

# Pre-scan only (static match + LLM analysis)
python guardian-api/guardian.py -i /path/to/skills-dir --stage pre-scan -o ./output -v

# Runtime sandbox only
python guardian-api/guardian.py -i /path/to/skills-dir --stage runtime -o ./output --enable-after-tool --parallel 4
```

---

## <a id="pull-docker-image"></a>3. Pull the Docker Image

Stage C launches an Agent inside a pre-built image. You must pull the image before running `--stage runtime` or the full pipeline.

| Architecture | Suitable for | Image tag |
|---|---|---|
| `amd64` (x86_64) | Intel / AMD CPUs, Linux servers, Windows / WSL, Intel Macs | `fangcunai/skillward:amd64` |
| `arm64` (aarch64) | Apple Silicon Macs (M1/M2/M3/M4), ARM Linux, Raspberry Pi 4+ | `fangcunai/skillward:arm64` |

```bash
# x86_64
docker pull fangcunai/skillward:amd64

# Apple Silicon / ARM
docker pull fangcunai/skillward:arm64
```

Verify:

```bash
docker image ls fangcunai/skillward
```

---

## 4. Argument Reference

### Input / Output

| Argument | Required | Description |
|---|---|---|
| `-i, --skills-dir <path>` | ✅ | Directory containing the skills to scan; each subdirectory is a standalone skill package (with a `SKILL.md`) |
| `-o, --output-dir <path>` | ✅ | Output directory for scan results |

### Stage Control

| Argument | Default | Description |
|---|---|---|
| `--stage {pre-scan,runtime,full}` | `full` | `pre-scan`: static analysis + LLM scoring only; `runtime`: Docker sandbox detection only; `full`: run both stages in sequence |
| `--enable-after-tool` | off | Enable content inspection |

### Scope Filtering

| Argument | Description |
|---|---|
| `-n, --max-count <N>` | Scan only the first N skills in the directory (sorted by name) |
| `-s, --skills <name1,name2,...>` | Scan only the specified skills (comma-separated, names = skill folder names) |

### Concurrency & Sandbox Tuning

| Argument | Default | Description |
|---|---|---|
| `--parallel <N>` | `1` | Number of Docker sandboxes to run in parallel during Stage 3, recommended range 4–8 |
| `--image <name>` | `fangcunai/skillward:amd64` | Docker image used by Stage 3 |
| `--phase1-timeout <seconds>` | `300` | Phase 1 (env prep) timeout |
| `--phase2-timeout <seconds>` | `300` | Phase 2 (skill execution) timeout |
| `--max-retries <N>` | `2` | Retry count when the agent crashes inside the sandbox |
| `--retry-delay <seconds>` | `10` | Wait time between retries |

### Other

| Argument | Default | Description |
|---|---|---|
| `--safety-threshold <float>` | `0.3` | Stage 2 LLM safety confidence threshold; range 0.0–1.0; higher values are stricter |
| `--sandbox-threshold <float>` | `0.9` | Stage 2 LLM confidence upper bound |
| `-v, --verbose` | off | Verbose logging (includes static rule hit details, LLM request summaries, etc.) |

---

## 4. Common Usage Examples

### 1. Full pipeline

```bash
python guardian-api/guardian.py -i ./my_skills -o ./scan_result --enable-after-tool --parallel 4
```

### 2. Static + LLM scoring only (no Docker)

```bash
python guardian-api/guardian.py -i ./my_skills -o ./scan_result --stage pre-scan
```

### 3. Disable content inspection

```bash
python guardian-api/guardian.py -i ./my_skills -o ./scan_result
```

### 4. Debug specific skills

```bash
python guardian-api/guardian.py -i ./my_skills -o ./scan_result \
    -s aces1up_redditrank,adisinghstudent_trump-code-market-signals
```

### 5. Sample-scan the first 5 skills

```bash
python guardian-api/guardian.py -i ./my_skills -o ./scan_result -n 5
```

### 6. Raise the safety threshold

```bash
python guardian-api/guardian.py -i ./my_skills -o ./scan_result --safety-threshold 0.7
```

---

## 5. Output Files

Inside the directory specified by `-o`:

| File / Directory | Description |
|---|---|
| `guardian_report.json` | Summary report containing each skill's prescan / runtime results, status, hit counts, and elapsed time |
| `safe-skills/` | Copies of skills marked SAFE by Stage 2 (used as Stage 3 input) |
| `skill_<name>_phase1.txt` | Sandbox Phase 1 (environment preparation) agent output log |
| `skill_<name>.txt` | Sandbox Phase 2 (skill execution) agent output log |

Runtime fields in `guardian_report.json`:

| Field | Meaning |
|---|---|
| `status` | `PASSED` / `WARNING` / `ERROR` |
| `elapsed_sec` | Total sandbox execution time (seconds) |
| `blacklist_hits` | Number of blacklist hits intercepted by hooks |
| `blocks` | Actual block count |
| `content_risks` | Content risk count |
| `agent_crashed` | Whether the agent crashed inside the sandbox |
| `details` | List of hit details (rule, context) |
