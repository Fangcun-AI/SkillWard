# Update Report · 2026-04-24

---

## Skill release — `skillward-audit-skill`

SkillWard is now also distributed as a **Claude Code / OpenClaw skill**. Once installed under the agent's skill directory, any agent can audit a local skill bundle (folder containing `SKILL.md`, `.zip`, or `.tar.gz` archive) directly inside a conversation — no need to leave the chat, open the Web UI, or run the CLI by hand.

**Repository**: <https://github.com/Fangcun-AI/SkillWard> — under `skillward-audit-skill/`.

### 1. What it does

Given a path to a skill folder or archive, the skill:

1. Packages the local bundle into an in-memory `.zip` (skipping `__pycache__`, `.git`, `node_modules`, `.venv`, and `*.pyc`).
2. Uploads it to `https://skillward.fangcunleap.com` via `/api/scan/upload-folder`.
3. Streams Stage A → B → C progress over SSE; heartbeat lines go to stderr so the agent can render live progress.
4. Saves the full JSON report next to the input and prints a one-line verdict summary to stdout.

The Stage A static analysis, Stage B LLM triage, and Stage C Docker sandbox stages are **the same pipeline** that powers the Web UI and CLI — the skill is a thin client.

### 2. Three depth modes

| Depth     | Stages                              | Typical duration | When to use |
|-----------|-------------------------------------|------------------|-------------|
| `static`  | Stage A only                        | 5 – 15 s         | Quick triage / large batch pre-screen |
| `sandbox` | A + B + C (Docker sandbox)          | 1 – 10 min       | **Default** — the standard audit |
| `deep`    | A + B + C + after-tool analysis     | 3 – 15 min       | Pre-install audit of a high-stakes skill |

### 3. Cross-harness timeout guidance

Long-running scans are sensitive to the agent harness's per-call shell-tool timeout. The skill's `SKILL.md` instructs the agent to **explicitly pass the per-call timeout in every invocation**, with concrete values for both Claude Code (`timeout` in milliseconds) and OpenClaw (`timeoutSec` in seconds). When the harness cannot honor a long timeout, the skill falls back to `--depth static` and tells the user the sandbox stage was skipped — rather than silently SIGKILL-ing mid-scan.

### 4. Auditable verdict, not opaque approval

The skill never declares "safe to install" on its own. It returns the SkillWard verdict (`SAFE` / `MEDIUM RISK` / `HIGH RISK`), surfaces the top warnings (with bilingual `text` / `text_en` fields), and points at the saved JSON report so the user can drill in.
