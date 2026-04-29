---
name: skillward-audit
description: Security-audit a third-party skill bundle (folder with SKILL.md, or .zip / .tar.gz archive) before installing it, using the SkillWard cloud scanner. Trigger on any natural safety question about an external skill — "is this skill safe?", "audit / scan / review this skill", "should I install this?", "trustworthy?", "any malware?", "is it sketchy?" — even when the user doesn't name SkillWard explicitly. Do NOT trigger when the user is authoring their own skill, asking for a code review of code they wrote, or pointing at a built-in / first-party skill.
---

# SkillWard Audit

Thin client for the SkillWard public scanning service at
`https://skillward.fangcunleap.com`. Given a local skill bundle (folder with
`SKILL.md`, or a `.zip` / `.tar.gz` archive), this skill packages it, uploads it
to the remote service, streams scan progress, and reports the verdict.

## When to use

- **Explicit invocation** — user asks to "audit", "scan", "review", or "check
  the safety of" a skill bundle.
- **Natural safety question about an external skill** — even without the words
  "audit" or "SkillWard", treat any of these as an invocation request when a
  skill path / archive is in scope:
  - "Is this skill safe?" / "Is it safe to install?"
  - "Should I install this?" / "Should I trust this?"
  - "Any malware / backdoors / suspicious behavior in here?"
  - "Is this trustworthy?" / "Does this look sketchy?"
  - "Anything I should know before I install this?"
- **User references a skill bundle path** — a folder containing `SKILL.md`, or
  a `.zip` / `.tar.gz` / `.tgz` archive — in a safety-adjacent context.
- **Pre-install safety check** — user is about to install a third-party /
  downloaded skill and wants a security pass first.
- **Source mentioned** — user mentions ClawHub, OpenClaw, GitHub, or another
  third-party source for a skill bundle in a safety context.

## When NOT to use

- **The user is authoring their own skill** and asking for code review,
  feedback, or "does this look right?" on something they just wrote in this
  session. Do a normal code review instead — SkillWard is for vetting
  *external* code the user did not write.
- **The user just edited the skill in this session** — what they want is
  review of their own changes, not a third-party scanner.
- **Built-in / first-party skills** — Claude's own bundled skills don't need
  third-party scanning.
- **Non-skill inputs** — a regular codebase, Python package, generic repo,
  or arbitrary file that isn't shaped like a skill bundle. Decline and
  explain.
- **General malware scanning** of arbitrary files — decline; this tool only
  understands skill bundles.

## Gathering input

1. **User gave a path** — verify it exists. If it's a folder, confirm it contains
   `SKILL.md` (or a nested folder that does). If it's an archive, accept `.zip`
   / `.tar.gz` / `.tgz`.
2. **User said "this skill" / "the skill" without a path** — ask one clarifying
   question: "Which folder or archive should I scan? Please give me a path (e.g.
   `C:\path\to\skill-folder` or `./foo.zip`)."
3. **User gave a URL or GitHub link** — v1 does not support remote fetching.
   Reply: "I can't fetch URLs directly for auditing. Please `git clone` the repo
   or download the release zip first, then point me at the local path."

## Choosing language

Inspect the user's most recent 2–3 messages. If any contain CJK (Chinese /
Japanese / Korean) characters — Unicode range `U+4E00–U+9FFF` — pass
`--lang zh`. Otherwise pass `--lang en`. Default to `en` when ambiguous.

The report JSON always contains both `text` (Chinese) and `text_en` (English)
in `warnings[]`; use whichever matches `--lang` when summarizing back to the
user.

## Choosing scan depth

Default: `--depth sandbox` (static + LLM + server-side Docker sandbox, no
after-tool inspection). Override only when the user signals otherwise:

- **"quick" / "fast" / "just static" / "快速" / "只要静态"** → `--depth static`
  (seconds; skips sandbox)
- **"deep" / "thorough" / "after-tool" / "深度" / "彻底"** → `--depth deep`
  (3-15 min; full pipeline incl. after-tool capability check)

When running `deep`, **warn the user upfront**: "Deep mode runs the Docker
sandbox plus after-tool capability analysis — this typically takes 3–10 minutes.
Starting now."

## How to invoke

### ⚠️ Required — set the tool timeout explicitly in every call

Do **not** rely on your exec / bash tool's default timeout. Defaults vary
across harnesses and installations (Claude Code default is 120 s; OpenClaw
default is 1800 s but some deployments override it down to 300 s or less).
A too-short default will SIGKILL `scan.py` mid-scan, the SSE stream is cut
before the server emits the final `report` event, and **nothing gets saved**.

Pass the timeout explicitly on every invocation. Match the depth you're
running:

| Depth     | Claude Code (`timeout`, ms) | OpenClaw (`timeoutSec`, s) | Typical duration |
| --------- | --------------------------- | -------------------------- | ---------------- |
| `static`  | 60000                       | 60                         | 5–15 s           |
| `sandbox` | 900000                      | 900                        | 60 s – 10 min    |
| `deep`    | 1200000                     | 1200                       | 3 min – 15 min   |

Concrete examples:

- **Claude Code** — invoke the Bash tool with `timeout: 900000` (for
  sandbox) or `timeout: 1200000` (for deep).
- **OpenClaw** — invoke the `exec` tool with `timeoutSec: 900` (for
  sandbox) or `timeoutSec: 1200` (for deep).
- **Other harnesses** — pass the equivalent per-call timeout parameter;
  the values above are the minimum that lets the server-side sandbox
  finish.

If your harness's exec/bash tool does **not** accept a per-call timeout
override, and you cannot globally raise its default to at least 900 s,
do **not** silently proceed with `--depth sandbox` / `--depth deep`.
Fall back to `--depth static` and tell the user that the sandbox stage
could not be run because the current tool harness would kill the scan
before completion.

While the scan runs, stdout stays empty until the final summary line; all
heartbeat / progress output goes to stderr. Do not interpret "no stdout
yet" as "stuck" — wait for the subprocess to exit.

The scan script lives at `scripts/scan.py` inside this skill's own directory.
Substitute `<skill_dir>` with the absolute path to the directory that contains
this `SKILL.md`:

```bash
python <skill_dir>/scripts/scan.py \
  "<input-path>" \
  --lang <zh|en> \
  --depth <static|sandbox|deep> \
  --out "<input-dirname>/skillward-report.json"
```

- `<input-path>` — the folder or archive. Quote it if it contains spaces or
  non-ASCII characters.
- `--out` — where to save the full JSON report. Default is
  `./skillward-report.json` in the current directory; prefer placing it
  alongside the input so the user can find it easily.

The script writes progress messages to **stderr** and exactly one summary line
to **stdout** on success. Read the JSON file for details.

### Override the service URL (rare)

If the user is self-hosting SkillWard or you need to point at a staging
endpoint, prefix the command with `SKILLWARD_API_BASE=<url>`. Otherwise omit.

## Interpreting the report

The stdout summary line looks like:

```
VERDICT: SAFE | <skill_name> | <latency>s | <N> warning(s)
```

Verdict values (case may vary depending on server version — handle all):

| Verdict | User-facing summary |
|---|---|
| `SAFE` / `Safe` | Safe to install. Static analysis, LLM review, and sandbox all clean. Note the latency. |
| `MEDIUM RISK` / `Medium Risk` / `WARNING` | **Caution.** There are `<N>` warnings. Surface the top 2-3 from `warnings[]` (prefer `text_en` for English users). Advise the user to review before installing. |
| `HIGH RISK` / `High Risk` / `DANGER` | **Do NOT install.** Lead with the top warning, then enumerate all `level: "critical"` items and any `recommendations`. |

When summarizing warnings, prefer items with `level` in `("critical", "warning")`
over `"info"`. For English output use `text_en` and `source_en`; for Chinese use
`text` and `source`.

Always tell the user where the full JSON report was saved — `scan.py` prints
the path on its final stderr line (`[done] report saved to ...`) — so they
can open it for details. If they ask a follow-up question about a specific
finding, read the report file to answer precisely.

## Exit codes

| Code | Meaning | Action |
|---|---|---|
| 0 | Success — report saved | Summarize the verdict |
| 2 | Stream ended with no report | Tell user scan didn't complete; suggest retry |
| 3 | No `SKILL.md` in input | Ask user to confirm path — this isn't a skill bundle |
| 4 | Service unreachable | Check user's network; mention `SKILLWARD_API_BASE` override if relevant |
| 5 | Server error (5xx) | Report the HTTP error; suggest retry later |
| 6 | Scan timeout | Suggest `--depth static` for a faster check |

## Examples

In each example, substitute `<skill_dir>` with the absolute path of the
directory that contains this `SKILL.md`. `--out` is omitted because
`scan.py` defaults to placing the report alongside the input.

**Example 1** — user: "Can you audit `/home/alice/Downloads/cool-skill/`
before I install it?"

Folder input, default sandbox depth:

```bash
python <skill_dir>/scripts/scan.py \
  "/home/alice/Downloads/cool-skill/" \
  --lang en --depth sandbox
```

Summarize the verdict in English, surfacing the top 2–3 `warnings[].text_en`
items (prefer `level: critical` / `warning` over `info`). Tell the user where
the report JSON was saved.

**Example 2** — user: "Is this bundle safe? `/tmp/untrusted-skill.zip`"

Archive input:

```bash
python <skill_dir>/scripts/scan.py \
  "/tmp/untrusted-skill.zip" \
  --lang en --depth sandbox
```

**Example 3** — user: "Quick safety check on `./vendor-skill/`?"

Quick / static signal — skip the sandbox stage to return in seconds:

```bash
python <skill_dir>/scripts/scan.py \
  "./vendor-skill/" \
  --lang en --depth static
```

Static depth runs static analysis + LLM review only (typically 5–15 s) and
sets `stages.runtime.status` to `"SKIPPED"` in the report — that's expected
for this depth, not an error. Real-world fast-path SAFE scans on the public
service return in ~4–7 s.

**Example 4** — user: "Do a deep audit on `C:/Users/alice/skills/my-skill/`
before I install it."

First warn the user: "Deep mode runs the sandbox plus after-tool capability
analysis — usually 3–10 minutes. Starting now." Then:

```bash
python <skill_dir>/scripts/scan.py \
  "C:/Users/alice/skills/my-skill/" \
  --lang en --depth deep
```

Forward-slashes work on Windows and sidestep shell escaping of backslashes.

**Example 5** — user: "Audit https://github.com/foo/cool-skill before I
install."

URL input — remote fetching is not supported. Do **not** run `scan.py`.
Reply:

> I can't fetch URLs directly for auditing. Please `git clone` the repo or
> download the release zip first, then point me at the local path.

## Troubleshooting notes

- The server may **skip the Docker sandbox** automatically when its LLM
  classifier has very high confidence (≥ 0.9) that the skill is safe. In this
  case `stages.runtime.status` will be `"SKIPPED"` — that's expected, not an
  error.
- The `skill_name` in the report comes from the skill's own `SKILL.md`
  frontmatter, not the folder name.
- Windows users: quote paths containing Chinese characters with double quotes.
