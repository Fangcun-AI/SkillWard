---
name: skillward-audit
description: Security-audit an Anthropic/OpenClaw skill bundle by uploading it to the SkillWard public scanning service (static analysis + LLM review + Docker sandbox). Use when the user asks to audit, scan, review, or check the safety of a skill folder, SKILL.md bundle, or downloaded .zip/.tar.gz — especially before installing a third-party skill.
---

# SkillWard Audit

Thin client for the SkillWard public scanning service at
`https://skillward.fangcunleap.com`. Given a local skill bundle (folder with
`SKILL.md`, or a `.zip` / `.tar.gz` archive), this skill packages it, uploads it
to the remote service, streams scan progress, and reports the verdict.

## When to use

- User asks to "audit", "scan", "review", "check the safety of" a skill
- User references a path to a folder containing `SKILL.md`, or a `.zip` /
  `.tar.gz` / `.tgz` archive
- User is about to install a third-party / downloaded skill and wants a
  security check first
- User mentions ClawHub, OpenClaw, Anthropic skill bundles in a safety context

## When NOT to use

- General malware scanning of arbitrary files (not skill-shaped) — decline
- Scanning a regular codebase, Python package, or repo that isn't a skill bundle
- Scanning Claude's own built-in skills (not third-party)

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

Always tell the user where the full JSON report was saved (the `--out` path)
so they can open it for details. If they ask a follow-up question about a
specific finding, read the report file to answer precisely.

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
directory that contains this `SKILL.md`.

**Example 1** — user: "Can you audit `~/Downloads/cool-skill/` before I
install it?"

Folder input, default sandbox depth:

```bash
python <skill_dir>/scripts/scan.py \
  "~/Downloads/cool-skill/" \
  --lang en --depth sandbox \
  --out "~/Downloads/cool-skill/skillward-report.json"
```

Summarize the verdict in English, surfacing the top 2–3 `warnings[].text_en`
items (prefer `level: critical` / `warning` over `info`). Tell the user where
the report JSON was saved.

**Example 2** — user: "Is this bundle safe? `/tmp/untrusted-skill.zip`"

Archive input:

```bash
python <skill_dir>/scripts/scan.py \
  "/tmp/untrusted-skill.zip" \
  --lang en --depth sandbox \
  --out "/tmp/untrusted-skill.skillward-report.json"
```

**Example 3** — user: "Do a deep audit on `C:/Users/alice/skills/my-skill/`
before I install it."

First warn the user: "Deep mode runs the sandbox plus after-tool capability
analysis — usually 3–10 minutes. Starting now." Then:

```bash
python <skill_dir>/scripts/scan.py \
  "C:/Users/alice/skills/my-skill/" \
  --lang en --depth deep \
  --out "C:/Users/alice/skills/my-skill/skillward-report.json"
```

Forward-slashes work on Windows and sidestep shell escaping of backslashes.

## Troubleshooting notes

- The server may **skip the Docker sandbox** automatically when its LLM
  classifier has very high confidence (≥ 0.9) that the skill is safe. In this
  case `stages.runtime.status` will be `"SKIPPED"` — that's expected, not an
  error.
- The `skill_name` in the report comes from the skill's own `SKILL.md`
  frontmatter, not the folder name.
- Windows users: quote paths containing Chinese characters with double quotes.