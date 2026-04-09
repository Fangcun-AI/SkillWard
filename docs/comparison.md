# Comparison Reference

We ran two public tools on the same Skills dataset as reference baselines. These tools are valuable for code- and policy-level inspection, but neither includes isolated runtime verification.

---

## Product A (Static + LLM, No Sandbox)

Product A is a mature Skill security scanning tool with a two-layer architecture of static analysis + LLM evaluation.

| Verdict | Percentage |
|---------|------------|
| **SAFE** | 61.3% |
| **UNSAFE** | 38.7% |

**Strengths:**
- Broad static analysis coverage including command injection, data exfiltration, prompt injection, and more
- LLM evaluation layer understands Skill semantic intent, not purely pattern-based
- Mature open-source project with active community

**Limitations:**

- **False positives:** Static rules alone cannot understand code context and intent — e.g., standard `node_modules` library code (such as `es-abstract/function-bind`) triggers command injection rules; CJK text is misidentified as homoglyph attacks; security education documents are flagged as real prompt injection; normal local file writes are flagged as data exfiltration
- **False negatives:** Threats that only manifest during Skill execution are completely undetectable — e.g., credential exfiltration via `curl`, `crontab` persistence backdoors, `postinstall` supply chain attacks
- **Noise:** Approximately 88.6% of total findings are INFO-level noise, requiring manual filtering

---

## Product B (Static Matching + Cloud API, No Sandbox)

Product B is a scanning tool offering both a CLI and a Web UI. The local client collects Skill content and sends it to a cloud API for analysis.

| Verdict | Percentage |
|---------|------------|
| **SAFE** | 45% |
| **UNSAFE** | 55% |

**Strengths:**
- Supports auto-discovery of multiple AI Agents on the local machine (Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, etc.)
- Correctly identifies some real threats (hardcoded API keys, on-chain transaction submissions, pipe-to-shell installs, etc.)
- Free Web UI lowers the barrier to entry
- Integrations with multiple third-party platforms

**Limitations:**

- **False positives:** Relies on keyword matching rather than behavior understanding, leading to high false positive rates. For example:
  - Mentioning "Binance" triggers a financial risk flag regardless of whether the Skill is a read-only query tool or an actual trading bot
  - Mentioning "web_search" triggers a third-party content flag even in static documentation templates with zero network calls
  - A pure text decision framework (zero code, zero network) flagged because it mentions "external perspective"
- **Coarse severity classification:** The vast majority of issues are uniformly labeled HIGH — a read-only market data query tool receives the same severity as a live trading bot, making it impossible for users to prioritize
- **False negatives:** The lack of runtime verification means threats hidden in dynamically constructed commands, runtime-downloaded dependencies, or disguised content cannot be detected
- **Cloud dependency:** Core analysis logic runs on remote servers; the tool cannot be used in offline environments

---

## Summary

| Dimension | SkillWard | Product A | Product B |
|-----------|-----------|-----------|-----------|
| **Detection architecture** | Static + LLM + Docker sandbox | Static + LLM | Static matching + Cloud API |
| **Runtime sandbox** | Docker isolated execution + honeypot decoys | None | None |
| **False positive control** | Sandbox verification filters gray zone, reduces FP | Higher FP rate | Keyword-driven, high FP rate |
| **Severity classification** | SAFE / ALERT / DANGER (3-tier) | SAFE / UNSAFE (2-tier) | Nearly all labeled HIGH |
| **Detection coverage** | Known patterns + semantic intent + runtime behavior | Known patterns + semantic intent | Keywords + cloud rules |
| **Agent auto-discovery** | No (scans specified directory) | No | Yes (auto-discovers local Agent configs) |

> **Key difference:** Both Product A and Product B have their own strengths in code-level inspection, but neither includes runtime verification. SkillWard adds Docker sandbox testing on top of static and LLM analysis, turning gray-zone warnings that cannot be confirmed through code review into high-confidence runtime evidence.
