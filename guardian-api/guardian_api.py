#!/usr/bin/env python3
"""
Guardian API: SSE streaming backend for guardian-ui.

Wraps the guardian.py pipeline and streams log events via Server-Sent Events.
The frontend connects to /api/scan/stream to get real-time pipeline output.

Usage:
    pip install -r requirements.txt
    python guardian_api.py                          # default port 8899
    python guardian_api.py --port 9000              # custom port
"""

import argparse
import asyncio
import json
import os
import re
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from datetime import datetime

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")

from fastapi import FastAPI, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from config import get_settings, update_settings, reset_settings

# Ensure guardian.py is importable
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(SCRIPT_DIR.parent))

app = FastAPI(title="Skill Guardian API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _sse_event(stage: int, event_type: str, text: str, data: dict | None = None):
    """Format an SSE event."""
    payload = {
        "stage": stage,
        "type": event_type,
        "text": text,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }
    if data:
        payload["data"] = data
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def _t(zh: str, en: str, lang: str) -> str:
    """Return Chinese or English text based on lang parameter."""
    return zh if lang == "zh" else en


_RX_BLACKLIST = re.compile(
    r"^\s*(?:\[plugins\]\s*)?(?:\[FangcunGuard\]\s*)?Blacklist hit:\s*([^|]+?)\s*\|\s*(.+?)\s*$"
)
_RX_BLOCK = re.compile(
    r"^\s*\[tools\]\s+\w+\s+failed:\s*\[FangcunGuard\]\s*High-risk operation blocked\s*"
    r"\(Risk Level\s*(\d+)\):\s*(.+?)\s*$"
)
_RX_CONTENT_RISK = re.compile(
    r"\[FangcunGuard\][^:]*?risk[= ](\d+)[^:]*?:?\s*(.+?)\s*$", re.IGNORECASE
)


def _humanize_runtime_detail(d: str):
    """Map a raw sandbox detail line into (level, zh_text, en_text).

    We only DETECT risk in the sandbox; nothing is actually intercepted, so
    drop "blocked / 拦截" framing in user-facing text. Returns None for empty input.
    """
    s = (d or "").strip()
    if not s:
        return None

    m = _RX_BLOCK.match(s)
    if m:
        risk_level, behavior = int(m.group(1)), m.group(2).strip()
        level = "critical" if risk_level >= 3 else "warning"
        return (
            level,
            f"检测到高风险行为：{behavior}",
            f"Detected high-risk behavior: {behavior}",
        )

    m = _RX_BLACKLIST.match(s)
    if m:
        tool, behavior = m.group(1).strip(), m.group(2).strip()
        return (
            "warning",
            f"检测到行为：{behavior}（工具：{tool}）",
            f"Detected behavior: {behavior} (tool: {tool})",
        )

    m = _RX_CONTENT_RISK.search(s)
    if m:
        risk_level, behavior = int(m.group(1)), m.group(2).strip()
        level = "critical" if risk_level >= 3 else "warning"
        return (
            level,
            f"检测到内容风险：{behavior}",
            f"Detected content risk: {behavior}",
        )

    cleaned = re.sub(r"^\[(plugins|tools)\]\s*", "", s)
    cleaned = re.sub(r"\[FangcunGuard\]\s*", "", cleaned)
    return ("warning", f"检测到行为：{cleaned}", f"Detected behavior: {cleaned}")


def _build_report(prescan: dict, runtime: dict, scanner_safe: bool, runtime_safe: bool,
                   latency: dict = None, batch_id: str = None, lang: str = "en",
                   skill_hash: str = "", save: bool = True) -> dict:
    """Build a structured execution report for the frontend.

    Always emits BOTH zh and en content for warnings/recommendations so the UI
    can switch languages at display time without re-querying the backend.
    `lang` kept for backward compatibility but no longer filters stored content.
    """
    status = runtime.get("status", "UNKNOWN") if runtime else prescan.get("safety_verdict", "UNKNOWN")
    runtime_confirmed_threat = status in ("DANGER", "CONTENT_RISK", "High Risk")
    is_false_negative = scanner_safe and runtime_confirmed_threat
    # Skill is sandbox-verified when runtime actually ran (not SKIPPED/UNKNOWN).
    # In that case, the static-analysis max-severity label is noise — Stages B/C supersede it.
    sandbox_ran = status not in ("UNKNOWN", "SKIPPED", "", "N/A")

    warnings = []
    details = runtime.get("details", []) if runtime else []
    cap_indicators = runtime.get("cap_indicators", []) if runtime else []

    def _add_w(level, zh_source, en_source, zh_text, en_text):
        warnings.append({
            "level": level,
            "source": zh_source,
            "source_en": en_source,
            "text": zh_text,
            "text_en": en_text,
        })

    if prescan.get("findings_count", 0) > 0:
        if sandbox_ran:
            zh_t = f"检测到 {prescan['findings_count']} 项发现"
            en_t = f"Detected {prescan['findings_count']} findings"
        else:
            zh_t = f"检测到 {prescan['findings_count']} 项发现（最高严重级别：{prescan.get('max_severity', 'N/A')}）"
            en_t = f"Detected {prescan['findings_count']} findings (max severity: {prescan.get('max_severity', 'N/A')})"
        _add_w("info", "静态分析", "Static Analysis", zh_t, en_t)

    if prescan.get("safety_confidence") is not None:
        conf = prescan["safety_confidence"]
        llm_reason_zh = prescan.get("llm_reason", "") or ""
        llm_reason_en = prescan.get("llm_reason_en", "") or llm_reason_zh
        _add_w(
            "info" if conf >= 0.7 else "warning",
            "LLM 研判", "LLM Evaluation",
            f"安全置信度：{conf:.2f} — {llm_reason_zh}",
            f"Safety confidence: {conf:.2f} — {llm_reason_en}",
        )

    _seen_behaviors = set()
    for d in details:
        norm = _humanize_runtime_detail(d)
        if not norm:
            continue
        level, zh_t, en_t = norm
        if zh_t in _seen_behaviors:
            continue
        _seen_behaviors.add(zh_t)
        _add_w(level, "运行时沙箱", "Runtime Sandbox", zh_t, en_t)

    # Always add a summary "运行时沙箱" warning when sandbox actually ran, so UI
    # has a sandbox section even for clean-Safe runs (with no per-detail events).
    # For high/medium-risk runs the per-behavior entries above replace the summary.
    if sandbox_ran:
        _rt_elapsed = runtime.get("elapsed_sec", 0) if runtime else 0
        if status in ("Safe", "PASSED", "SAFE"):
            _add_w(
                "info", "运行时沙箱", "Runtime Sandbox",
                f"沙箱执行完成（耗时 {_rt_elapsed:.0f}s），未检测到异常工具调用或数据外泄行为。",
                f"Sandbox execution completed ({_rt_elapsed:.0f}s) with no anomalous tool calls or data exfiltration detected.",
            )
        elif status in ("Medium Risk", "WARNING", "High Risk", "DANGER", "BLOCKED", "CONTENT_RISK"):
            if not _seen_behaviors:
                _is_high = status in ("High Risk", "DANGER", "BLOCKED", "CONTENT_RISK")
                _add_w(
                    "critical" if _is_high else "warning",
                    "运行时沙箱", "Runtime Sandbox",
                    "沙箱检测到风险信号，但未捕获到具体行为细节，建议人工复核日志。",
                    "Sandbox detected risk signals but no specific behavior captured. Manual log review recommended.",
                )
        elif status == "TIMEOUT":
            _add_w(
                "info", "运行时沙箱", "Runtime Sandbox",
                f"沙箱执行超时（{_rt_elapsed:.0f}s 未完成），未能完整验证。参考静态和 LLM 结果。",
                f"Sandbox execution timed out ({_rt_elapsed:.0f}s), verification incomplete. Refer to static and LLM results.",
            )
        elif status in ("INCOMPLETE", "INCONCLUSIVE"):
            _add_w(
                "info", "运行时沙箱", "Runtime Sandbox",
                "Agent 未完整执行 skill 主要功能（可能在询问用户输入），本次未完整验证。建议重试扫描。",
                "Agent did not fully execute the skill's main function (may have requested user input); verification incomplete. Rescan recommended.",
            )
        elif status in ("ERROR", "SANDBOX_FAILED"):
            _add_w(
                "info", "运行时沙箱", "Runtime Sandbox",
                "沙箱执行出错，本次未能完整验证。建议检查依赖和日志。",
                "Sandbox execution encountered an error; verification incomplete. Check dependencies and logs.",
            )

    guard_audit = runtime.get("guard_model_audit") if runtime else None
    if guard_audit:
        _raw_api = guard_audit.get("raw_api_output") or {}
        api_risk = _raw_api.get("risk_level") or guard_audit.get("api_risk_level") or guard_audit.get("risk_level") or 0
        risk_label = _raw_api.get("risk_label") or guard_audit.get("risk_label") or "unknown"
        if risk_label in ("Low Risk", "low_risk"):
            risk_label = "Medium Risk"
        analysis = _raw_api.get("analysis") or guard_audit.get("analysis") or ""
        remediation = _raw_api.get("remediation") or ""
        level = "critical" if api_risk >= 3 else "warning" if api_risk >= 2 else "info"
        _add_w(
            level,
            "模型审计", "Model Audit",
            f"风险等级: {risk_label} (level={api_risk}) — {analysis[:300]}",
            f"Risk level: {risk_label} (level={api_risk}) — {analysis[:300]}",
        )
        if remediation and remediation.strip().lower() != "none":
            _add_w(
                "info",
                "修复建议", "Remediation",
                remediation[:500], remediation[:500],
            )

    if is_false_negative:
        _add_w(
            "critical",
            "综合研判", "Cross-validation",
            "静态分析未发现风险，但沙箱运行时检测到异常行为，建议仔细审查该 Skill",
            "Static analysis found no risk but runtime sandbox detected anomalous behavior. Manual review recommended.",
        )

    if prescan and prescan.get("safety_confidence") is not None:
        conf = prescan["safety_confidence"]
        if 0.3 <= conf < 0.7:
            skill_desc_raw = prescan.get("skill_description", "")
            if skill_desc_raw:
                _add_w(
                    "warning",
                    "SKILL.md 分析", "SKILL.md Analysis",
                    f'Skill 声称的功能: "{skill_desc_raw[:200]}" — LLM 评估认为描述与实际代码行为存在差异（置信度 {conf:.2f}）',
                    f'Skill claims: "{skill_desc_raw[:200]}" — LLM evaluation found discrepancy between description and actual code behavior (confidence {conf:.2f})',
                )

    recommendations = []
    recommendations_en = []

    def _add_r(zh, en):
        recommendations.append(zh)
        recommendations_en.append(en)

    all_indicators = [d.lower() for d in details + cap_indicators]
    has_external = any("external" in d or "curl" in d or "exfil" in d or "domain" in d for d in all_indicators)
    has_credential = any("credential" in d or "api_key" in d or "token" in d or "secret" in d for d in all_indicators)
    has_write_root = any("write to /root" in d or "write" in d for d in all_indicators)

    if status in ("DANGER", "CONTENT_RISK", "High Risk"):
        _add_r(
            "禁止使用该 Skill — 检测到恶意或高风险行为。",
            "DO NOT USE this skill — malicious or high-risk behavior detected.",
        )
        if has_external:
            _add_r(
                "该 Skill 试图访问外部服务或外泄数据，具体行为：向外部域名发起网络请求（如 curl/wget/fetch），可能将工作环境中的敏感数据（API 密钥、配置文件等）发送到外部服务器。建议：审查 SKILL.md 中所有涉及网络请求的步骤，确认目标域名是否可信。",
                "This skill attempts to access external services or exfiltrate data: it makes network requests to external domains (e.g. curl/wget/fetch), potentially sending sensitive data (API keys, config files, etc.) to external servers. Recommendation: Review all network-related steps in SKILL.md and verify target domains are trusted.",
            )
        if has_credential:
            _add_r(
                "检测到凭证访问行为 — 该 Skill 在执行过程中读取了 API 密钥或令牌文件。即使 Skill 声称只做本地检查，读取凭证后配合网络请求可能导致密钥泄露。建议：在沙箱环境中不放置真实凭证，或对凭证文件设置严格的访问权限。",
                "Credential access detected — this skill reads API keys or token files during execution. Even if the skill claims to only perform local checks, reading credentials combined with network requests could lead to key leakage. Recommendation: Do not place real credentials in the sandbox, or set strict access permissions on credential files.",
            )
        if has_external and has_credential:
            _add_r(
                "高危组合：凭证读取 + 外部请求 = 典型数据外泄模式。该 Skill 先读取了本地凭证/密钥文件，随后向外部域名发起请求，这是经典的凭证窃取攻击链。强烈建议禁止使用。",
                "HIGH RISK COMBINATION: Credential access + external requests = classic data exfiltration pattern. This skill reads local credential/key files then makes requests to external domains — a classic credential theft attack chain. Strongly recommend blocking.",
            )
        if is_false_negative:
            _add_r(
                "该 Skill 通过了静态分析和 LLM 评估（被误判为安全），仅在运行时沙箱中才暴露出恶意行为。这说明多 Stage 检测的重要性 — 对于此类善于伪装的 Skill，必须启用深度扫描（Docker 沙箱）才能有效识别。",
                "This skill passed static analysis and LLM evaluation (false negative) — malicious behavior was only exposed in the runtime sandbox. This demonstrates the importance of multi-stage detection. For skills that are good at disguising themselves, deep scanning (Docker sandbox) must be enabled.",
            )
        if has_write_root:
            _add_r(
                "该 Skill 尝试向系统敏感路径写入文件，可能修改系统配置或植入后门。建议：限制 Skill 的 write 工具权限，仅允许写入指定的输出目录。",
                "This skill attempts to write files to sensitive system paths, potentially modifying system configuration or planting backdoors. Recommendation: Restrict the skill's write tool permissions to only allow writing to designated output directories.",
            )
    elif status in ("WARNING", "Medium Risk"):
        _add_r(
            "谨慎使用 — 检测到中等风险指标，建议在部署前进行人工审查。",
            "Use with caution — medium risk indicators detected. Manual review recommended before deployment.",
        )
        if has_external:
            _add_r(
                "检测到外部网络请求行为，虽未被判定为高危，但仍需确认目标域名是否在允许列表中。建议：在生产环境中配置网络白名单，仅允许 Skill 访问已审核的域名。",
                "External network request behavior detected. While not classified as high risk, verify target domains are on the allowlist. Recommendation: Configure a network whitelist in production, only allowing the skill to access approved domains.",
            )
        if has_credential:
            _add_r(
                "该 Skill 访问了凭证文件，请确认是否为必要操作。建议：使用临时令牌或受限 API 密钥，避免暴露主密钥。",
                "This skill accessed credential files — verify this is necessary. Recommendation: Use temporary tokens or restricted API keys to avoid exposing master keys.",
            )
        _add_r(
            "建议在生产环境中限制该 Skill 的工具权限（如禁用 exec/write），并保持 FangcunGuard 实时监控开启。",
            "Recommendation: Restrict tool permissions for this skill in production (e.g. disable exec/write) and keep FangcunGuard real-time monitoring enabled.",
        )
    elif status in ("PASSED", "Safe"):
        _add_r(
            "该 Skill 通过所有安全检查，可在标准防护下安全使用。",
            "This skill passed all security checks and can be safely used under standard protection.",
        )
        _add_r(
            "建议在生产环境中保持 FangcunGuard 监控开启，提供持续运行时保护。即使当前检测安全，Skill 的行为可能因输入不同而变化。",
            "Recommendation: Keep FangcunGuard monitoring enabled in production for continuous runtime protection. Even if currently detected as safe, skill behavior may vary with different inputs.",
        )
    elif status == "TIMEOUT":
        _add_r(
            "执行超时 — 该 Skill 在规定时间内未完成执行，可能原因：死循环、资源耗尽、等待不可达的外部服务响应。建议：检查 Skill 逻辑，增加超时时间后重新测试，或在资源受限环境中设置更严格的执行上限。",
            "Execution timeout — the skill did not complete within the time limit. Possible causes: infinite loop, resource exhaustion, or waiting for unreachable external services. Recommendation: Check skill logic, increase timeout and retest, or set stricter execution limits in resource-constrained environments.",
        )
    elif status == "INCONCLUSIVE":
        _add_r(
            "沙箱执行未能完成（可能是 Skill 依赖缺失或代码兼容性问题），已回退到静态分析结果。该结果不代表安全风险，仅表示无法通过运行时验证。",
            "Sandbox execution could not complete (possibly due to missing skill dependencies or code compatibility issues). Fell back to static analysis results. This does not indicate a security risk, only that runtime verification was not possible.",
        )
    elif status == "ERROR":
        _add_r(
            "执行过程中遇到错误，可能原因：环境依赖缺失、Skill 代码 bug、Docker 容器配置问题。建议：检查完整日志，确认所需的运行时依赖是否已安装。",
            "An error occurred during execution. Possible causes: missing environment dependencies, skill code bugs, or Docker container configuration issues. Recommendation: Check full logs and verify required runtime dependencies are installed.",
        )

    # Extract skill info from SKILL.md
    skill_desc = ""
    skill_capabilities = []
    skill_md_text = ""
    skill_path = prescan.get("skill_path", "")
    if skill_path:
        skill_md = Path(skill_path) / "SKILL.md"
        if skill_md.exists():
            try:
                content = skill_md.read_text(errors="replace")
                skill_md_text = content[:8000]
                if content.startswith("---"):
                    fm_end = content.index("---", 3)
                    fm_text = content[3:fm_end]
                    desc_match = re.search(r'description:\s*["\']?(.*?)["\']?\s*$', fm_text, re.MULTILINE)
                    if desc_match:
                        skill_desc = desc_match.group(1).strip().strip("\"'")
                    tools_match = re.search(r'allowed-tools:\s*\[(.*?)\]', fm_text)
                    if tools_match:
                        skill_capabilities = [t.strip().strip("\"'") for t in tools_match.group(1).split(",")]
            except Exception:
                pass

    lat = latency or {}
    final_verdict = status

    _skill_path = prescan.get("skill_path", "")
    _skill_folder = Path(_skill_path).name if _skill_path else ""

    report = {
        "verdict": final_verdict,
        "skill_name": prescan.get("skill_name", "unknown"),
        "skill_folder": _skill_folder,
        "skill_description": skill_desc,
        "capabilities": skill_capabilities,
        "false_negative": is_false_negative,
        "scan_time": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
        "source": "用户提交",
        "source_en": "User Submitted",
        "latency": {
            "total": round(lat.get("total", 0), 2),
            "static": round(lat.get("static", 0), 2),
            "llm": round(lat.get("llm", 0), 2),
            "runtime": round(lat.get("runtime", 0), 2),
            "verify": round(lat.get("verify", 0), 2),
        },
        "stages": {
            "static": {
                "verdict": prescan.get("safety_verdict", "N/A"),
                "findings": prescan.get("findings_count", 0),
                "severity": prescan.get("max_severity", "N/A"),
                "skill_md": skill_md_text,
            },
            "llm": {
                "confidence": prescan.get("safety_confidence"),
                "reason": prescan.get("llm_reason", ""),
                "reason_en": prescan.get("llm_reason_en", ""),
            },
            "runtime": {
                "status": runtime.get("status", "N/A") if runtime else "SKIPPED",
                "elapsed": runtime.get("elapsed_sec", 0) if runtime else 0,
                "blacklist_hits": runtime.get("blacklist_hits", 0) if runtime else 0,
                "blocks": runtime.get("blocks", 0) if runtime else 0,
            },
        },
        "warnings": warnings,
        "recommendations": recommendations,
        "recommendations_en": recommendations_en,
        "skill_hash": skill_hash,
    }

    # Pre-compute the same scan_id that scan_db.save_scan will use, so the SSE
    # "report" event carries it and the frontend can call /api/scan/{id}/remediate
    # immediately (without a follow-up history fetch).
    import hashlib as _hl
    report["id"] = _hl.md5(
        f"{report['skill_name']}{report['scan_time']}".encode()
    ).hexdigest()[:16]

    if batch_id:
        report["batch_id"] = batch_id

    if save:
        from scan_db import save_scan
        save_scan(report, skill_hash=report.pop("skill_hash", ""))
    # save=False: skill_hash stays in the report dict; caller pops + saves after final yield.
    return report


async def _run_pipeline_stream(skill_path: str, policy: str = "balanced",
                                use_llm: bool = True, use_runtime: bool = True,
                                enable_after_tool: bool = True, lang: str = "en"):
    """Generator that runs the real pipeline and yields SSE events."""
    settings = get_settings()
    _pipeline_start = time.time()
    _latency = {"total": 0, "static": 0, "llm": 0, "runtime": 0, "verify": 0}

    # ── Compute skill hash for deduplication ──
    from scan_db import compute_skill_hash, find_by_skill_hash
    _skill_hash = compute_skill_hash(skill_path)
    _cached = find_by_skill_hash(_skill_hash, lang=lang) if _skill_hash else None
    if _cached:
        yield _sse_event(0, "step", _t(f"检测到相同 Skill 已扫描过（{_cached.get('scan_time', '')}），直接返回历史结果", f"Cache hit — same Skill scanned at {_cached.get('scan_time', '')}, returning cached result", lang))
        await asyncio.sleep(0.5)
        yield _sse_event(0, "report", _t("扫描报告", "Scan Report", lang), {"report": _cached})
        await asyncio.sleep(0.2)
        yield _sse_event(0, "done", _t("流水线完成（缓存命中）", "Pipeline complete (cache hit)", lang), {"prescan": {}, "runtime": {}})
        return

    # ══════════════════════════════════════════════════════════════
    # Stage 1: Static Analysis + LLM Safety Scoring
    # ══════════════════════════════════════════════════════════════
    yield _sse_event(1, "stage", _t("Stage A+B: 静态分析 + LLM 安全评估", "Stage A+B: Static Analysis + LLM Evaluation", lang))
    await asyncio.sleep(0.3)

    yield _sse_event(1, "step", f"Loading skill: {Path(skill_path).name}")
    await asyncio.sleep(0.2)

    yield _sse_event(1, "step", "Running static analysis (YARA + regex + behavioral)...")
    await asyncio.sleep(0.1)

    _t_static_start = time.time()
    try:
        from skill_scanner.core.scanner import SkillScanner
        from skill_scanner.core.scan_policy import ScanPolicy
        from skill_scanner.core.analyzer_factory import build_core_analyzers

        def _do_static_scan():
            p = ScanPolicy.default()
            analyzers = build_core_analyzers(p)
            scanner = SkillScanner(analyzers=analyzers, policy=p)
            result = scanner.scan_skill(Path(skill_path))
            findings_list = [f.to_dict() for f in result.findings]
            return {
                "skill_name": result.skill_name,
                "skill_path": result.skill_directory,
                "findings": findings_list,
                "findings_count": len(findings_list),
                "max_severity": result.max_severity.value,
                "is_safe": result.is_safe,
                "analyzers_used": result.analyzers_used,
                "scan_duration": result.scan_duration_seconds,
            }

        loop = asyncio.get_event_loop()
        skill_data = await loop.run_in_executor(None, _do_static_scan)
        _latency["static"] = time.time() - _t_static_start
    except Exception as e:
        yield _sse_event(1, "finding", f"Static analysis error: {e}")
        yield _sse_event(0, "done", f"Pipeline failed: {e}")
        return

    skill_name = skill_data["skill_name"]
    skill_desc = skill_data.get("skill_description", "")
    # Parse description from SKILL.md if not available from scanner
    if not skill_desc:
        try:
            _skill_md = Path(skill_data["skill_path"]) / "SKILL.md"
            if _skill_md.exists():
                _md_text = _skill_md.read_text(errors="replace")
                if _md_text.startswith("---"):
                    _fm_end = _md_text.index("---", 3)
                    _fm = _md_text[3:_fm_end]
                    _dm = re.search(r"description:\s*(.+)", _fm, re.MULTILINE)
                    if _dm:
                        skill_desc = _dm.group(1).strip().strip('"').strip("'")
        except Exception:
            pass
    findings_count = skill_data["findings_count"]
    max_sev = skill_data["max_severity"]

    yield _sse_event(1, "step", f"YARA rule scan... {sum(1 for f in skill_data['findings'] if 'yara' in f.get('rule_id','').lower())} matches")
    await asyncio.sleep(0.2)
    yield _sse_event(1, "step", _t(f"正则模式扫描... 发现 {sum(1 for f in skill_data['findings'] if 'yara' not in f.get('rule_id','').lower())} 项", f"Regex pattern scan... {sum(1 for f in skill_data['findings'] if 'yara' not in f.get('rule_id','').lower())} findings", lang))
    await asyncio.sleep(0.2)

    if findings_count > 0:
        for f in skill_data["findings"][:5]:
            sev = f.get("severity", "INFO")
            title = f.get("title", "unknown")
            yield _sse_event(1, "finding" if sev in ("HIGH", "CRITICAL") else "step",
                           f"[{sev}] {f.get('rule_id','')}: {title}")
            await asyncio.sleep(0.15)

    yield _sse_event(1, "result", f"Static result: {max_sev} ({findings_count} findings)")
    await asyncio.sleep(0.3)

    # Step 1b: LLM safety scoring
    safety_confidence = None
    safety_verdict = "SAFE"
    llm_reason = ""
    llm_reason_en = ""

    if use_llm:
        llm_model = settings.llm_model
        yield _sse_event(1, "step", _t(f"LLM 安全评估 ({llm_model})...", f"LLM safety scoring ({llm_model})...", lang))
        await asyncio.sleep(0.2)

        _t_llm_start = time.time()
        try:
            from guardian import _read_skill_files, _format_static_findings, _LLM_TRIAGE_SYSTEM, _LLM_TRIAGE_USER
            import litellm

            skill_content, code_files = _read_skill_files(skill_data["skill_path"])
            static_summary = _format_static_findings(skill_data["findings"])
            user_prompt = _LLM_TRIAGE_USER.format(
                skill_content=skill_content,
                code_files=code_files,
                static_findings=static_summary,
            )

            # Build litellm kwargs from settings
            extra = {}
            if settings.llm_api_key:
                extra["api_key"] = settings.llm_api_key
            if settings.llm_base_url:
                extra["api_base"] = settings.llm_base_url
            if llm_model.startswith("azure/") and settings.llm_api_version:
                extra["api_version"] = settings.llm_api_version

            response = await litellm.acompletion(
                model=llm_model,
                messages=[
                    {"role": "system", "content": _LLM_TRIAGE_SYSTEM},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=500,
                **extra,
            )
            raw = response.choices[0].message.content.strip()
            if raw.startswith("```"):
                raw = re.sub(r'^```(?:json)?\s*', '', raw)
                raw = re.sub(r'\s*```$', '', raw)
            result = json.loads(raw)
            score = max(0.0, min(1.0, float(result.get("safety_confidence", 0.0))))
            triage = {"safety_confidence": score, "reason": result.get("reason", ""), "reason_en": result.get("reason_en", "")}
            safety_confidence = triage["safety_confidence"]
            llm_reason = triage["reason"]
            llm_reason_en = triage["reason_en"]
            # If lang=en and LLM returned Chinese reason, store it and ask for translation next time
            if lang == "en" and not llm_reason_en and llm_reason:
                llm_reason_en = llm_reason  # Fallback: same text for both

            if llm_reason.startswith("error:") or llm_reason.startswith("JSON parse error"):
                yield _sse_event(1, "alert", f"LLM API error: {llm_reason}, falling back to static result")
                safety_verdict = "UNSAFE" if max_sev in ("HIGH", "CRITICAL") else "SAFE"
                safety_confidence = None
            else:
                safety_verdict = "SAFE" if safety_confidence >= settings.safety_threshold else "UNSAFE"
                _latency["llm"] = time.time() - _t_llm_start
                yield _sse_event(1, "result",
                    _t(f"LLM 置信度: {safety_confidence:.2f} → {safety_verdict} ({_latency['llm']:.1f}s)" +
                    (f"，进入沙箱" if safety_verdict == "SAFE" and use_runtime else ""),
                    f"LLM confidence: {safety_confidence:.2f} → {safety_verdict} ({_latency['llm']:.1f}s)" +
                    (f", entering sandbox" if safety_verdict == "SAFE" and use_runtime else ""), lang),
                    {"safety_confidence": safety_confidence, "verdict": safety_verdict, "reason": llm_reason})
        except Exception as e:
            _latency["llm"] = time.time() - _t_llm_start
            yield _sse_event(1, "alert", f"LLM scoring failed: {e}, using static result only")
            safety_verdict = "UNSAFE" if max_sev in ("HIGH", "CRITICAL") else "SAFE"
    else:
        safety_verdict = "UNSAFE" if max_sev in ("HIGH", "CRITICAL") else "SAFE"
        yield _sse_event(1, "result",
            f"Static verdict: {safety_verdict} (LLM disabled)" +
            (", entering sandbox" if safety_verdict == "SAFE" and use_runtime else ""))

    if safety_confidence is None and safety_verdict == "SAFE":
        yield _sse_event(1, "result",
            f"Static verdict: SAFE (0 findings)" +
            (", entering sandbox" if use_runtime else ""))

    await asyncio.sleep(0.5)

    prescan_data = {
        "skill_name": skill_name,
        "skill_path": skill_path,
        "findings_count": findings_count,
        "max_severity": max_sev,
        "safety_confidence": safety_confidence,
        "safety_verdict": safety_verdict,
        "llm_reason": llm_reason,
        "llm_reason_en": llm_reason_en,
    }

    if safety_verdict == "UNSAFE":
        _latency["total"] = time.time() - _pipeline_start
        yield _sse_event(1, "result", _t("Skill 判定为不安全 — 跳过沙箱测试", "Skill judged UNSAFE — skipping sandbox test", lang))
        report = _build_report(prescan_data, {}, False, False, latency=_latency, lang=lang, skill_hash=_skill_hash, save=False)
        report["recommendations"] = [
            "DO NOT USE this skill — static analysis and/or LLM flagged it as UNSAFE.",
            "Review the findings above before considering any use.",
        ]
        _hash_for_save = report.pop("skill_hash", "")
        yield _sse_event(0, "report", _t("扫描报告", "Scan Report", lang), {"report": report})
        await asyncio.sleep(0.2)
        yield _sse_event(0, "done", _t("流水线完成", "Pipeline complete", lang),
                        {"prescan": prescan_data, "runtime": None, "verify": None})
        # Only reached if client kept SSE connection open through final yield.
        from scan_db import save_scan
        save_scan(report, skill_hash=_hash_for_save)
        return

    # Clearly safe (confidence above sandbox_threshold) — skip sandbox
    if safety_confidence is not None and safety_confidence >= settings.sandbox_threshold and use_runtime:
        _latency["total"] = time.time() - _pipeline_start
        yield _sse_event(1, "result",
            f"LLM confidence {safety_confidence:.2f} >= {settings.sandbox_threshold} — clearly safe, skipping sandbox")
        report = _build_report(prescan_data, {}, True, True, latency=_latency, lang=lang, skill_hash=_skill_hash, save=False)
        report["recommendations"] = [
            _t("该 Skill 通过静态分析和 LLM 高置信度评估，判定为安全，无需沙箱验证。",
               "This skill passed static analysis and high-confidence LLM evaluation — deemed safe, no sandbox verification needed.", lang),
            _t("建议在生产环境中保持 FangcunGuard 监控开启，提供持续运行时保护。",
               "Recommendation: Keep FangcunGuard monitoring enabled in production for continuous runtime protection.", lang),
        ]
        _hash_for_save = report.pop("skill_hash", "")
        yield _sse_event(0, "report", _t("扫描报告", "Scan Report", lang), {"report": report})
        await asyncio.sleep(0.2)
        yield _sse_event(0, "done", _t("流水线完成", "Pipeline complete", lang),
                        {"prescan": prescan_data, "runtime": None, "verify": None})
        from scan_db import save_scan
        save_scan(report, skill_hash=_hash_for_save)
        return

    # ══════════════════════════════════════════════════════════════
    # Stage 2: Docker Sandbox Runtime Detection
    # ══════════════════════════════════════════════════════════════
    if not use_runtime:
        _latency["total"] = time.time() - _pipeline_start
        scanner_safe = safety_verdict == "SAFE"
        report = _build_report(prescan_data, {}, scanner_safe, True, latency=_latency, lang=lang, skill_hash=_skill_hash, save=False)
        _hash_for_save = report.pop("skill_hash", "")
        yield _sse_event(0, "report", _t("扫描报告", "Scan Report", lang), {"report": report})
        await asyncio.sleep(0.2)
        yield _sse_event(0, "done", "Pipeline complete (runtime disabled)",
                        {"prescan": prescan_data, "runtime": None, "verify": None})
        from scan_db import save_scan
        save_scan(report, skill_hash=_hash_for_save)
        return

    yield _sse_event(2, "stage", _t("Stage C: Docker 沙箱运行时检测", "Stage C: Docker Sandbox Runtime Detection", lang))
    await asyncio.sleep(0.3)

    docker_image = settings.docker_image
    docker_model = settings.docker_model
    azure_url = settings.docker_api_url
    azure_key = settings.docker_api_key
    timeout_sec = settings.phase2_timeout
    prep_timeout = settings.phase1_timeout
    max_retries = settings.max_retries

    # Extract provider, model_id, and profile from model string: "provider/model@profile"
    _model_provider = docker_model.split("/")[0] if "/" in docker_model else "openai-responses"
    _model_profile = docker_model.split("@")[1] if "@" in docker_model else "default"
    _model_id = docker_model.split("/", 1)[1].split("@")[0] if "/" in docker_model else docker_model.split("@")[0]
    # Determine API type: "responses" for openai-responses/azure-openai-responses, else "chat"
    _api_type = "openai-responses" if "responses" in _model_provider else "openai"
    retry_delay = settings.retry_delay
    guard_plugin_api_url = settings.guard_plugin_api_url
    guard_plugin_api_key = settings.guard_plugin_api_key

    yield _sse_event(2, "step", _t("正在准备沙箱环境...", "Preparing sandbox environment...", lang))
    await asyncio.sleep(0.2)

    import queue as _queue
    import functools as _functools

    runtime_result = {"status": "ERROR", "details": []}
    try:
        from guardian import run_two_phase_test

        skill_folder = Path(skill_path).name
        skills_parent = str(Path(skill_path).parent)
        output_dir = os.path.join(str(SCRIPT_DIR), "output")
        os.makedirs(output_dir, exist_ok=True)

        _msg_queue: _queue.Queue = _queue.Queue()

        def _on_progress(kind, msg):
            _msg_queue.put((kind, msg))

        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(
            None,
            _functools.partial(
                run_two_phase_test,
                skill_folder=skill_folder,
                skills_dir=skills_parent,
                output_dir=output_dir,
                image=docker_image,
                timeout=timeout_sec,
                prep_timeout=prep_timeout,
                azure_url=azure_url,
                azure_key=azure_key,
                model=docker_model,
                max_retries=max_retries,
                retry_delay=retry_delay,
                enable_after_tool=enable_after_tool,
                on_progress=_on_progress,
            ),
        )

        # Stream progress SSE events while the blocking sandbox runs in executor
        while not future.done():
            try:
                kind, msg = _msg_queue.get(timeout=0.3)
                yield _sse_event(2, kind, msg)
            except _queue.Empty:
                pass
            await asyncio.sleep(0.05)

        # Drain any remaining queued events
        while not _msg_queue.empty():
            try:
                kind, msg = _msg_queue.get_nowait()
                yield _sse_event(2, kind, msg)
            except _queue.Empty:
                break

        result = await future
        runtime_status = result.get("status", "ERROR")
        runtime_result = {
            "skill": result.get("skill", skill_folder),
            "status": runtime_status,
            "elapsed_sec": result.get("elapsed_sec", 0),
            "blacklist_hits": result.get("blacklist_hits", 0),
            "blocks": result.get("blocks", 0),
            "content_risks": result.get("content_risks", 0),
            "agent_crashed": result.get("agent_crashed", False),
            "early_stopped": result.get("early_stopped", False),
            "low_risk_alert": result.get("low_risk_alert", False),
            "details": result.get("details", []),
            "output_file": result.get("output_file"),
            "phase1_file": result.get("phase1_file"),
        }

        _details = result.get("details", []) or []
        _verdict_suffix = f" — {'; '.join(_details[:2])}" if _details else ""
        yield _sse_event(2, "result",
            f"{_t('运行时结论', 'Runtime Verdict', lang)}: {runtime_status}{_verdict_suffix}",
            {"status": runtime_status, "details": _details})

    except Exception as e:
        import traceback; traceback.print_exc()
        yield _sse_event(2, "finding", f"Runtime error: {e}")
        yield _sse_event(2, "result", f"{_t('运行时结论', 'Runtime Verdict', lang)}: ERROR — {e}")
        runtime_result = {"status": "ERROR", "details": [str(e)]}

    await asyncio.sleep(0.5)

    # ══════════════════════════════════════════════════════════════
    # Stage 3: Post-hoc Capability Analysis / False Negative Check
    # ══════════════════════════════════════════════════════════════
    _latency["runtime"] = runtime_result.get("elapsed_sec", 0)

    if not enable_after_tool:
        _latency["total"] = time.time() - _pipeline_start
        scanner_safe = safety_verdict == "SAFE"
        runtime_safe = runtime_result.get("status") in ("PASSED", "Safe")
        report = _build_report(prescan_data, runtime_result, scanner_safe, runtime_safe, latency=_latency, lang=lang, skill_hash=_skill_hash, save=False)
        _hash_for_save = report.pop("skill_hash", "")
        yield _sse_event(0, "report", _t("扫描报告", "Scan Report", lang), {"report": report})
        await asyncio.sleep(0.2)
        yield _sse_event(0, "done", _t("流水线完成", "Pipeline complete", lang),
                        {"prescan": prescan_data, "runtime": runtime_result})
        from scan_db import save_scan
        save_scan(report, skill_hash=_hash_for_save)
        return

    # Stage C verification merged into runtime conclusion
    await asyncio.sleep(0.3)
    yield _sse_event(3, "step", _t("正在分析工具调用链的能力滥用情况...", "Analyzing tool call chain for capability abuse...", lang))
    await asyncio.sleep(0.2)

    scanner_safe = safety_verdict == "SAFE"
    runtime_safe = runtime_result.get("status") in ("PASSED", "Safe")

    if scanner_safe and not runtime_safe:
        yield _sse_event(3, "finding",
            f"漏报警告: Stage A+B 判定为安全，但运行时检测到 {runtime_result.get('status')}")
        await asyncio.sleep(0.2)
        final_verdict = runtime_result.get("status", "DANGER")
        yield _sse_event(3, "result",
            f"最终结论: {final_verdict} — 运行时检测发现了静态分析遗漏的威胁",
            {"verdict": final_verdict, "false_negative": True})
    elif not runtime_safe:
        yield _sse_event(3, "result",
            f"最终结论: {runtime_result.get('status')} — Stage A+B + C 均确认",
            {"verdict": runtime_result.get("status"), "false_negative": False})
    else:
        yield _sse_event(3, "result", _t("最终结论: SAFE — 通过所有 Stage 检查", "Final verdict: SAFE — passed all stages", lang),
                        {"verdict": "SAFE", "false_negative": False})

    await asyncio.sleep(0.3)

    _latency["total"] = time.time() - _pipeline_start
    report = _build_report(prescan_data, runtime_result, scanner_safe, runtime_safe, latency=_latency, lang=lang, skill_hash=_skill_hash, save=False)
    _hash_for_save = report.pop("skill_hash", "")
    yield _sse_event(0, "report", _t("扫描报告", "Scan Report", lang), {"report": report})
    await asyncio.sleep(0.2)

    yield _sse_event(0, "done", _t("流水线完成", "Pipeline complete", lang), {
        "prescan": prescan_data,
        "runtime": {
            "status": runtime_result.get("status"),
            "details": runtime_result.get("details", []),
        },
    })
    # Only reached if client kept SSE connection open through final yield.
    from scan_db import save_scan
    save_scan(report, skill_hash=_hash_for_save)


# ══════════════════════════════════════════════════════════════
# API Endpoints
# ══════════════════════════════════════════════════════════════

@app.get("/api/scan/history")
async def scan_history(
    limit: int = 50, offset: int = 0,
    verdict: str = None, skill_name: str = None,
    false_negative_only: bool = False,
):
    from scan_db import get_history
    return get_history(limit=limit, offset=offset, verdict=verdict,
                       skill_name=skill_name, false_negative_only=false_negative_only)


# ══════════════════════════════════════════════════════════════
# On-demand LLM remediation: reviews Docker runtime evidence and
# proposes concrete SKILL.md edits. Only applicable to Medium Risk
# (design-flaw) scans. Never runs automatically during scanning.
# ══════════════════════════════════════════════════════════════

_REMEDIATION_SYSTEM_PROMPT = """You are a security engineer reviewing a skill — a SKILL.md instruction file
that was executed in a sandboxed Docker container. Your task is to write
concrete security patch suggestions the author can apply to SKILL.md,
preserving their original purpose while closing security gaps.

You receive three inputs as evidence:
  1. SKILL.md — the author's source, mixing natural-language steps with
     backticked literal commands.
  2. Runtime warnings — security signals intercepted by the sandbox
     during execution.
  3. Docker runtime log — stdout including the tool_call lines showing
     the exact commands that ran.

Output language requirement (IMPORTANT):
  • finding_title, description, and explanation MUST each be a JSON object
    with both "zh" (Simplified Chinese) and "en" (English) keys. Both
    languages must come from the SAME analysis pass so they describe the
    SAME finding consistently — they are translations of each other, not
    independent judgments.
  • severity is an enum string. code_before and code_after are verbatim
    quotes / code patches and stay language-neutral.

Style rules for finding_title (BOTH zh AND en):
  • MUST start with a verb phrase that names the FIX action, not the problem.
    Read like a PR title or commit subject: "do X to Y".
    Good (zh): "对远程安装脚本增加完整性校验"
    Good (en): "Verify remote install script integrity before executing"
    Bad (don't do this): "禁止将 curl 输出通过管道交给解释器" (negative-prefixed,
    jargon-heavy, doesn't say what to actually do).
    Bad (don't do this): "Avoid piping curl to bash" (still negative-framed).
  • Professional tone, but plain wording — avoid raw jargon like "管道",
    "解释器", "fork-exec"; prefer "用 curl 直接执行远程脚本", "shell".
  • Concrete, specific to the evidence — don't write generic "Improve security".
  • Keep ≤ 60 Chinese chars / ≤ 90 English chars.

Few-shot title examples (use this exact style and tone):
  Issue (curl | bash) → "对远程安装脚本增加完整性校验" / "Verify remote install script integrity before executing"
  Issue (open external URLs unrestricted) → "为外部网络请求增加域名白名单" / "Restrict outbound requests to an allowlisted domain set"
  Issue (real-looking BT token in example) → "示例改用占位符令牌而非样本数据" / "Replace sample payment tokens with placeholders in examples"
  Issue (polling without bound) → "为轮询步骤增加最大次数和总超时" / "Add a max attempt count and total timeout to the polling loop"
  Issue (writes secrets to /tmp) → "将敏感字段保留在内存中处理" / "Keep sensitive fields in memory rather than writing them to disk"

Rules for code_before / code_after:
  • code_before MUST be quoted verbatim from the evidence. Prefer a line
    from SKILL.md; fall back to a tool_call line from the log only if
    the risky pattern appears only there. Never invent code.
  • code_after is the minimal change that fixes the issue while preserving
    what the author was trying to do. Prose-level edits are allowed (e.g.
    "Add a step: exclude .env files from the archive"). If no safe
    replacement exists and the step should simply be removed, leave
    code_after empty.

Severity calibration (don't inflate):
  CRITICAL — remote code execution, credential exfiltration, destructive ops
  HIGH     — reading or transmitting secrets, unnecessary root access
  MEDIUM   — over-permissive permissions, missing input validation
  LOW      — fragile or inefficient but not directly dangerous
  INFO     — style / hygiene

description and explanation: also write zh + en. Each language ≤ 3 sentences.
description states what went wrong; explanation says why this fix preserves
the author's intent.

Do not fabricate issues if the evidence is clean — an empty array is a
valid answer.

Return strict JSON only — no prose outside the JSON object."""


_REMEDIATION_MAX_LOG_BYTES = 40000
_GUARD_EVENT_RE = re.compile(
    r"\[FangcunGuard\]|Blacklist hit|Risk Level|risk detected|\"blocked\":\s*true"
)


def _load_scan_record(scan_id: str) -> dict | None:
    """Fetch a scan record by id and deserialize its JSON blobs."""
    from scan_db import _get_conn
    row = _get_conn().execute(
        "SELECT * FROM scan_results WHERE id = ?", (scan_id,)
    ).fetchone()
    if not row:
        return None
    rec = dict(row)
    for field in ("stages", "capabilities", "warnings",
                  "recommendations", "recommendations_en"):
        try:
            rec[field] = json.loads(rec[field]) if rec.get(field) else ({} if field == "stages" else [])
        except (json.JSONDecodeError, TypeError):
            rec[field] = {} if field == "stages" else []
    rec["false_negative"] = bool(rec.get("false_negative"))
    return rec


def _compress_phase2_log(text: str) -> tuple[str, bool, int]:
    """If text is <= MAX_LOG_BYTES, return as-is. Otherwise keep a window of
    ±5 lines around every Guard-event hit, merged, plus a short head and
    tail. Returns (compressed_text, was_compressed, original_length_kb).
    """
    original_len = len(text)
    if original_len <= _REMEDIATION_MAX_LOG_BYTES:
        return text, False, original_len // 1024

    lines = text.split("\n")
    hit_indices = [i for i, line in enumerate(lines) if _GUARD_EVENT_RE.search(line)]

    if not hit_indices:
        compressed = text[-_REMEDIATION_MAX_LOG_BYTES:]
        return compressed, True, original_len // 1024

    windows: list[tuple[int, int]] = []
    for idx in hit_indices:
        lo = max(0, idx - 5)
        hi = min(len(lines) - 1, idx + 5)
        if windows and lo <= windows[-1][1] + 1:
            windows[-1] = (windows[-1][0], max(windows[-1][1], hi))
        else:
            windows.append((lo, hi))

    parts: list[str] = []
    parts.append(text[:500])
    parts.append("\n... [window-compressed] ...\n")
    prev_end = -1
    for lo, hi in windows:
        if prev_end >= 0 and lo > prev_end + 1:
            parts.append("\n... [skip] ...\n")
        parts.append("\n".join(lines[lo:hi + 1]))
        prev_end = hi
    parts.append("\n... [tail] ...\n")
    parts.append(text[-2000:])
    compressed = "\n".join(parts)
    if len(compressed) > _REMEDIATION_MAX_LOG_BYTES:
        compressed = compressed[-_REMEDIATION_MAX_LOG_BYTES:]
    return compressed, True, original_len // 1024


def _build_guard_events(warnings: list, lang: str) -> list[str]:
    """Filter warnings down to critical/warning levels and format as bullet lines."""
    events: list[str] = []
    for w in warnings or []:
        if not isinstance(w, dict):
            continue
        level = w.get("level", "")
        if level not in ("critical", "warning"):
            continue
        if lang == "zh":
            source = w.get("source") or w.get("source_en") or ""
            text = w.get("text") or w.get("text_en") or ""
        else:
            source = w.get("source_en") or w.get("source") or ""
            text = w.get("text_en") or w.get("text") or ""
        if not text:
            continue
        events.append(f"- [{level}][{source}] {text}")
    return events


@app.post("/api/scan/{scan_id}/remediate")
async def generate_remediation(scan_id: str, lang: str = "en"):
    """On-demand LLM fix suggestions for a Medium Risk scan.

    Reads the saved Docker phase2 log plus Guard events already captured
    during the scan, sends them to the configured LLM, returns structured
    RemediationSuggestion[]. Not called automatically by the pipeline.
    """
    record = _load_scan_record(scan_id)
    if not record:
        return {"error": "scan_not_found", "remediations": []}, 404

    verdict = record.get("verdict", "")
    false_negative = record.get("false_negative", False)

    if false_negative:
        return {
            "error": "not_applicable",
            "reason": "high-risk or likely malicious — do not reuse",
            "remediations": [],
        }, 400
    if verdict != "Medium Risk":
        if verdict in ("Safe", "PASSED", "SAFE"):
            reason = "skill is safe, no fixes needed"
        elif verdict in ("High Risk", "DANGER", "BLOCKED", "CONTENT_RISK"):
            reason = "high-risk or likely malicious — do not reuse"
        elif verdict in ("TIMEOUT", "ERROR", "INCOMPLETE", "SANDBOX_FAILED", "INCONCLUSIVE"):
            reason = "runtime did not complete — no evidence to analyze"
        else:
            reason = f"verdict '{verdict}' is not eligible for remediation"
        return {"error": "not_applicable", "reason": reason, "remediations": []}, 400

    # Cache: if remediations were already generated for this scan, return them
    # without burning another LLM call. Stored as JSON string in scan_results.remediation_json.
    cached_raw = (record.get("remediation_json") or "").strip()
    if cached_raw:
        try:
            return {
                "scan_id": scan_id,
                "remediations": json.loads(cached_raw),
                "lang": lang,
                "cached": True,
            }
        except json.JSONDecodeError:
            pass  # cached value corrupted — fall through to regenerate

    skill_name = record.get("skill_name", "unknown")
    stages = record.get("stages") or {}
    runtime_stage = stages.get("runtime") or {}
    static_stage = stages.get("static") or {}
    warnings = record.get("warnings") or []

    # Locate the phase2 sandbox log. Prefer skill_folder (original extracted folder name,
    # populated by _build_report). Fall back to skill_name (older records). If still
    # missing, glob for skill_*<skill_name>.txt to handle pre-skill_folder records.
    folder = record.get("skill_folder") or skill_name
    phase2_path = SCRIPT_DIR / "output" / f"skill_{folder}.txt"
    if not phase2_path.exists() and skill_name:
        cands = sorted((SCRIPT_DIR / "output").glob(f"skill_*{skill_name}.txt"))
        # Prefer files whose name ends with the skill_name (avoids matching unrelated suffix overlaps)
        cands = [p for p in cands if p.name.endswith(f"{skill_name}.txt") and "_phase1" not in p.name]
        if cands:
            phase2_path = cands[0]
    if not phase2_path.exists():
        return {
            "error": "no_runtime_evidence",
            "message": "Docker sandbox log not found for this scan.",
            "remediations": [],
        }
    try:
        phase2_full = phase2_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {
            "error": "log_read_failed",
            "message": f"Could not read sandbox log: {e}",
            "remediations": [],
        }, 500

    phase2_log, was_compressed, original_kb = _compress_phase2_log(phase2_full)
    guard_events = _build_guard_events(warnings, lang)
    skill_md_text = static_stage.get("skill_md") or ""
    if not skill_md_text:
        skill_md_text = "(skill source unavailable for this older record)"

    log_hint = (
        f"(Log compressed around guard events; original length was {original_kb} KB)\n"
        if was_compressed
        else ""
    )
    events_block = "\n".join(guard_events) if guard_events else "(none)"

    user_prompt = (
        f"SKILL NAME: {skill_name}\n"
        f"OVERALL VERDICT: {verdict}\n"
        f"RUNTIME STATUS: {runtime_stage.get('status', 'N/A')}  "
        f"(blacklist_hits={runtime_stage.get('blacklist_hits', 0)}, "
        f"blocks={runtime_stage.get('blocks', 0)})\n\n"
        f"{'-' * 10} SKILL.md {'-' * 10}\n"
        f"{skill_md_text}\n"
        f"{'-' * 30}\n\n"
        f"{'-' * 10} RUNTIME WARNINGS {'-' * 10}\n"
        f"{events_block}\n"
        f"{'-' * 38}\n\n"
        f"{'-' * 10} DOCKER RUNTIME LOG {'-' * 10}\n"
        f"{log_hint}{phase2_log}\n"
        f"{'-' * 40}\n\n"
        "Produce up to 5 security patch suggestions, prioritized by severity.\n"
        "Each suggestion must be bilingual: provide BOTH zh (Simplified Chinese)\n"
        "AND en (English) for finding_title, description, and explanation.\n\n"
        "Respond as:\n"
        "{\n"
        '  "remediations": [\n'
        "    {\n"
        '      "finding_title": {"zh": "动词短语开头点出修复动作", "en": "Verb-phrase fix action title"},\n'
        '      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
        '      "description": {"zh": "中文描述（1-2 句）", "en": "English description (1-2 sentences)"},\n'
        '      "code_before": "verbatim quote from evidence",\n'
        '      "code_after": "corrected version or SKILL.md prose edit, or empty",\n'
        '      "explanation": {"zh": "中文解释（1-3 句）", "en": "English explanation (1-3 sentences)"}\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "Empty array if no actionable issue."
    )

    settings = get_settings()
    try:
        import litellm
        extra = {}
        if settings.llm_api_key:
            extra["api_key"] = settings.llm_api_key
        if settings.llm_base_url:
            extra["api_base"] = settings.llm_base_url
        if settings.llm_model.startswith("azure/") and settings.llm_api_version:
            extra["api_version"] = settings.llm_api_version

        response = await litellm.acompletion(
            model=settings.llm_model,
            messages=[
                {"role": "system", "content": _REMEDIATION_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
            max_tokens=2000,
            **extra,
        )
        raw = response.choices[0].message.content or "{}"
    except Exception as e:
        return {"error": "llm_failed", "message": str(e), "remediations": []}, 500

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group(0))
            except json.JSONDecodeError:
                parsed = {"remediations": []}
        else:
            parsed = {"remediations": []}

    items = parsed.get("remediations") if isinstance(parsed, dict) else parsed
    if not isinstance(items, list):
        items = []

    def _bilingual(v, default_zh: str = "", default_en: str = "") -> dict:
        """Coerce LLM output to {"zh": ..., "en": ...}.

        Accepts both new shape (dict with zh/en) and legacy single string;
        if one language is missing/empty, fall back to the other so the UI
        never renders blank.
        """
        if isinstance(v, dict):
            zh = str(v.get("zh") or "").strip()
            en = str(v.get("en") or "").strip()
        elif isinstance(v, str):
            zh = v.strip()
            en = v.strip()
        else:
            zh = ""
            en = ""
        if not zh:
            zh = en or default_zh
        if not en:
            en = zh or default_en
        return {"zh": zh, "en": en}

    allowed_severity = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"}
    remediations: list[dict] = []
    for item in items[:5]:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity", "MEDIUM")).upper().strip()
        if sev not in allowed_severity:
            sev = "MEDIUM"
        title = _bilingual(item.get("finding_title"), default_zh="安全补丁建议", default_en="Security patch")
        # Cap each language individually to avoid one bloated lang dragging the card height
        for k in ("zh", "en"):
            if len(title[k]) > 120:
                title[k] = title[k][:120]
        remediations.append({
            "skill_name": skill_name,
            "finding_title": title,
            "severity": sev,
            "description": _bilingual(item.get("description")),
            "code_before": str(item.get("code_before", "")),
            "code_after": str(item.get("code_after", "")),
            "explanation": _bilingual(item.get("explanation")),
        })

    # Persist so subsequent visits return immediately from cache.
    # Skip caching empty arrays — those usually indicate LLM flakiness (malformed
    # JSON / truncated response), and caching them would break the retry button.
    if remediations:
        try:
            from scan_db import update_remediation
            update_remediation(scan_id, remediations)
        except Exception:
            pass  # best-effort cache; never fail the request because of persistence

    return {"scan_id": scan_id, "remediations": remediations, "lang": lang}


@app.get("/api/scan/stats")
async def scan_stats():
    """Aggregate statistics across all scans."""
    from scan_db import get_stats
    return get_stats()


@app.get("/api/scan/export")
async def scan_export(verdict: str = None):
    """Export scan results to CSV."""
    from scan_db import export_csv
    import tempfile
    tmp = tempfile.mktemp(suffix=".csv", prefix="guardian_export_")
    count = export_csv(tmp, verdict=verdict)
    from fastapi.responses import FileResponse
    return FileResponse(tmp, media_type="text/csv",
                        filename=f"scan_results_{count}.csv")


@app.post("/api/scan/migrate")
async def scan_migrate():
    """One-time migration from old scan_history.json to SQLite."""
    from scan_db import migrate_from_json
    json_path = str(SCRIPT_DIR / "scan_history.json")
    count = migrate_from_json(json_path)
    return {"migrated": count, "source": json_path}


@app.get("/api/batch")
async def list_batches():
    """List all batch scans."""
    from scan_db import list_batches
    return list_batches()


@app.get("/api/batch/{batch_id}")
async def get_batch(batch_id: str):
    """Get batch summary + skill results."""
    from scan_db import get_batch as _get_batch, get_batch_skills
    batch = _get_batch(batch_id)
    if not batch:
        return {"error": "Batch not found"}, 404
    skills = get_batch_skills(batch_id, limit=2000)
    return {**batch, "skills": skills["records"]}



@app.post("/api/batch/upload")
async def batch_upload(file: UploadFile = File(...)):
    """Upload a zip containing multiple skill folders. Returns extracted path and discovered skills."""
    tmp_dir = tempfile.mkdtemp(prefix="guardian_batch_")
    file_path = os.path.join(tmp_dir, file.filename or "upload.zip")

    with open(file_path, "wb") as f:
        content_bytes = await file.read()
        f.write(content_bytes)

    extract_dir = os.path.join(tmp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    if file_path.endswith(".zip"):
        with zipfile.ZipFile(file_path, "r") as zf:
            zf.extractall(extract_dir)
    elif file_path.endswith((".tar.gz", ".tgz")):
        import tarfile
        with tarfile.open(file_path, "r:gz") as tf:
            tf.extractall(extract_dir)

    # Discover skills
    skill_dirs = []
    for root, dirs, files in os.walk(extract_dir):
        if "SKILL.md" in files:
            p = Path(root)
            is_nested = any(pp in skill_dirs for pp in p.parents)
            if not is_nested:
                skill_dirs.append(p)

    return {
        "skills_dir": extract_dir,
        "skill_count": len(skill_dirs),
        "skills": [{"name": p.name, "path": str(p)} for p in sorted(skill_dirs)],
    }

@app.get("/api/batch/{batch_id}/stream")
async def batch_scan_stream(
    batch_id: str = None,
    skills_dir: str = Query(..., description="Path to directory containing skill folders"),
    concurrency: int = Query(4, description="Number of parallel scans"),
    use_llm: bool = Query(True),
    use_runtime: bool = Query(True),
    enable_after_tool: bool = Query(True),
    lang: str = Query("en"),
):
    """Batch scan: discover all skills in a directory, scan in parallel, stream progress."""

    async def _batch_generator():
        import hashlib as _hl
        from scan_db import create_batch, update_batch_progress, finish_batch, save_scan

        # Discover skills
        skills_path = Path(skills_dir)
        if not skills_path.is_dir():
            yield _sse_event(0, "error", f"Directory not found: {skills_dir}")
            return

        skill_dirs = []
        for root, dirs, files in os.walk(str(skills_path)):
            if "SKILL.md" in files:
                p = Path(root)
                # Skip if any parent already has SKILL.md (avoid scanning extracted/unpacked subdirs)
                is_nested = any(pp in skill_dirs for pp in p.parents)
                if not is_nested:
                    skill_dirs.append(p)
        skill_dirs.sort()

        if not skill_dirs:
            yield _sse_event(0, "error", f"No skills found (no SKILL.md) in {skills_dir}")
            return

        # Create batch record
        bid = batch_id or _hl.md5(f"{skills_dir}{time.time()}".encode()).hexdigest()[:12]
        batch_name = skills_path.name
        create_batch(bid, batch_name, str(skills_dir), len(skill_dirs))

        yield _sse_event(0, "batch_start", _t(f"批量扫描: 发现 {len(skill_dirs)} 个 Skill", f"Batch scan: found {len(skill_dirs)} Skills", lang), {
            "batch_id": bid,
            "total": len(skill_dirs),
            "concurrency": concurrency,
        })

        # Queue-based approach: workers push results, generator yields them
        result_queue: asyncio.Queue = asyncio.Queue()
        sem = asyncio.Semaphore(concurrency)
        batch_start_time = time.time()
        completed = {"count": 0}

        async def _scan_one(skill_path: Path):
            async with sem:
                skill_name = skill_path.name
                t0 = time.time()
                try:
                    report = await _run_single_scan(
                        str(skill_path), use_llm=use_llm, use_runtime=use_runtime,
                        enable_after_tool=enable_after_tool, batch_id=bid, lang=lang)
                    update_batch_progress(bid, report)
                    completed["count"] += 1
                    # Use the report's skill_name (from scanner) so it matches the DB record
                    reported_name = report.get("skill_name", skill_name)
                    await result_queue.put({
                        "skill_name": reported_name,
                        "verdict": report.get("verdict", "UNKNOWN"),
                        "false_negative": report.get("false_negative", False),
                        "latency": round(time.time() - t0, 1),
                        "findings": report.get("stages", {}).get("static", {}).get("findings", 0),
                        "progress": completed["count"],
                    })
                except Exception as e:
                    completed["count"] += 1
                    err_report = {
                        "verdict": "ERROR",
                        "skill_name": skill_name,
                        "false_negative": False,
                        "scan_time": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                        "source": _t("批量扫描", "Batch Scan", lang),
                        "batch_id": bid,
                        "latency": {"total": round(time.time() - t0, 1), "static": 0, "llm": 0, "runtime": 0, "verify": 0},
                        "stages": {"static": {"verdict": "ERROR", "findings": 0, "severity": "N/A"},
                                   "llm": {"confidence": None, "reason": ""},
                                   "runtime": {"status": "SKIPPED", "elapsed": 0, "blacklist_hits": 0, "blocks": 0}},
                        "warnings": [{"level": "critical", "source": _t("系统", "System", lang), "text": str(e)}],
                        "recommendations": [],
                    }
                    from scan_db import save_scan as _save
                    _save(err_report)
                    update_batch_progress(bid, err_report)
                    await result_queue.put({
                        "skill_name": skill_name,
                        "verdict": "ERROR",
                        "false_negative": False,
                        "latency": round(time.time() - t0, 1),
                        "findings": 0,
                        "progress": completed["count"],
                        "error": str(e),
                    })

        # Launch all workers in background
        async def _run_all():
            tasks = [asyncio.create_task(_scan_one(sd)) for sd in skill_dirs]
            await asyncio.gather(*tasks)
            await result_queue.put(None)  # sentinel

        asyncio.create_task(_run_all())

        # Yield results as they arrive
        while True:
            result = await result_queue.get()
            if result is None:
                break
            verdict_icon = {"PASSED": "SAFE", "Safe": "SAFE", "DANGER": "DANGER", "High Risk": "DANGER", "WARNING": "WARNING", "Medium Risk": "WARNING", "ERROR": "ERROR"}.get(result["verdict"], result["verdict"])
            yield _sse_event(0, "skill_done",
                f"[{result['progress']}/{len(skill_dirs)}] {result['skill_name']} → {verdict_icon} ({result['latency']}s)",
                result)

        # Finalize batch
        finish_batch(bid)
        total_elapsed = round(time.time() - batch_start_time, 1)

        from scan_db import get_batch as _gb
        summary = _gb(bid)

        yield _sse_event(0, "batch_done", _t(f"批量扫描完成: {len(skill_dirs)} 个 Skill, 耗时 {total_elapsed}s", f"Batch scan complete: {len(skill_dirs)} Skills in {total_elapsed}s", lang), {
            "batch_id": bid,
            **summary,
        })

    return StreamingResponse(
        _batch_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


async def _run_docker_sandbox(skill_path: str, settings, enable_after_tool: bool = True) -> dict:
    """Run Docker sandbox for a single skill (non-streaming). Delegates to guardian.run_two_phase_test."""
    import functools as _functools
    from guardian import run_two_phase_test

    skill_folder = Path(skill_path).name
    skills_parent = str(Path(skill_path).parent)
    output_dir = os.path.join(str(SCRIPT_DIR), "output")
    os.makedirs(output_dir, exist_ok=True)

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        _functools.partial(
            run_two_phase_test,
            skill_folder=skill_folder,
            skills_dir=skills_parent,
            output_dir=output_dir,
            image=settings.docker_image,
            timeout=settings.phase2_timeout,
            prep_timeout=settings.phase1_timeout,
            azure_url=settings.docker_api_url,
            azure_key=settings.docker_api_key,
            model=settings.docker_model,
            max_retries=settings.max_retries,
            retry_delay=settings.retry_delay,
            enable_after_tool=enable_after_tool,
        ),
    )
    return {
        "skill": result.get("skill", skill_folder),
        "status": result.get("status", "ERROR"),
        "elapsed_sec": result.get("elapsed_sec", 0),
        "blacklist_hits": result.get("blacklist_hits", 0),
        "blocks": result.get("blocks", 0),
        "content_risks": result.get("content_risks", 0),
        "agent_crashed": result.get("agent_crashed", False),
        "early_stopped": result.get("early_stopped", False),
        "low_risk_alert": result.get("low_risk_alert", False),
        "details": result.get("details", []),
    }


async def _run_single_scan(skill_path: str, use_llm: bool = True, use_runtime: bool = False,
                           enable_after_tool: bool = True, batch_id: str = None, lang: str = "en") -> dict:
    """Run a single skill scan (non-streaming) and return the report dict."""
    settings = get_settings()
    _pipeline_start = time.time()
    _latency = {"total": 0, "static": 0, "llm": 0, "runtime": 0, "verify": 0}

    # Static analysis (run in executor to avoid blocking event loop)
    _t0 = time.time()
    def _do_static():
        from skill_scanner.core.scanner import SkillScanner
        from skill_scanner.core.scan_policy import ScanPolicy
        from skill_scanner.core.analyzer_factory import build_core_analyzers

        p = ScanPolicy.default()
        analyzers = build_core_analyzers(p)
        scanner = SkillScanner(analyzers=analyzers, policy=p)
        result = scanner.scan_skill(Path(skill_path))
        findings_list = [f.to_dict() for f in result.findings]
        return {
            "skill_name": result.skill_name,
            "skill_path": result.skill_directory,
            "findings": findings_list,
            "findings_count": len(findings_list),
            "max_severity": result.max_severity.value,
            "is_safe": result.is_safe,
        }

    try:
        loop = asyncio.get_event_loop()
        skill_data = await loop.run_in_executor(None, _do_static)
    except Exception as e:
        # Static analysis failed — use fallback data so pipeline continues
        skill_data = {
            "skill_name": Path(skill_path).name,
            "skill_path": skill_path,
            "findings": [],
            "findings_count": 0,
            "max_severity": "SAFE",
            "is_safe": True,
            "static_error": str(e),
        }
    _latency["static"] = time.time() - _t0

    skill_name = skill_data["skill_name"]
    findings_count = skill_data["findings_count"]
    max_sev = skill_data["max_severity"]

    # LLM scoring
    safety_confidence = None
    safety_verdict = "SAFE"
    llm_reason = ""
    llm_reason_en = ""

    if use_llm:
        _t0 = time.time()
        try:
            from guardian import _read_skill_files, _format_static_findings, _LLM_TRIAGE_SYSTEM, _LLM_TRIAGE_USER
            import litellm

            skill_content, code_files = _read_skill_files(skill_data["skill_path"])
            static_summary = _format_static_findings(skill_data["findings"])
            user_prompt = _LLM_TRIAGE_USER.format(
                skill_content=skill_content,
                code_files=code_files,
                static_findings=static_summary,
            )
            extra = {}
            if settings.llm_api_key:
                extra["api_key"] = settings.llm_api_key
            if settings.llm_base_url:
                extra["api_base"] = settings.llm_base_url
            if settings.llm_model.startswith("azure/") and settings.llm_api_version:
                extra["api_version"] = settings.llm_api_version

            response = await litellm.acompletion(
                model=settings.llm_model,
                messages=[
                    {"role": "system", "content": _LLM_TRIAGE_SYSTEM},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=500,
                **extra,
            )
            raw = response.choices[0].message.content.strip()
            if raw.startswith("```"):
                raw = re.sub(r'^```(?:json)?\s*', '', raw)
                raw = re.sub(r'\s*```$', '', raw)
            parsed = json.loads(raw)
            safety_confidence = max(0.0, min(1.0, float(parsed.get("safety_confidence", 0.0))))
            llm_reason = parsed.get("reason", "")
            llm_reason_en = parsed.get("reason_en", "")
            safety_verdict = "SAFE" if safety_confidence >= settings.safety_threshold else "UNSAFE"
        except Exception as e:
            safety_verdict = "UNSAFE" if max_sev in ("HIGH", "CRITICAL") else "SAFE"
            llm_reason = f"LLM 评分失败: {e}"
            import logging
            logging.getLogger("guardian").warning("LLM scoring failed for %s: %s", skill_path, e)
        _latency["llm"] = time.time() - _t0
    else:
        safety_verdict = "UNSAFE" if max_sev in ("HIGH", "CRITICAL") else "SAFE"

    prescan_data = {
        "skill_name": skill_name,
        "skill_path": skill_path,
        "findings_count": findings_count,
        "max_severity": max_sev,
        "safety_confidence": safety_confidence,
        "safety_verdict": safety_verdict,
        "llm_reason": llm_reason,
        "llm_reason_en": llm_reason_en,
    }

    # Runtime sandbox: only for gray zone (confidence between safety_threshold and sandbox_threshold)
    runtime_result = {}
    runtime_safe = True
    needs_sandbox = safety_verdict == "SAFE" and (
        safety_confidence is None  # LLM failed, fallback — verify in sandbox
        or safety_confidence < settings.sandbox_threshold  # gray zone
    )

    if use_runtime and needs_sandbox:
        _t0 = time.time()
        try:
            runtime_result = await _run_docker_sandbox(skill_path, settings, enable_after_tool=enable_after_tool)
            runtime_safe = runtime_result.get("status") in ("PASSED", "Safe")
        except Exception as e:
            runtime_result = {"status": "ERROR", "elapsed_sec": round(time.time() - _t0, 1),
                              "details": [str(e)], "blacklist_hits": 0, "blocks": 0}
            runtime_safe = True  # Don't penalize on docker error
        _latency["runtime"] = runtime_result.get("elapsed_sec", round(time.time() - _t0, 1))

    _latency["total"] = time.time() - _pipeline_start
    scanner_safe = safety_verdict == "SAFE"
    report = _build_report(prescan_data, runtime_result, scanner_safe, runtime_safe,
                           latency=_latency, batch_id=batch_id, lang=lang)
    return report


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "Skill Guardian API"}


@app.get("/api/debug/llm")
async def debug_llm():
    """Test LLM connectivity with current settings."""
    settings = get_settings()
    try:
        import litellm
        extra = {}
        if settings.llm_api_key:
            extra["api_key"] = settings.llm_api_key
        if settings.llm_base_url:
            extra["api_base"] = settings.llm_base_url
        if settings.llm_model.startswith("azure/") and settings.llm_api_version:
            extra["api_version"] = settings.llm_api_version

        r = await litellm.acompletion(
            model=settings.llm_model,
            messages=[{"role": "user", "content": "say hi"}],
            max_tokens=5,
            **extra,
        )
        return {"ok": True, "response": r.choices[0].message.content,
                "model": settings.llm_model}
    except Exception as e:
        return {"ok": False, "error": str(e), "model": settings.llm_model}


@app.post("/api/scan/upload")
async def upload_skill(file: UploadFile = File(...)):
    tmp_dir = tempfile.mkdtemp(prefix="guardian_upload_")
    file_path = os.path.join(tmp_dir, file.filename or "upload.zip")

    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)

    if file_path.endswith(".zip"):
        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(file_path, "r") as zf:
            zf.extractall(extract_dir)
        for root, dirs, files in os.walk(extract_dir):
            if "SKILL.md" in files:
                return {"skill_path": root, "skill_name": Path(root).name}
        subdirs = [d for d in os.listdir(extract_dir) if os.path.isdir(os.path.join(extract_dir, d))]
        if subdirs:
            return {"skill_path": os.path.join(extract_dir, subdirs[0]), "skill_name": subdirs[0]}
        return {"skill_path": extract_dir, "skill_name": Path(extract_dir).name}

    return {"skill_path": tmp_dir, "skill_name": file.filename}


@app.post("/api/scan/upload-folder")
async def upload_folder(files: list[UploadFile] = File(...)):
    tmp_dir = tempfile.mkdtemp(prefix="guardian_folder_")

    # Check if single archive file (zip/tar.gz/tgz)
    if len(files) == 1 and files[0].filename:
        fname = files[0].filename.lower()
        if fname.endswith(".zip") or fname.endswith(".tar.gz") or fname.endswith(".tgz"):
            archive_path = os.path.join(tmp_dir, files[0].filename)
            with open(archive_path, "wb") as out:
                out.write(await files[0].read())
            extract_dir = os.path.join(tmp_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            if fname.endswith(".zip"):
                import zipfile
                with zipfile.ZipFile(archive_path, "r") as zf:
                    zf.extractall(extract_dir)
            else:
                import tarfile
                with tarfile.open(archive_path, "r:gz") as tf:
                    tf.extractall(extract_dir)
            # Find SKILL.md in extracted
            for root, dirs, fnames in os.walk(extract_dir):
                if "SKILL.md" in fnames:
                    return {"skill_path": root, "skill_name": Path(root).name}
            subdirs = [d for d in os.listdir(extract_dir) if os.path.isdir(os.path.join(extract_dir, d))]
            if subdirs:
                skill_dir = os.path.join(extract_dir, subdirs[0])
                return {"skill_path": skill_dir, "skill_name": subdirs[0]}
            return {"skill_path": extract_dir, "skill_name": Path(extract_dir).name}

    # Regular folder upload
    for f in files:
        rel_path = f.filename or f.headers.get("filename", "unknown")
        dest = os.path.join(tmp_dir, rel_path)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as out:
            content = await f.read()
            out.write(content)
    for root, dirs, fnames in os.walk(tmp_dir):
        if "SKILL.md" in fnames:
            return {"skill_path": root, "skill_name": Path(root).name}
    subdirs = [d for d in os.listdir(tmp_dir) if os.path.isdir(os.path.join(tmp_dir, d))]
    if subdirs:
        skill_dir = os.path.join(tmp_dir, subdirs[0])
        return {"skill_path": skill_dir, "skill_name": subdirs[0]}
    return {"skill_path": tmp_dir, "skill_name": Path(tmp_dir).name}


@app.get("/api/scan/stream")
async def scan_stream(
    skill_path: str = Query(..., description="Path to skill directory"),
    policy: str = Query("balanced"),
    use_llm: bool = Query(True),
    use_runtime: bool = Query(True),
    enable_after_tool: bool = Query(True),
    lang: str = Query("en"),
):
    async def event_generator():
        async for event in _run_pipeline_stream(
            skill_path, policy, use_llm, use_runtime, enable_after_tool, lang=lang
        ):
            yield event
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@app.get("/api/scan/local")
async def scan_local(
    skill_path: str = Query(..., description="Absolute path to local skill directory"),
):
    p = Path(skill_path)
    if not p.exists():
        return {"error": f"Path not found: {skill_path}"}, 404
    if not p.is_dir():
        return {"error": "Path must be a directory"}, 400
    return {"skill_path": str(p.resolve()), "skill_name": p.name}


# ── Settings API ──

@app.get("/api/settings")
async def get_settings_api():
    """Return current settings (API keys are masked)."""
    return get_settings().to_dict(mask_keys=True)


@app.put("/api/settings")
async def update_settings_api(body: dict):
    """Update settings. Accepts partial updates. Masked keys are skipped."""
    updated = update_settings(body)
    return updated.to_dict(mask_keys=True)


@app.post("/api/settings/reset")
async def reset_settings_api():
    """Reset settings to defaults."""
    s = reset_settings()
    return s.to_dict(mask_keys=True)


@app.get("/api/settings/providers")
async def list_providers():
    """Return supported LLM provider presets."""
    return [
        {"id": "azure", "name": "Azure OpenAI", "fields": ["llm_api_key", "llm_base_url", "llm_api_version", "llm_model"],
         "defaults": {"llm_model": "azure/gpt-4o", "llm_api_version": "2025-04-01-preview"}},
        {"id": "openai", "name": "OpenAI", "fields": ["llm_api_key", "llm_model"],
         "defaults": {"llm_model": "gpt-4o-mini", "llm_base_url": ""}},
        {"id": "local_vllm", "name": "Local vLLM", "fields": ["llm_base_url", "llm_model"],
         "defaults": {"llm_model": "Qwen/Qwen3-8B", "llm_base_url": "http://localhost:8000/v1", "llm_api_key": ""}},
        {"id": "custom", "name": "Custom (litellm)", "fields": ["llm_api_key", "llm_base_url", "llm_model"],
         "defaults": {}},
    ]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Skill Guardian SSE API")
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--host", type=str, default="0.0.0.0")
    args = parser.parse_args()

    import uvicorn
    print(f"Starting Guardian API on {args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port)
