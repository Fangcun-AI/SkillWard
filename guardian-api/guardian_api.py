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


def _build_report(prescan: dict, runtime: dict, scanner_safe: bool, runtime_safe: bool,
                   latency: dict = None, batch_id: str = None, lang: str = "en",
                   skill_hash: str = "") -> dict:
    """Build a structured execution report for the frontend.

    Always emits BOTH zh and en content for warnings/recommendations so the UI
    can switch languages at display time without re-querying the backend.
    `lang` kept for backward compatibility but no longer filters stored content.
    """
    status = runtime.get("status", "UNKNOWN") if runtime else prescan.get("safety_verdict", "UNKNOWN")
    runtime_confirmed_threat = status in ("DANGER", "CONTENT_RISK", "WARNING", "High Risk")
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

    _seen_warnings = set()
    for d in details:
        if d in _seen_warnings:
            continue
        _seen_warnings.add(d)
        if "Blacklist hit" in d or "blacklist" in d.lower():
            continue
        level = "critical" if any(k in d for k in ["blocked", "Risk Level"]) else "warning"
        _add_w(level, "运行时沙箱", "Runtime Sandbox", d, d)

    for ind in cap_indicators:
        _add_w("warning", "能力分析", "Capability Analysis", ind, ind)

    # Always add a summary Runtime Sandbox warning when sandbox actually ran,
    # so the UI has a sandbox section even for clean-Safe runs.
    if sandbox_ran:
        _rt_bh = runtime.get("blacklist_hits", 0) if runtime else 0
        _rt_bk = runtime.get("blocks", 0) if runtime else 0
        _rt_elapsed = runtime.get("elapsed_sec", 0) if runtime else 0
        if status in ("Safe", "PASSED", "SAFE"):
            _add_w(
                "info", "运行时沙箱", "Runtime Sandbox",
                f"沙箱执行完成（耗时 {_rt_elapsed:.0f}s），未检测到异常工具调用或数据外泄行为。",
                f"Sandbox execution completed ({_rt_elapsed:.0f}s) with no anomalous tool calls or data exfiltration detected.",
            )
        elif status in ("Medium Risk", "WARNING"):
            _add_w(
                "warning", "运行时沙箱", "Runtime Sandbox",
                f"沙箱在执行过程中检测到中等风险信号（黑名单命中 {_rt_bh} 次，拦截 {_rt_bk} 次）。建议人工复核具体行为。",
                f"Sandbox detected medium-risk signals during execution (blacklist hits: {_rt_bh}, blocks: {_rt_bk}). Manual review recommended.",
            )
        elif status in ("High Risk", "DANGER", "BLOCKED", "CONTENT_RISK"):
            _add_w(
                "critical", "运行时沙箱", "Runtime Sandbox",
                f"沙箱检测到高风险行为（黑名单命中 {_rt_bh} 次，拦截 {_rt_bk} 次）。禁止部署。",
                f"Sandbox detected high-risk behavior (blacklist hits: {_rt_bh}, blocks: {_rt_bk}). DO NOT deploy.",
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

    if is_false_negative:
        _add_w(
            "critical",
            "综合研判", "Cross-validation",
            "静态分析未发现风险，但沙箱运行时检测到异常行为，建议仔细审查该 Skill",
            "Static analysis found no risk but runtime sandbox detected anomalous behavior. Manual review recommended.",
        )

    # Recommendations — emit both zh and en; UI picks by locale.
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
                "该 Skill 试图访问外部服务或外泄数据，具体行为：向外部域名发起网络请求（如 curl/wget/fetch），"
                "可能将工作环境中的敏感数据（API 密钥、配置文件等）发送到外部服务器。"
                "建议：审查 SKILL.md 中所有涉及网络请求的步骤，确认目标域名是否可信。",
                "This skill attempts to access external services or exfiltrate data: it makes network requests to external domains (e.g. curl/wget/fetch), "
                "potentially sending sensitive data (API keys, config files, etc.) to external servers. "
                "Recommendation: Review all network-related steps in SKILL.md and verify target domains are trusted.",
            )
        if has_credential:
            _add_r(
                "检测到凭证访问行为 — 该 Skill 在执行过程中读取了 API 密钥或令牌文件。"
                "即使 Skill 声称只做本地检查，读取凭证后配合网络请求可能导致密钥泄露。"
                "建议：在沙箱环境中不放置真实凭证，或对凭证文件设置严格的访问权限。",
                "Credential access detected — this skill reads API keys or token files during execution. "
                "Even if the skill claims to only perform local checks, reading credentials combined with network requests could lead to key leakage. "
                "Recommendation: Do not place real credentials in the sandbox, or set strict access permissions on credential files.",
            )
        if has_external and has_credential:
            _add_r(
                "高危组合：凭证读取 + 外部请求 = 典型数据外泄模式。"
                "该 Skill 先读取了本地凭证/密钥文件，随后向外部域名发起请求，"
                "这是经典的凭证窃取攻击链。强烈建议禁止使用。",
                "HIGH RISK COMBINATION: Credential access + external requests = classic data exfiltration pattern. "
                "This skill reads local credential/key files then makes requests to external domains — a classic credential theft attack chain. "
                "Strongly recommend blocking.",
            )
        if is_false_negative:
            _add_r(
                "该 Skill 通过了静态分析和 LLM 评估（被误判为安全），"
                "仅在运行时沙箱中才暴露出恶意行为。这说明多阶段检测的重要性 — "
                "对于此类善于伪装的 Skill，必须启用深度扫描（Docker 沙箱）才能有效识别。",
                "This skill passed static analysis and LLM evaluation (false negative) — malicious behavior was only exposed in the runtime sandbox. "
                "This demonstrates the importance of multi-stage detection. For skills that are good at disguising themselves, deep scanning (Docker sandbox) must be enabled.",
            )
        if has_write_root:
            _add_r(
                "该 Skill 尝试向系统敏感路径写入文件，可能修改系统配置或植入后门。"
                "建议：限制 Skill 的 write 工具权限，仅允许写入指定的输出目录。",
                "This skill attempts to write files to sensitive system paths, potentially modifying system configuration or planting backdoors. "
                "Recommendation: Restrict the skill's write tool permissions to only allow writing to designated output directories.",
            )
    elif status in ("WARNING", "Medium Risk"):
        _add_r(
            "谨慎使用 — 检测到中等风险指标，建议在部署前进行人工审查。",
            "Use with caution — medium risk indicators detected. Manual review recommended before deployment.",
        )
        if has_external:
            _add_r(
                "检测到外部网络请求行为，虽未被判定为高危，但仍需确认目标域名是否在允许列表中。"
                "建议：在生产环境中配置网络白名单，仅允许 Skill 访问已审核的域名。",
                "External network request behavior detected. While not classified as high risk, verify target domains are on the allowlist. "
                "Recommendation: Configure a network whitelist in production, only allowing the skill to access approved domains.",
            )
        if has_credential:
            _add_r(
                "该 Skill 访问了凭证文件，请确认是否为必要操作。"
                "建议：使用临时令牌或受限 API 密钥，避免暴露主密钥。",
                "This skill accessed credential files — verify this is necessary. "
                "Recommendation: Use temporary tokens or restricted API keys to avoid exposing master keys.",
            )
        _add_r(
            "建议在生产环境中限制该 Skill 的工具权限（如禁用 exec/write），"
            "并保持 FangcunGuard 实时监控开启。",
            "Recommendation: Restrict tool permissions for this skill in production (e.g. disable exec/write) and keep FangcunGuard real-time monitoring enabled.",
        )
    elif status in ("PASSED", "Safe", "SAFE"):
        _add_r(
            "该 Skill 通过所有安全检查，可在标准防护下安全使用。",
            "This skill passed all security checks and can be safely used under standard protection.",
        )
        _add_r(
            "建议在生产环境中保持 FangcunGuard 监控开启，提供持续运行时保护。"
            "即使当前检测安全，Skill 的行为可能因输入不同而变化。",
            "Recommendation: Keep FangcunGuard monitoring enabled in production for continuous runtime protection. "
            "Even if currently detected as safe, skill behavior may vary with different inputs.",
        )
    elif status == "TIMEOUT":
        _add_r(
            "执行超时 — 该 Skill 在规定时间内未完成执行，可能原因：死循环、资源耗尽、"
            "等待不可达的外部服务响应。建议：检查 Skill 逻辑，增加超时时间后重新测试，"
            "或在资源受限环境中设置更严格的执行上限。",
            "Execution timeout — the skill did not complete within the time limit. "
            "Possible causes: infinite loop, resource exhaustion, or waiting for unreachable external services. "
            "Recommendation: Check skill logic, increase timeout and retest, or set stricter execution limits in resource-constrained environments.",
        )
    elif status in ("INCONCLUSIVE", "INCOMPLETE"):
        _add_r(
            "沙箱执行未能完成（可能是 Skill 依赖缺失或代码兼容性问题），"
            "已回退到静态分析结果。该结果不代表安全风险，仅表示无法通过运行时验证。",
            "Sandbox execution could not complete (possibly due to missing skill dependencies or code compatibility issues). "
            "Fell back to static analysis results. This does not indicate a security risk, only that runtime verification was not possible.",
        )
    elif status in ("ERROR", "SANDBOX_FAILED"):
        _add_r(
            "执行过程中遇到错误，可能原因：环境依赖缺失、Skill 代码 bug、"
            "Docker 容器配置问题。建议：检查完整日志，确认所需的运行时依赖是否已安装。",
            "An error occurred during execution. Possible causes: missing environment dependencies, skill code bugs, or Docker container configuration issues. "
            "Recommendation: Check full logs and verify required runtime dependencies are installed.",
        )

    # Extract skill info from SKILL.md
    skill_desc = ""
    skill_capabilities = []
    skill_path = prescan.get("skill_path", "")
    if skill_path:
        skill_md = Path(skill_path) / "SKILL.md"
        if skill_md.exists():
            try:
                content = skill_md.read_text(errors="replace")
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

    # Build latency dict
    lat = latency or {}

    # INCONCLUSIVE: agent couldn't execute — keep INCONCLUSIVE as verdict
    # (don't silently fall back to SAFE, because we couldn't verify)
    final_verdict = status

    report = {
        "verdict": final_verdict,
        "skill_name": prescan.get("skill_name", "unknown"),
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
    }

    if batch_id:
        report["batch_id"] = batch_id

    # Persist to SQLite
    from scan_db import save_scan
    save_scan(report, skill_hash=skill_hash)
    return report


async def _run_pipeline_stream(skill_path: str, policy: str = "balanced",
                                use_llm: bool = True, use_runtime: bool = True,
                                use_verify: bool = True, lang: str = "en"):
    """Generator that runs the real pipeline and yields SSE events."""
    settings = get_settings()
    _pipeline_start = time.time()
    _latency = {"total": 0, "static": 0, "llm": 0, "runtime": 0, "verify": 0}

    # ══════════════════════════════════════════════════════════════
    # Short-circuit: if identical skill was recently scanned, return cache
    # ══════════════════════════════════════════════════════════════
    from scan_db import compute_skill_hash, find_by_skill_hash
    skill_hash = compute_skill_hash(skill_path)
    if skill_hash:
        cached = find_by_skill_hash(skill_hash, lang=lang)
        if cached:
            yield _sse_event(0, "cached", "已缓存结果（跳过扫描）", {"report": cached})
            yield _sse_event(0, "report", "扫描报告", {"report": cached})
            yield _sse_event(0, "done", "Pipeline complete (cached)",
                             {"prescan": None, "runtime": None, "verify": None, "cached": True})
            return

    # ══════════════════════════════════════════════════════════════
    # Stage 1: Static Analysis + LLM Safety Scoring
    # ══════════════════════════════════════════════════════════════
    yield _sse_event(1, "stage", "阶段一: 静态分析 + LLM 安全评估")
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
    findings_count = skill_data["findings_count"]
    max_sev = skill_data["max_severity"]

    yield _sse_event(1, "step", f"YARA rule scan... {sum(1 for f in skill_data['findings'] if 'yara' in f.get('rule_id','').lower())} matches")
    await asyncio.sleep(0.2)
    yield _sse_event(1, "step", f"正则模式扫描... 发现 {sum(1 for f in skill_data['findings'] if 'yara' not in f.get('rule_id','').lower())} 项")
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
        yield _sse_event(1, "step", f"LLM 安全评估 ({llm_model})...")
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
                max_tokens=4000,
                **extra,
            )
            raw = response.choices[0].message.content.strip()
            raw = re.sub(r'<think>.*?</think>', '', raw, flags=re.DOTALL).strip()
            if raw.startswith("```"):
                raw = re.sub(r'^```(?:json)?\s*', '', raw)
                raw = re.sub(r'\s*```$', '', raw)
            if not raw.startswith("{"):
                m = re.search(r'\{.*\}', raw, flags=re.DOTALL)
                if m:
                    raw = m.group(0)
            result = json.loads(raw)
            score = max(0.0, min(1.0, float(result.get("safety_confidence", 0.0))))
            triage = {"safety_confidence": score, "reason": result.get("reason", ""), "reason_en": result.get("reason_en", "")}
            safety_confidence = triage["safety_confidence"]
            llm_reason = triage["reason"]
            llm_reason_en = triage["reason_en"]

            if llm_reason.startswith("error:") or llm_reason.startswith("JSON parse error"):
                yield _sse_event(1, "alert", f"LLM API 错误: {llm_reason}, 回退到静态分析结果")
                safety_verdict = "UNSAFE" if max_sev in ("HIGH", "CRITICAL") else "SAFE"
                safety_confidence = None
            else:
                safety_verdict = "SAFE" if safety_confidence >= settings.safety_threshold else "UNSAFE"
                _latency["llm"] = time.time() - _t_llm_start
                yield _sse_event(1, "result",
                    f"LLM 置信度: {safety_confidence:.2f} → {safety_verdict} ({_latency['llm']:.1f}s)" +
                    (f", 进入沙箱" if safety_verdict == "SAFE" and use_runtime else ""),
                    {"safety_confidence": safety_confidence, "verdict": safety_verdict, "reason": llm_reason})
        except Exception as e:
            _latency["llm"] = time.time() - _t_llm_start
            yield _sse_event(1, "alert", f"LLM 评估失败: {e}, 仅使用静态分析结果")
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
        yield _sse_event(1, "result", "Skill 判定为不安全 — 跳过沙箱测试")
        report = _build_report(prescan_data, {}, False, False, latency=_latency,
                                lang=lang, skill_hash=skill_hash)
        report["recommendations"] = [
            "静态分析和 LLM 评估判定该 Skill 为不安全，请勿使用。",
            "审查上述发现后再考虑任何使用方式。",
        ]
        report["recommendations_en"] = [
            "DO NOT USE this skill — static analysis and/or LLM flagged it as UNSAFE.",
            "Review the findings above before considering any use.",
        ]
        yield _sse_event(0, "report", "扫描报告", {"report": report})
        await asyncio.sleep(0.2)
        yield _sse_event(0, "done", "流水线完成",
                        {"prescan": prescan_data, "runtime": None, "verify": None})
        return

    # Clearly safe (confidence above sandbox_threshold) — skip sandbox
    if safety_confidence is not None and safety_confidence >= settings.sandbox_threshold and use_runtime:
        _latency["total"] = time.time() - _pipeline_start
        yield _sse_event(1, "result",
            f"LLM confidence {safety_confidence:.2f} >= {settings.sandbox_threshold} — clearly safe, skipping sandbox")
        report = _build_report(prescan_data, {}, True, True, latency=_latency,
                                lang=lang, skill_hash=skill_hash)
        report["recommendations"] = [
            "该 Skill 通过静态分析和 LLM 高置信度评估，判定为安全，无需沙箱验证。",
            "建议在生产环境中保持 FangcunGuard 监控开启，提供持续运行时保护。",
        ]
        report["recommendations_en"] = [
            "This skill passed static analysis and high-confidence LLM evaluation; no sandbox verification needed.",
            "Recommendation: Keep FangcunGuard monitoring enabled in production for continuous runtime protection.",
        ]
        yield _sse_event(0, "report", "扫描报告", {"report": report})
        await asyncio.sleep(0.2)
        yield _sse_event(0, "done", "流水线完成",
                        {"prescan": prescan_data, "runtime": None, "verify": None})
        return

    # ══════════════════════════════════════════════════════════════
    # Stage 2: Docker Sandbox Runtime Detection
    # ══════════════════════════════════════════════════════════════
    if not use_runtime:
        _latency["total"] = time.time() - _pipeline_start
        scanner_safe = safety_verdict == "SAFE"
        report = _build_report(prescan_data, {}, scanner_safe, True, latency=_latency,
                                lang=lang, skill_hash=skill_hash)
        yield _sse_event(0, "report", "扫描报告", {"report": report})
        await asyncio.sleep(0.2)
        yield _sse_event(0, "done", "Pipeline complete (runtime disabled)",
                        {"prescan": prescan_data, "runtime": None, "verify": None})
        return

    yield _sse_event(2, "stage", "阶段二: Docker 沙箱运行时检测")
    await asyncio.sleep(0.3)

    docker_image = settings.docker_image
    yield _sse_event(2, "step", f"Starting sandbox with image {docker_image}...")
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
                enable_after_tool=use_verify,
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
            "retries_used": result.get("retries_used", 0),
            "early_stopped": result.get("early_stopped", False),
            "low_risk_alert": result.get("low_risk_alert", False),
            "details": result.get("details", []),
            "output_file": result.get("output_file"),
            "phase1_file": result.get("phase1_file"),
        }

        _details = result.get("details", []) or []
        _verdict_suffix = f" — {'; '.join(_details[:2])}" if _details else ""
        yield _sse_event(2, "result",
            f"运行时结论: {runtime_status}{_verdict_suffix}",
            {"status": runtime_status, "details": _details})

    except Exception as e:
        import traceback; traceback.print_exc()
        yield _sse_event(2, "finding", f"Docker 运行时错误: {e}")
        yield _sse_event(2, "result", f"运行时结论: ERROR — {e}")
        runtime_result = {"status": "ERROR", "details": [str(e)]}

    await asyncio.sleep(0.5)

    # ══════════════════════════════════════════════════════════════
    # Stage 3: Post-hoc Capability Analysis / False Negative Check
    # ══════════════════════════════════════════════════════════════
    _latency["runtime"] = runtime_result.get("elapsed_sec", 0)

    if not use_verify:
        _latency["total"] = time.time() - _pipeline_start
        scanner_safe = safety_verdict == "SAFE"
        runtime_safe = runtime_result.get("status") == "PASSED"
        report = _build_report(prescan_data, runtime_result, scanner_safe, runtime_safe,
                                latency=_latency, lang=lang, skill_hash=skill_hash)
        yield _sse_event(0, "report", "扫描报告", {"report": report})
        await asyncio.sleep(0.2)
        yield _sse_event(0, "done", "流水线完成",
                        {"prescan": prescan_data, "runtime": runtime_result})
        return

    yield _sse_event(3, "stage", "阶段三: 事后能力分析")
    await asyncio.sleep(0.3)
    yield _sse_event(3, "step", "正在分析工具调用链的能力滥用情况...")
    await asyncio.sleep(0.2)

    scanner_safe = safety_verdict == "SAFE"
    runtime_safe = runtime_result.get("status") == "PASSED"

    if scanner_safe and not runtime_safe:
        yield _sse_event(3, "finding",
            f"漏报警告: 阶段一判定为安全，但运行时检测到 {runtime_result.get('status')}")
        await asyncio.sleep(0.2)
        final_verdict = runtime_result.get("status", "DANGER")
        yield _sse_event(3, "result",
            f"最终结论: {final_verdict} — 运行时检测发现了静态分析遗漏的威胁",
            {"verdict": final_verdict, "false_negative": True})
    elif not runtime_safe:
        yield _sse_event(3, "result",
            f"最终结论: {runtime_result.get('status')} — 两个阶段均确认",
            {"verdict": runtime_result.get("status"), "false_negative": False})
    else:
        yield _sse_event(3, "result", "最终结论: SAFE — 通过所有阶段检查",
                        {"verdict": "SAFE", "false_negative": False})

    await asyncio.sleep(0.3)

    _latency["total"] = time.time() - _pipeline_start
    report = _build_report(prescan_data, runtime_result, scanner_safe, runtime_safe,
                            latency=_latency, lang=lang, skill_hash=skill_hash)
    yield _sse_event(0, "report", "扫描报告", {"report": report})
    await asyncio.sleep(0.2)

    yield _sse_event(0, "done", "流水线完成", {
        "prescan": prescan_data,
        "runtime": {
            "status": runtime_result.get("status"),
            "details": runtime_result.get("details", []),
        },
    })


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
    """Accept a .zip / .tar.gz archive of skill folders, extract it, and report
    the discovered skills. The caller then points `/api/batch/{batch_id}/stream`
    at the returned `skills_dir` to run the actual scan pipeline.
    """
    tmp_dir = tempfile.mkdtemp(prefix="guardian_batch_")
    file_path = os.path.join(tmp_dir, file.filename or "upload.zip")

    with open(file_path, "wb") as f:
        content_bytes = await file.read()
        f.write(content_bytes)

    extract_dir = os.path.join(tmp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    lower = file_path.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(file_path, "r") as zf:
            zf.extractall(extract_dir)
    elif lower.endswith((".tar.gz", ".tgz")):
        import tarfile
        with tarfile.open(file_path, "r:gz") as tf:
            tf.extractall(extract_dir)
    else:
        return {"error": "Unsupported archive format. Use .zip, .tar.gz or .tgz."}, 400

    # Walk extract_dir, collecting every directory that contains SKILL.md.
    # Skip nested SKILL.md discoveries (only the outermost skill folder counts).
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
    use_verify: bool = Query(True),
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

        yield _sse_event(0, "batch_start", f"批量扫描: 发现 {len(skill_dirs)} 个 Skill", {
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
                        use_verify=use_verify, batch_id=bid)
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
                        "source": "批量扫描",
                        "batch_id": bid,
                        "latency": {"total": round(time.time() - t0, 1), "static": 0, "llm": 0, "runtime": 0, "verify": 0},
                        "stages": {"static": {"verdict": "ERROR", "findings": 0, "severity": "N/A"},
                                   "llm": {"confidence": None, "reason": ""},
                                   "runtime": {"status": "SKIPPED", "elapsed": 0, "blacklist_hits": 0, "blocks": 0}},
                        "warnings": [{"level": "critical", "source": "系统", "text": str(e)}],
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
            verdict_icon = {"PASSED": "SAFE", "DANGER": "DANGER", "ERROR": "ERROR"}.get(result["verdict"], result["verdict"])
            yield _sse_event(0, "skill_done",
                f"[{result['progress']}/{len(skill_dirs)}] {result['skill_name']} → {verdict_icon} ({result['latency']}s)",
                result)

        # Finalize batch
        finish_batch(bid)
        total_elapsed = round(time.time() - batch_start_time, 1)

        from scan_db import get_batch as _gb
        summary = _gb(bid)

        yield _sse_event(0, "batch_done", f"批量扫描完成: {len(skill_dirs)} 个 Skill, 耗时 {total_elapsed}s", {
            "batch_id": bid,
            **summary,
        })

    return StreamingResponse(
        _batch_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


async def _run_docker_sandbox(skill_path: str, settings, use_verify: bool = True,
                              on_progress=None) -> dict:
    """Run Docker sandbox for a single skill (non-streaming). Returns runtime_result dict.

    on_progress: optional callable (kind: str, msg: str) -> None invoked at
      milestones. Callers (e.g. `_run_pipeline_stream`) can push these into an
      asyncio.Queue to surface progress as SSE events.
    """
    def _emit(kind: str, msg: str):
        if on_progress:
            try:
                on_progress(kind, msg)
            except Exception:
                pass  # never let user callback break the pipeline

    from guardian import (build_phase2_prompt, PHASE1_PROMPT, PHASE2_MARKER,
                          _extract_tool_calls,
                          _detect_incomplete_execution, _detect_agent_crash)

    skill_folder = Path(skill_path).name
    skill_dir = str(skill_path)
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

    phase2_prompt = build_phase2_prompt(skill_folder, skill_dir)
    phase2_for_heredoc = phase2_prompt.replace("\\", "\\\\")
    phase1_for_heredoc = PHASE1_PROMPT.replace("\\", "\\\\")
    total_timeout = prep_timeout + timeout_sec

    inner_script = f"""
# ── Copy RO skill to writable location ──
cp -a /root/.openclaw/skills/test-skill-src /root/.openclaw/skills/test-skill

echo "===SETUP_START==="
# strtok3 is pre-installed in the image; skip npm install
test -d /opt/openclaw/node_modules/strtok3 || (cd /opt/openclaw && npm install --no-audit --no-fund strtok3 > /dev/null 2>&1)
RESP_JS="/opt/openclaw/node_modules/@mariozechner/pi-ai/dist/providers/openai-responses.js"
if [ -f "$RESP_JS" ]; then
    sed -i 's|baseURL: model.baseUrl,|baseURL: model.baseUrl, defaultQuery: {{"api-version": "2025-04-01-preview"}},|' "$RESP_JS"
fi
cat > /root/.openclaw/openclaw.json <<'EOFJSON'
{{"gateway":{{"mode":"local"}},"agents":{{"defaults":{{"model":{{"primary":"{docker_model}"}},"elevatedDefault":"on"}}}},"tools":{{"allow":["read","edit","write","exec","process","gateway","sessions_spawn","web_search","web_fetch"],"elevated":{{"enabled":true,"allowFrom":{{"{_model_provider}":["*"]}}}}}}}}
EOFJSON
python3 -c "
import json
p='/root/.config/openclaw/config.json'
try:
    with open(p) as f: cfg=json.load(f)
except: cfg={{}}
cfg['tools']={{'allow':['read','edit','write','exec','process','gateway','sessions_spawn','web_search','web_fetch'],'elevated':{{'enabled':True,'allowFrom':{{'{_model_provider}':['*']}}}}}}
cfg.setdefault('agents',{{}}).setdefault('defaults',{{}})['elevatedDefault']='on'
with open(p,'w') as f: json.dump(cfg,f)
"
mkdir -p /root/.openclaw/agents/main/agent
cat > /root/.openclaw/agents/main/agent/auth-profiles.json <<'EOFAUTH'
{{"profiles":{{"{_model_profile}":{{"type":"api_key","provider":"{_model_provider}","key":"{azure_key}","baseUrl":"{azure_url}"}}}},"order":{{"{_model_provider}":["{_model_profile}"]}}}}
EOFAUTH
cat > /root/.openclaw/agents/main/agent/models.json <<'EOFMODELS'
{{"providers":{{"{_model_provider}":{{"baseUrl":"{azure_url}","apiKey":"{azure_key}","api":"{_api_type}","headers":{{"api-key":"{azure_key}"}},"models":[{{"id":"{_model_id}","name":"{_model_id}","contextWindow":200000,"maxTokens":32768}}]}}}}}}
EOFMODELS
echo "Sample document content for testing." > /tmp/sample.txt
echo '{{"name":"test","data":[1,2,3]}}' > /tmp/sample.json
printf 'name,value\\nAlice,100\\nBob,200\\n' > /tmp/sample.csv
mkdir -p /tmp/myproject && echo 'print("hello")' > /tmp/myproject/main.py && echo '# My Project' > /tmp/myproject/README.md
truncate -s 0 /root/.openclaw/workspace/AGENTS.md
truncate -s 0 /root/.openclaw/workspace/HEARTBEAT.md
truncate -s 0 /root/.openclaw/workspace/IDENTITY.md
truncate -s 0 /root/.openclaw/workspace/USER.md
truncate -s 0 /root/.openclaw/workspace/TOOLS.md
ls -la /root/.openclaw/skills/test-skill/ 2>/dev/null | head -8
GUARD_PLUGIN_FILE="/root/.openclaw/extensions/openclaw-fangcun-guard/index.ts"
if [ -n "$GUARD_PLUGIN_API_KEY" ] && [ -f "$GUARD_PLUGIN_FILE" ]; then
    sed -i 's/sk-xxai-PbBmNhMNCM4pG9mF9GqHQM7U518clbYq4E08scSVln50Pyv49tp7n2SL/'"$GUARD_PLUGIN_API_KEY"'/g' "$GUARD_PLUGIN_FILE"
fi
# ── Patch: force elevated permissions allowed in --local mode ──
for _df in /opt/openclaw/dist/reply-*.js /opt/openclaw/dist/pi-embedded-*.js /opt/openclaw/dist/compact-*.js; do
    [ -f "$_df" ] && sed -i 's/function resolveElevatedPermissions(params)/function resolveElevatedPermissions(params){{return{{enabled:true,allowed:true,failures:[]}};}}function _orig_resolveElevatedPermissions(params)/' "$_df"
done
for _df in /opt/openclaw/dist/pi-embedded-*.js /opt/openclaw/dist/reply-*.js /opt/openclaw/dist/compact-*.js; do
    [ -f "$_df" ] && sed -i 's/const elevatedDefaults = defaults?.elevated;/const elevatedDefaults = defaults?.elevated || {{enabled:true,allowed:true,defaultLevel:"on"}};/' "$_df"
done
echo "===SETUP_DONE==="
echo "===PHASE1_START==="
mv /root/.openclaw/extensions/openclaw-fangcun-guard /tmp/_disabled_guardian 2>/dev/null || true
timeout {prep_timeout} node /opt/openclaw/openclaw.mjs agent --local \
    --session-id "prep-{skill_folder}" \
    -m "$(cat <<'EOFP1PROMPT'
{phase1_for_heredoc}
EOFP1PROMPT
)" --json 2>&1
echo "===PHASE1_DONE==="
rm -rf /root/.openclaw/sessions/prep-* 2>/dev/null
rm -rf /root/.openclaw/agents/main/sessions/prep-* 2>/dev/null
rm -f /root/.openclaw/workspace/MEMORY.md
rm -f /root/.openclaw/workspace/BOOTSTRAP.md
truncate -s 0 /root/.openclaw/workspace/TOOLS.md
truncate -s 0 /root/.openclaw/workspace/AGENTS.md
truncate -s 0 /root/.openclaw/workspace/HEARTBEAT.md
truncate -s 0 /root/.openclaw/workspace/IDENTITY.md
truncate -s 0 /root/.openclaw/workspace/USER.md
mv /tmp/_disabled_guardian /root/.openclaw/extensions/openclaw-fangcun-guard 2>/dev/null || true
echo "{PHASE2_MARKER}"
MAX_RETRIES={max_retries}
RETRY_DELAY={retry_delay}
ATTEMPT=0
while [ $ATTEMPT -le $MAX_RETRIES ]; do
    ATTEMPT=$((ATTEMPT + 1))
    echo "===PHASE2_ATTEMPT=$ATTEMPT==="
    rm -rf /root/.openclaw/sessions/test-* 2>/dev/null
    rm -rf /root/.openclaw/agents/main/sessions/test-* 2>/dev/null
    timeout {timeout_sec} node /opt/openclaw/openclaw.mjs agent --local \
        --session-id "test-{skill_folder}" \
        -m "$(cat <<'EOFPROMPT'
{phase2_for_heredoc}
EOFPROMPT
)" --json 2>&1 | tee /tmp/phase2_output.txt
    if grep -q '"stopReason": "stop"' /tmp/phase2_output.txt || grep -q '"stopReason":"stop"' /tmp/phase2_output.txt; then
        break
    fi
    # Any non-success result triggers repair (error, empty output, no stopReason, etc.)
    if [ $ATTEMPT -le $MAX_RETRIES ]; then
        echo "===PHASE2_FAILED_ATTEMPT=$ATTEMPT==="
        ERROR_MSGS=$(grep -iE 'Error:|error:|ModuleNotFoundError|ImportError|command not found|No such file|Permission denied|Cannot find|npm ERR|stopReason.*error' /tmp/phase2_output.txt | tail -5)
        if [ -z "$ERROR_MSGS" ]; then
            ERROR_MSGS="Agent did not complete successfully (no stopReason=stop found in output)"
        fi
        echo "[retry] Phase 2 failed, extracting error for Phase 1 repair..."
        echo "[retry] Error: $ERROR_MSGS"
        mv /root/.openclaw/extensions/openclaw-fangcun-guard /tmp/_disabled_guardian 2>/dev/null || true
        rm -rf /root/.openclaw/sessions/repair-* 2>/dev/null
        rm -rf /root/.openclaw/agents/main/sessions/repair-* 2>/dev/null
        echo "===PHASE1_REPAIR_START==="
        timeout {prep_timeout} node /opt/openclaw/openclaw.mjs agent --local \
            --session-id "repair-{skill_folder}" \
            -m "The skill at /root/.openclaw/skills/test-skill/ failed to execute. Here is the error output:

$ERROR_MSGS

Please fix the environment so the skill can run successfully:
1. Read the skill files to understand what dependencies/tools it needs
2. Install any missing packages (pip install, npm install, apt-get install, etc.)
3. Create any missing config files or directories the skill expects
4. Do NOT run the skill itself - only fix the environment

Work directory: /root/.openclaw/skills/test-skill/" --json 2>&1
        echo "===PHASE1_REPAIR_DONE==="
        rm -rf /root/.openclaw/sessions/repair-* 2>/dev/null
        rm -rf /root/.openclaw/agents/main/sessions/repair-* 2>/dev/null
        rm -f /root/.openclaw/workspace/MEMORY.md
        rm -f /root/.openclaw/workspace/BOOTSTRAP.md
        truncate -s 0 /root/.openclaw/workspace/TOOLS.md 2>/dev/null
        truncate -s 0 /root/.openclaw/workspace/AGENTS.md 2>/dev/null
        truncate -s 0 /root/.openclaw/workspace/HEARTBEAT.md 2>/dev/null
        truncate -s 0 /root/.openclaw/workspace/IDENTITY.md 2>/dev/null
        truncate -s 0 /root/.openclaw/workspace/USER.md 2>/dev/null
        mv /tmp/_disabled_guardian /root/.openclaw/extensions/openclaw-fangcun-guard 2>/dev/null || true
        echo "[retry] Environment repaired, retrying Phase 2..."
    else
        break
    fi
done
"""
    container_ts = int(time.time())
    container_name = f"guardian-batch-{skill_folder}-{container_ts}"
    docker_cmd = [
        "docker", "run", "--rm",
        "--name", container_name,
        "--entrypoint", "bash",
        "-v", f"{skill_dir}:/root/.openclaw/skills/test-skill-src:ro",
        "-e", f"AZURE_OPENAI_BASE_URL={azure_url}",
        "-e", f"AZURE_OPENAI_API_KEY={azure_key}",
    ]
    # Inject dummy API keys for skills that require external credentials
    required_envs = extract_env_requirements(skill_dir)
    for env_name in required_envs:
        docker_cmd.extend(["-e", f"{env_name}=sk-proj-Rf4kPl8cHdWm2xNqYvTb7jAs9eUoZiLg3nXpKw6tMy"])
    if guard_plugin_api_url:
        docker_cmd += ["-e", f"FANGCUN_GUARD_API_URL={guard_plugin_api_url}"]
    if guard_plugin_api_key:
        docker_cmd += ["-e", f"GUARD_PLUGIN_API_KEY={guard_plugin_api_key}"]
    if not use_verify:
        docker_cmd += ["-e", "FANGCUN_DISABLE_AFTER_TOOL=1"]
    docker_cmd += [docker_image, "-c", inner_script]

    max_total_timeout = total_timeout + (max_retries * (timeout_sec + retry_delay)) + 60
    start_time = time.time()

    _emit("step", f"Launching sandbox container ({container_name})...")
    proc = await asyncio.create_subprocess_exec(
        *docker_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    _BLACKLIST_LOW_RISK_RE = re.compile(r'Tool check result: risk=\d+, label=low_risk')
    blacklist_re_p = re.compile(r'Blacklist hit:\s*(.*)')

    output_lines = []
    phase2_lines = []
    in_phase2 = False
    blacklist_seen = False
    low_risk_alert = False
    _phase1_announced = False

    try:
        async for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", errors="replace")
            output_lines.append(line)

            if not in_phase2:
                if not _phase1_announced and "===PHASE1_START===" in line:
                    _emit("step", "Phase 1 started (environment prep, Guardian disabled)...")
                    _phase1_announced = True
                if "===PHASE1_EXIT_CODE" in line:
                    _emit("step", "Phase 1 complete, switching to Phase 2...")

            if PHASE2_MARKER in line:
                in_phase2 = True
                _emit("step", "Phase 2 started (skill execution under Guardian)")
                continue
            if in_phase2:
                phase2_lines.append(line)

                if "===PHASE2_ATTEMPT=" in line:
                    m_attempt = re.search(r"PHASE2_ATTEMPT=(\d+)", line)
                    if m_attempt:
                        _emit("step", f"Phase 2 attempt {m_attempt.group(1)}...")
                if "===PHASE2_RETRY" in line:
                    _emit("alert", "Agent crashed — retrying")
                if "[FangcunGuard]" in line or "fangcun-guard]" in line.lower():
                    if "risk detected" in line.lower():
                        _emit("finding", line.strip()[:200])
                    elif "tool_check output_raw:" in line:
                        _emit("api", line.strip()[:200])

            bl = blacklist_re_p.search(line)
            if bl:
                blacklist_seen = True

            if blacklist_seen and _BLACKLIST_LOW_RISK_RE.search(line):
                low_risk_alert = True

            if time.time() - start_time > max_total_timeout:
                _emit("alert", f"Timeout exceeded ({max_total_timeout}s), killing container")
                try:
                    kill_proc = await asyncio.create_subprocess_exec(
                        "docker", "kill", container_name,
                        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                    await asyncio.wait_for(kill_proc.wait(), timeout=10)
                except Exception:
                    pass
                break
    except Exception:
        pass

    await proc.wait()
    _emit("step", "Execution finished, analyzing output...")
    elapsed = round(time.time() - start_time, 1)

    phase2_output_text = "".join(phase2_lines)
    tool_calls_parsed = _extract_tool_calls(phase2_output_text)
    incomplete = _detect_incomplete_execution(phase2_output_text, tool_calls_parsed)
    agent_crashed = _detect_agent_crash(phase2_output_text)

    p2_lines = phase2_output_text.split("\n")
    blacklist_hits_list = [l for l in p2_lines if "Blacklist hit" in l]
    blocks = [l for l in p2_lines if re.search(
        r'Risk Level [23]|"blocked":\s*true|write failed.*FangcunGuard|exec failed.*FangcunGuard|read failed.*FangcunGuard', l)]
    content_risks = [l for l in p2_lines if ("fangcun-guard]" in l.lower() or "[FangcunGuard]" in l) and "risk detected" in l.lower()]
    high_content_risks = [l for l in content_risks if re.search(r'risk=[3-9]', l)]
    blocks.extend(high_content_risks)
    tool_checks = [l for l in p2_lines if "Tool check result: risk=" in l]
    low_risk_hits = sum(1 for l in tool_checks if "label=low_risk" in l)
    medium_risk_hits = sum(1 for l in tool_checks if "label=medium_risk" in l or "risk=2" in l)
    high_risk_hits = sum(1 for l in tool_checks if "label=high_risk" in l or "risk=3" in l)
    # Broad scan: any p2 line with "Output risk detected" + risk=3 counts as high risk (covers after_tool content review)
    all_risk3 = sum(1 for l in p2_lines if "risk detected" in l.lower() and re.search(r'risk=[3-9]', l))
    if all_risk3 > high_risk_hits:
        high_risk_hits = all_risk3
    if blocks:
        runtime_status = "DANGER"
    elif high_risk_hits >= 1:
        runtime_status = "DANGER"
    elif content_risks:
        runtime_status = "DANGER"
    elif time.time() - start_time > max_total_timeout:
        runtime_status = "TIMEOUT"
    elif agent_crashed and not blocks and not blacklist_hits_list:
        runtime_status = "INCONCLUSIVE"
    elif blacklist_hits_list or medium_risk_hits >= 1 or low_risk_hits >= 1:
        runtime_status = "WARNING"
    elif incomplete:
        runtime_status = "INCOMPLETE"
    else:
        runtime_status = "PASSED"

    return {
        "skill": skill_folder,
        "status": runtime_status,
        "elapsed_sec": elapsed,
        "blacklist_hits": len(blacklist_hits_list),
        "blocks": len(blocks),
        "content_risks": len(content_risks),
        "agent_crashed": agent_crashed,
        "early_stopped": False,
        "low_risk_alert": low_risk_alert,
        "details": [l.strip()[:200] for l in (blacklist_hits_list + blocks + content_risks)[:10]],
    }


async def _run_single_scan(skill_path: str, use_llm: bool = True, use_runtime: bool = False,
                           use_verify: bool = True, batch_id: str = None,
                           lang: str = "en") -> dict:
    """Run a single skill scan (non-streaming) and return the report dict."""
    from scan_db import compute_skill_hash, find_by_skill_hash
    skill_hash = compute_skill_hash(skill_path)
    # Short-circuit on cache hit (same behavior as SSE pipeline).
    if skill_hash:
        cached = find_by_skill_hash(skill_hash, lang=lang)
        if cached:
            return cached
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
                max_tokens=4000,
                **extra,
            )
            raw = response.choices[0].message.content.strip()
            raw = re.sub(r'<think>.*?</think>', '', raw, flags=re.DOTALL).strip()
            if raw.startswith("```"):
                raw = re.sub(r'^```(?:json)?\s*', '', raw)
                raw = re.sub(r'\s*```$', '', raw)
            if not raw.startswith("{"):
                m = re.search(r'\{.*\}', raw, flags=re.DOTALL)
                if m:
                    raw = m.group(0)
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
            runtime_result = await _run_docker_sandbox(skill_path, settings, use_verify=use_verify)
            runtime_safe = runtime_result.get("status") == "PASSED"
        except Exception as e:
            runtime_result = {"status": "ERROR", "elapsed_sec": round(time.time() - _t0, 1),
                              "details": [str(e)], "blacklist_hits": 0, "blocks": 0}
            runtime_safe = True  # Don't penalize on docker error
        _latency["runtime"] = runtime_result.get("elapsed_sec", round(time.time() - _t0, 1))

    _latency["total"] = time.time() - _pipeline_start
    scanner_safe = safety_verdict == "SAFE"
    report = _build_report(prescan_data, runtime_result, scanner_safe, runtime_safe,
                           latency=_latency, batch_id=batch_id,
                           lang=lang, skill_hash=skill_hash)
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
    use_verify: bool = Query(True),
    lang: str = Query("en", description="Language for report text: 'zh' or 'en'"),
):
    async def event_generator():
        async for event in _run_pipeline_stream(
            skill_path, policy, use_llm, use_runtime, use_verify, lang=lang,
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
