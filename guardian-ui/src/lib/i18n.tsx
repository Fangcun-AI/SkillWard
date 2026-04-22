"use client";

import { createContext, useContext, useState, useCallback, useEffect, useRef, type ReactNode } from "react";

export type Locale = "zh" | "en";

const translations = {
  // ── Nav ──
  "nav.title": { zh: "SkillWard", en: "SkillWard" },
  "nav.subtitle": { zh: "AI 安全检测流水线", en: "AI Security Pipeline" },
  "nav.submit": { zh: "提交", en: "Submit" },
  "nav.history": { zh: "历史", en: "History" },
  "nav.batch": { zh: "批量扫描", en: "Batch Scan" },
  "nav.online": { zh: "在线", en: "ONLINE" },

  // ── Home hero ──
  "hero.badge": { zh: "Guardian 就绪", en: "Guardian Ready" },
  "hero.title_pre": { zh: "提交 ", en: "Submit " },
  "hero.title_accent": { zh: "Skill", en: "Skill" },
  "hero.title_post": { zh: " 进行分析", en: " for Analysis" },
  "hero.desc": { zh: "三阶段流水线：静态分析 + LLM 评分、Docker 运行时检测、漏报交叉验证", en: "Three-stage pipeline: static analysis + LLM scoring, Docker runtime detection, false negative verification" },

  // ── Pipeline stages (home page) ──
  "pipeline.title": { zh: "扫描流水线", en: "Scan Pipeline" },
  "stage.1.label": { zh: "STAGE 1", en: "STAGE 1" },
  "stage.1.name": { zh: "静态分析", en: "Static Analysis" },
  "stage.1.desc": { zh: "YARA 规则、正则匹配、AST 语法树扫描，秒级识别已知恶意模式", en: "YARA rules, regex matching, AST scanning — identifies known malicious patterns in seconds" },
  "stage.2.label": { zh: "STAGE 2", en: "STAGE 2" },
  "stage.2.name": { zh: "LLM 语义评估", en: "LLM Semantic Eval" },
  "stage.2.desc": { zh: "大模型深度理解代码意图，识别混淆与隐蔽后门", en: "Deep code intent analysis via LLM, detecting obfuscation and hidden backdoors" },
  "stage.3.label": { zh: "STAGE 3", en: "STAGE 3" },
  "stage.3.name": { zh: "沙箱执行", en: "Sandbox Execution" },
  "stage.3.desc": { zh: "Docker 隔离容器中实际执行，定制化 Guard 实时监控行为", en: "Real execution in Docker isolation, customized Guard monitors behavior in real-time" },
  "pipeline.deep_available": { zh: "深度扫描可用", en: "Deep scan available" },
  "stage.4.label": { zh: "STAGE 4", en: "STAGE 4" },
  "stage.4.name": { zh: "深度追踪", en: "Deep Trace" },
  "stage.4.desc": { zh: "追踪并检查 Agent 访问的外部链接与资源内容", en: "Traces and inspects external URLs and resources accessed by the Agent" },

  // ── Submit mode toggle ──
  "submit.mode.single": { zh: "单个扫描", en: "Single Scan" },
  "submit.mode.batch": { zh: "批量扫描", en: "Batch Scan" },

  // ── Upload panel ──
  "upload.tab.file": { zh: "文件", en: "File" },
  "upload.tab.url": { zh: "URL", en: "URL" },
  "upload.drop.prompt": { zh: "点击选择一个 Skill 压缩包（包含 SKILL.md）", en: "Click to select a skill archive (containing SKILL.md)" },
  "upload.drop.formats": { zh: "支持格式：", en: "Supported: " },
  "upload.drop.folder": { zh: "skill 文件夹", en: "skill folder" },
  "upload.drop.must_contain": { zh: "Skill 压缩包必须包含 ", en: "Skill archive must contain " },
  "upload.drop.remove": { zh: "移除并重新选择", en: "Remove & choose another" },
  "upload.drop.files_count": { zh: " 个文件", en: " files" },
  "upload.url.label": { zh: "Skill 仓库地址", en: "Skill Repository URL" },
  "upload.url.hint": { zh: "支持 GitHub、GitLab 及直链归档文件", en: "Supports GitHub, GitLab, and direct archive URLs" },
  "upload.submit": { zh: "开始扫描", en: "Submit Scan" },
  "upload.scanning": { zh: "扫描中...", en: "Scanning..." },

  // ── Scan modes ──
  "mode.title": { zh: "扫描模式", en: "Scan Mode" },
  "mode.static.name": { zh: "快速扫描", en: "Quick Scan" },
  "mode.static.sub": { zh: "~10s", en: "~10s" },
  "mode.static.desc": { zh: "静态分析 + LLM 评分，秒级出结果", en: "Static analysis + LLM scoring, results in seconds" },
  "mode.sandbox.name": { zh: "沙箱检测", en: "Sandbox Scan" },
  "mode.sandbox.sub": { zh: "~2-3min", en: "~2-3min" },
  "mode.sandbox.desc": { zh: "Docker 隔离执行 Skill，实时监控行为（2-3 min）", en: "Execute Skill in Docker isolation, real-time behavior monitoring (2-3 min)" },
  "mode.deep.name": { zh: "深度追踪", en: "Deep Trace" },
  "mode.deep.sub": { zh: "~2-4min", en: "~2-4min" },
  "mode.deep.desc": { zh: "沙箱执行 + 追踪检查外部链接内容（2-4 min）", en: "Sandbox execution + trace external URL content (2-4 min)" },

  // ── Scan modal ──
  "modal.title.scanning": { zh: "扫描进行中", en: "Scanning" },
  "modal.title.complete": { zh: "扫描完成", en: "Scan Complete" },

  // ── Pipeline preview (scanning state) ──
  "preview.output": { zh: "流水线输出", en: "PIPELINE OUTPUT" },
  "preview.stage0.title": { zh: "正在准备扫描环境...", en: "Preparing scan environment..." },
  "preview.stage0.desc": { zh: "初始化扫描引擎与检测规则", en: "Initializing scan engine and detection rules" },
  "preview.stage1.title": { zh: "静态分析 + LLM 安全评估中", en: "Running static analysis + LLM evaluation" },
  "preview.stage1.desc": { zh: "使用 YARA 规则、正则匹配和 LLM 模型进行代码审查", en: "Code review with YARA rules, regex matching, and LLM models" },
  "preview.stage2.title": { zh: "Docker 沙箱运行中", en: "Docker sandbox running" },
  "preview.stage2.desc": { zh: "Agent 正在沙箱中执行 Skill，实时监控工具调用、网络请求与文件操作", en: "Agent executing Skill in sandbox, monitoring tool calls, network requests, and file operations" },
  "preview.stage3.title": { zh: "交叉验证分析中", en: "Cross-validation analysis" },
  "preview.stage3.desc": { zh: "对比各阶段结果，排查是否存在漏报", en: "Comparing results across stages, checking for false negatives" },

  // ── Report ──
  "report.safe_use": { zh: "可安全使用", en: "Safe to Use" },
  "report.block": { zh: "拒绝安装", en: "Block Installation" },
  "report.review": { zh: "人工审查", en: "Manual Review" },
  "report.verdict.safe": { zh: "安全", en: "SAFE" },
  "report.verdict.danger": { zh: "危险", en: "DANGER" },
  "report.verdict.warn": { zh: "警告", en: "WARNING" },
  "report.verdict.cap_risk": { zh: "能力风险", en: "CAPABILITY RISK" },
  "report.verdict.content_risk": { zh: "内容风险", en: "CONTENT RISK" },
  "report.verdict.timeout": { zh: "超时", en: "TIMEOUT" },
  "report.verdict.error": { zh: "错误", en: "ERROR" },
  "report.verdict.inconclusive": { zh: "未确定", en: "INCONCLUSIVE" },
  "report.not_found": { zh: "未找到该扫描记录", en: "Scan record not found" },
  "report.load_error": { zh: "加载失败", en: "Failed to load" },
  "report.loading": { zh: "加载中...", en: "Loading..." },
  "report.back_history": { zh: "返回历史记录", en: "Back to history" },
  "report.source.other": { zh: "其他", en: "Other" },
  "report.score.failed": { zh: "评分失败 — LLM 未返回结果", en: "Scoring failed — LLM returned no result" },
  "report.stage.verify": { zh: "交叉验证", en: "Cross Verification" },
  "report.score.failed_detail": { zh: "LLM 未能返回评分结果（可能是 API 连接或认证问题），已回退到静态分析结论。", en: "LLM failed to return a score (possibly API connection or auth issue). Falling back to static analysis verdict." },
  "report.latency.analysis": { zh: "时延分析", en: "Latency Analysis" },
  "report.source.static": { zh: "静态分析", en: "Static Analysis" },
  "report.source.llm": { zh: "LLM 研判", en: "LLM Evaluation" },
  "report.source.runtime": { zh: "运行时沙箱", en: "Runtime Sandbox" },
  "report.source.verify": { zh: "跨阶段验证", en: "Cross-Stage Verification" },
  "report.source.capability": { zh: "能力分析", en: "Capability Analysis" },
  "report.capabilities": { zh: "Skill 能力声明", en: "Skill Capabilities" },
  "report.cap.python": { zh: "Python 运行时", en: "Python Runtime" },
  "report.cap.javascript": { zh: "JavaScript", en: "JavaScript" },
  "report.cap.typescript": { zh: "TypeScript", en: "TypeScript" },
  "report.cap.bash": { zh: "Bash Shell", en: "Bash Shell" },
  "report.cap.shell": { zh: "Shell", en: "Shell" },
  "report.cap.node": { zh: "Node.js", en: "Node.js" },
  "report.cap.read": { zh: "文件读取", en: "File Read" },
  "report.cap.readdir": { zh: "目录读取", en: "Dir Read" },
  "report.cap.write": { zh: "文件写入", en: "File Write" },
  "report.cap.edit": { zh: "文件编辑", en: "File Edit" },
  "report.cap.exec": { zh: "命令执行", en: "Cmd Execute" },
  "report.cap.run": { zh: "进程运行", en: "Process Run" },
  "report.cap.network": { zh: "网络访问", en: "Network Access" },
  "report.cap.http": { zh: "HTTP 请求", en: "HTTP Request" },
  "report.cap.fetch": { zh: "网络请求", en: "Net Request" },
  "report.cap.high_risk": { zh: "高危", en: "HIGH" },
  "report.stages": { zh: "各阶段结果", en: "Stage Results" },
  "report.stage.static": { zh: "静态分析", en: "Static Analysis" },
  "report.stage.llm": { zh: "LLM 评估", en: "LLM Evaluation" },
  "report.stage.runtime": { zh: "运行时沙箱", en: "Runtime Sandbox" },
  "report.stage.no_risk": { zh: "未发现风险", en: "No risks found" },
  "report.stage.findings": { zh: " 项发现", en: " findings" },
  "report.stage.safe_pct": { zh: "% 安全", en: "% safe" },
  "report.stage.passed": { zh: "通过", en: "Passed" },
  "report.stage.blocked": { zh: "已拦截", en: "Blocked" },
  "report.findings": { zh: "发现的问题", en: "Findings" },
  "report.level.critical": { zh: "严重", en: "CRITICAL" },
  "report.level.warning": { zh: "警告", en: "WARNING" },
  "report.level.info": { zh: "信息", en: "INFO" },
  "report.fn.title": { zh: "检测到漏报（False Negative）", en: "False Negative Detected" },
  "report.fn.desc": { zh: "静态分析 + LLM 将该 Skill 评估为安全，但运行时沙箱执行发现了恶意行为。这说明多阶段分析的重要性。", en: "Static analysis + LLM assessed this Skill as safe, but runtime sandbox detected malicious behavior. This demonstrates the importance of multi-stage analysis." },
  "report.rec.safe": { zh: "使用建议", en: "Usage Advice" },
  "report.rec.unsafe": { zh: "修复建议", en: "Recommendations" },
  "report.score.label": { zh: "总评分 / 置信度", en: "Score / Confidence" },
  "report.score.name": { zh: "LLM 安全置信度", en: "LLM Safety Confidence" },
  "report.static.label": { zh: "静态发现", en: "Static Findings" },
  "report.static.count": { zh: "项发现", en: "findings" },
  "report.sandbox.label": { zh: "沙箱状态", en: "Sandbox Status" },
  "report.sandbox.hits": { zh: "黑名单命中", en: "Blacklist hits" },
  "report.latency.label": { zh: "总时延", en: "Total Latency" },
  "report.latency.unit": { zh: "秒", en: "sec" },
  "report.stages.title": { zh: "三阶段分析", en: "Three-Stage Analysis" },
  "report.stage.verdict": { zh: "结论", en: "Verdict" },
  "report.stage.findings_count": { zh: "发现数", en: "Findings" },
  "report.stage.severity": { zh: "最高严重度", en: "Max Severity" },
  "report.stage.elapsed": { zh: "耗时", en: "Elapsed" },
  "report.stage.confidence": { zh: "置信度", en: "Confidence" },
  "report.stage.status": { zh: "状态", en: "Status" },
  "report.stage.exec_time": { zh: "执行耗时", en: "Exec Time" },
  "report.stage.blacklist_hits": { zh: "黑名单命中", en: "Blacklist Hits" },
  "report.stage.blocks": { zh: "拦截次数", en: "Blocks" },
  "report.stage.reason": { zh: "分析理由", en: "Analysis Reason" },
  "report.threats.title": { zh: "威胁详情", en: "Threat Details" },
  "report.capabilities.title": { zh: "能力声明", en: "Capabilities" },
  "report.fn_detect": { zh: "漏报检测", en: "FN Detection" },

  // ── Certificate ──
  "cert.title": { zh: "安全认证通过", en: "Security Certification Passed" },
  "cert.desc": { zh: "该 Skill 已通过 Skills Scanner 三阶段安全检测流水线，未发现恶意行为或安全风险。", en: "This Skill has passed the Skills Scanner three-stage security pipeline with no malicious behavior or security risks detected." },
  "cert.skill_name": { zh: "Skill 名称:", en: "Skill Name:" },
  "cert.scan_time": { zh: "检测时间:", en: "Scan Time:" },
  "cert.cert_id": { zh: "证书编号:", en: "Certificate ID:" },
  "cert.engine": { zh: "检测引擎:", en: "Scan Engine:" },
  "cert.download": { zh: "下载证书", en: "Download Certificate" },

  // ── History ──
  "history.title": { zh: "扫描历史", en: "Scan History" },
  "history.subtitle": { zh: "// 扫描记录 SCAN HISTORY", en: "// SCAN HISTORY" },
  "history.loading": { zh: "加载中...", en: "Loading..." },
  "history.empty": { zh: "暂无扫描记录", en: "No scan records yet" },
  "history.go_scan": { zh: "提交 Skill 进行分析", en: "Submit a Skill for analysis" },
  "history.findings_count": { zh: "发现 {n} 项", en: "{n} findings" },
  "history.false_neg": { zh: "漏报", en: "FN" },
  "history.verdict.danger": { zh: "危险", en: "Danger" },
  "history.verdict.warn": { zh: "警告", en: "Warning" },
  "history.verdict.safe": { zh: "安全", en: "Safe" },
  "history.verdict.timeout": { zh: "超时", en: "Timeout" },
  "history.verdict.error": { zh: "错误", en: "Error" },

  // ── Threat tags (history) ──
  "tag.data_exfil": { zh: "数据外传", en: "Data Exfil" },
  "tag.external_req": { zh: "外部请求", en: "External Req" },
  "tag.blacklist": { zh: "黑名单命中", en: "Blacklist Hit" },
  "tag.credential": { zh: "凭证访问", en: "Credential Access" },
  "tag.fn_detect": { zh: "漏报检测", en: "FN Detection" },
  "tag.runtime_block": { zh: "运行时拦截", en: "Runtime Block" },
  "tag.risk_eval": { zh: "风险评估", en: "Risk Assessment" },
  "tag.early_term": { zh: "提前终止", en: "Early Termination" },
  "tag.static_find": { zh: "静态发现", en: "Static Findings" },

  // ── Batch upload ──
  "batch.upload.prompt": { zh: "点击上传包含多个 Skill 的压缩包", en: "Click to upload an archive containing multiple Skills" },
  "batch.upload.hint": { zh: "压缩包内每个 Skill 文件夹须包含 SKILL.md", en: "Each Skill folder inside must contain SKILL.md" },
  "batch.uploading": { zh: "上传中...", en: "Uploading..." },

  // ── Batch scan ──
  "batch.title": { zh: "批量扫描", en: "Batch Scan" },
  "batch.subtitle": { zh: "// 批量检测 BATCH SCAN", en: "// BATCH SCAN" },
  "batch.dir_label": { zh: "Skills 压缩包", en: "Skills Archive" },
  "batch.dir_placeholder": { zh: "点击上传 .zip / .tar.gz 压缩包", en: "Click to upload .zip / .tar.gz archive" },
  "batch.concurrency": { zh: "并发数", en: "Workers" },
  "batch.runtime": { zh: "沙箱", en: "Sandbox" },
  "batch.start": { zh: "开始扫描", en: "Start Scan" },
  "batch.stop": { zh: "停止", en: "Stop" },
  "batch.scanning": { zh: "扫描进行中...", en: "Scanning..." },
  "batch.complete": { zh: "扫描完成", en: "Scan Complete" },
  "batch.results": { zh: "扫描结果", en: "Scan Results" },
  "batch.log": { zh: "扫描日志", en: "Scan Log" },
  "batch.stat.total": { zh: "总计", en: "Total" },
  "batch.stat.safe": { zh: "安全", en: "Safe" },
  "batch.stat.unsafe": { zh: "危险", en: "Unsafe" },
  "batch.stat.error": { zh: "错误", en: "Error" },
  "batch.stat.fn": { zh: "漏报", en: "FN" },
  "batch.stat.avg_latency": { zh: "平均时延", en: "Avg Latency" },
  "batch.verdict.safe": { zh: "安全", en: "Safe" },
  "batch.verdict.danger": { zh: "危险", en: "Danger" },
  "batch.verdict.risk": { zh: "风险", en: "Risk" },
  "batch.verdict.warn": { zh: "警告", en: "Warning" },
  "batch.verdict.error": { zh: "错误", en: "Error" },
  "batch.verdict.timeout": { zh: "超时", en: "Timeout" },
  "batch.filter.all": { zh: "全部", en: "All" },
  "batch.filter.safe": { zh: "安全", en: "Safe" },
  "batch.filter.unsafe": { zh: "危险", en: "Unsafe" },
  "batch.filter.error": { zh: "错误", en: "Error" },
  "batch.col.name": { zh: "Skill 名称", en: "Skill Name" },
  "batch.col.verdict": { zh: "结论", en: "Verdict" },
  "batch.col.findings": { zh: "发现", en: "Findings" },
  "batch.col.latency": { zh: "时延", en: "Latency" },
  "batch.col.fn": { zh: "漏报", en: "FN" },

  // ── Language switcher ──
  "lang.zh": { zh: "中文", en: "中文" },
  "lang.en": { zh: "English", en: "English" },

  // ── Settings modal ──
  "settings.title": { zh: "设置", en: "Settings" },
  "settings.llm.title": { zh: "LLM 配置", en: "LLM Configuration" },
  "settings.llm.provider": { zh: "提供商", en: "Provider" },
  "settings.llm.api_key": { zh: "API 密钥", en: "API Key" },
  "settings.llm.base_url": { zh: "Base URL", en: "Base URL" },
  "settings.llm.model": { zh: "模型", en: "Model" },
  "settings.llm.api_version": { zh: "API 版本", en: "API Version" },
  "settings.docker.title": { zh: "Docker 沙箱", en: "Docker Sandbox" },
  "settings.docker.image": { zh: "Docker 镜像", en: "Docker Image" },
  "settings.docker.model": { zh: "容器内模型", en: "Container Model" },
  "settings.docker.azure_url": { zh: "容器 Azure URL", en: "Container Azure URL" },
  "settings.docker.azure_key": { zh: "容器 Azure Key", en: "Container Azure Key" },
  "settings.safety.title": { zh: "安全阈值", en: "Safety Thresholds" },
  "settings.safety.threshold": { zh: "安全置信度阈值", en: "Safety Confidence Threshold" },
  "settings.safety.phase1_timeout": { zh: "Phase 1 超时 (秒)", en: "Phase 1 Timeout (sec)" },
  "settings.safety.phase2_timeout": { zh: "Phase 2 超时 (秒)", en: "Phase 2 Timeout (sec)" },
  "settings.fangcun.title": { zh: "FangcunGuard API（主机端，可选）", en: "FangcunGuard API (host-side, optional)" },
  "settings.fangcun.url": { zh: "API 地址", en: "API URL" },
  "settings.fangcun.key": { zh: "API 密钥", en: "API Key" },
  "settings.guard_plugin.title": { zh: "容器内 Guard 插件（运行时拦截）", en: "Container Guard Plugin (runtime interception)" },
  "settings.guard_plugin.desc": { zh: "配置 Docker 沙箱内 FangcunGuard 插件连接的后端 API，用于实时拦截恶意工具调用", en: "Configure the backend API that the FangcunGuard plugin inside Docker sandbox connects to for real-time malicious tool interception" },
  "settings.guard_plugin.url": { zh: "Guard API 地址", en: "Guard API URL" },
  "settings.guard_plugin.key": { zh: "Guard API 密钥", en: "Guard API Key" },
  "settings.save": { zh: "保存", en: "Save" },
  "settings.test": { zh: "测试连接", en: "Test Connection" },
  "settings.saved": { zh: "已保存", en: "Saved" },
  "settings.reset": { zh: "恢复默认", en: "Reset Defaults" },
  "settings.test.ok": { zh: "连接成功", en: "Connection OK" },
  "settings.test.fail": { zh: "连接失败", en: "Connection Failed" },
} as const;

type TranslationKey = keyof typeof translations;

interface I18nContextValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: (key: TranslationKey, vars?: Record<string, string | number>) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>("zh");
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem("guardian-locale") as Locale | null;
    if (saved === "zh" || saved === "en") {
      setLocaleState(saved);
    }
    setReady(true);
  }, []);

  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l);
    localStorage.setItem("guardian-locale", l);
  }, []);

  const t = useCallback((key: TranslationKey, vars?: Record<string, string | number>): string => {
    const entry = translations[key];
    if (!entry) return key;
    let text: string = entry[locale] || entry.zh;
    if (vars) {
      for (const [k, v] of Object.entries(vars)) {
        text = text.replace(`{${k}}`, String(v));
      }
    }
    return text;
  }, [locale]);

  return (
    <I18nContext.Provider value={{ locale, setLocale, t }}>
      {children}
    </I18nContext.Provider>
  );
}

export function useI18n() {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within I18nProvider");
  return ctx;
}

/** Language dropdown selector */
export function LanguageToggle() {
  const { locale, setLocale } = useI18n();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const options: { key: Locale; label: string; flag: string }[] = [
    { key: "zh", label: "中文", flag: "🇨🇳" },
    { key: "en", label: "English", flag: "🇺🇸" },
  ];

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 text-[11px] font-medium text-stone-400 hover:text-white transition-colors px-2.5 py-1.5 rounded-md hover:bg-white/10"
      >
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 21l5.25-11.25L21 21m-9-3h7.5M3 5.621a48.474 48.474 0 016-.371m0 0c1.12 0 2.233.038 3.334.114M9 5.25V3m3.334 2.364C11.176 10.658 7.69 15.08 3 17.502m9.334-12.138c.896.061 1.785.147 2.666.257m-4.589 8.495a18.023 18.023 0 01-3.827-5.802" />
        </svg>
        {locale === "zh" ? "中文" : "EN"}
        <svg className={`w-3 h-3 transition-transform ${open ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
        </svg>
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-1.5 w-32 bg-stone-800 border border-stone-600/50 rounded-lg shadow-xl overflow-hidden z-50">
          {options.map((opt) => (
            <button
              key={opt.key}
              onClick={() => { setLocale(opt.key); setOpen(false); }}
              className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs transition-colors ${
                locale === opt.key
                  ? "bg-violet-600/20 text-violet-400"
                  : "text-stone-300 hover:bg-white/5 hover:text-white"
              }`}
            >
              <span className="text-sm">{opt.flag}</span>
              <span className="font-medium">{opt.label}</span>
              {locale === opt.key && (
                <svg className="w-3.5 h-3.5 ml-auto text-violet-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                </svg>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
