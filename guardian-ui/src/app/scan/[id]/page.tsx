"use client";

import { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { useI18n, LanguageToggle } from "@/lib/i18n";

const API_BASE = process.env.NEXT_PUBLIC_GUARDIAN_API || "http://localhost:8899";

interface ScanRecord {
  id: string;
  skill_name: string;
  skill_description?: string;
  verdict: string;
  false_negative: boolean;
  scan_time?: string;
  source?: string;
  stages: {
    static: {
      verdict: string; findings: number; severity: string;
      findings_list?: Array<{
        id: string; rule_id: string; category: string; severity: string;
        title: string; description: string;
        file_path?: string; line_number?: number; snippet?: string;
        remediation?: string;
      }>;
    };
    llm: { confidence: number | null; reason: string; reason_en?: string };
    runtime: { status: string; elapsed: number; blacklist_hits: number; blocks: number };
  };
  capabilities: string[];
  warnings: { level: string; source: string; text: string; text_en?: string }[];
  recommendations: string[];
  recommendations_en?: string[];
  findings_count: number;
  max_severity: string;
  safety_confidence: number;
  latency: { total: number; static: number; llm: number; runtime: number; verify: number };
  runtime_status: string;
}

const VERDICT_STYLES: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  BLOCKED: { bg: "bg-red-50", text: "text-red-600", border: "border-red-200", dot: "bg-red-500" },
  ALERT: { bg: "bg-amber-50", text: "text-amber-600", border: "border-amber-200", dot: "bg-amber-500" },
  PASSED: { bg: "bg-emerald-50", text: "text-emerald-600", border: "border-emerald-200", dot: "bg-emerald-500" },
  SAFE: { bg: "bg-emerald-50", text: "text-emerald-600", border: "border-emerald-200", dot: "bg-emerald-500" },
  CAPABILITY_RISK: { bg: "bg-orange-50", text: "text-orange-600", border: "border-orange-200", dot: "bg-orange-500" },
  CONTENT_RISK: { bg: "bg-orange-50", text: "text-orange-600", border: "border-orange-200", dot: "bg-orange-500" },
  TIMEOUT: { bg: "bg-stone-50", text: "text-stone-500", border: "border-stone-200", dot: "bg-stone-400" },
  ERROR: { bg: "bg-stone-50", text: "text-stone-500", border: "border-stone-200", dot: "bg-stone-400" },
  INCONCLUSIVE: { bg: "bg-amber-50", text: "text-amber-600", border: "border-amber-200", dot: "bg-amber-400" },
  UNSAFE: { bg: "bg-red-50", text: "text-red-600", border: "border-red-200", dot: "bg-red-500" },
};

const VERDICT_LABEL_KEYS: Record<string, string> = {
  BLOCKED: "report.verdict.danger", ALERT: "report.verdict.warn",
  PASSED: "report.verdict.safe", SAFE: "report.verdict.safe",
  CAPABILITY_RISK: "report.verdict.cap_risk", CONTENT_RISK: "report.verdict.content_risk",
  TIMEOUT: "report.verdict.timeout", ERROR: "report.verdict.error",
  INCONCLUSIVE: "report.verdict.inconclusive", UNSAFE: "report.verdict.danger",
};

const LEVEL_STYLES: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: "bg-red-50", text: "text-red-700", border: "border-red-200" },
  warning: { bg: "bg-amber-50", text: "text-amber-700", border: "border-amber-200" },
  info: { bg: "bg-blue-50", text: "text-blue-700", border: "border-blue-200" },
};

const LEVEL_LABEL_KEYS: Record<string, string> = {
  critical: "report.level.critical", warning: "report.verdict.warn", info: "report.level.info",
};

/** Circular progress indicator */
function CircularProgress({ value, size = 80, strokeWidth = 6 }: { value: number; size?: number; strokeWidth?: number }) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (value / 100) * circumference;
  const color = value >= 80 ? "text-red-500" : value >= 50 ? "text-amber-500" : "text-emerald-500";
  // Invert: high confidence in threat = red; low = green

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="currentColor"
          strokeWidth={strokeWidth} className="text-stone-100" />
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="currentColor"
          strokeWidth={strokeWidth} className={color}
          strokeDasharray={circumference} strokeDashoffset={offset}
          strokeLinecap="round" style={{ transition: "stroke-dashoffset 0.6s ease" }} />
      </svg>
      <span className={cn("absolute text-lg font-bold font-mono", color)}>
        {value}%
      </span>
    </div>
  );
}

export default function ScanDetailPage() {
  const { t, locale } = useI18n();
  const isEn = locale === "en";
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;

  const getVerdictConfig = (verdict: string) => {
    const style = VERDICT_STYLES[verdict] || VERDICT_STYLES.ERROR;
    const labelKey = VERDICT_LABEL_KEYS[verdict] || "report.verdict.error";
    return { ...style, label: t(labelKey) };
  };

  const getLevelConfig = (level: string) => {
    const style = LEVEL_STYLES[level] || LEVEL_STYLES.info;
    const labelKey = LEVEL_LABEL_KEYS[level] || "report.level.info";
    return { ...style, label: t(labelKey) };
  };

  const [record, setRecord] = useState<ScanRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`${API_BASE}/api/scan/history?limit=200`)
      .then((res) => res.json())
      .then((data) => {
        const list: ScanRecord[] = Array.isArray(data) ? data : (data.records || []);
        const found = list.find((r) => r.id === id);
        if (found) {
          setRecord(found);
        } else {
          setError(t("report.not_found"));
        }
        setLoading(false);
      })
      .catch(() => {
        setError(t("report.load_error"));
        setLoading(false);
      });
  }, [id]);

  if (loading) {
    return (
      <div className="min-h-screen bg-warm flex flex-col">
        <NavBar />
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <span className="w-8 h-8 border-2 border-stone-300 border-t-cyan-500 rounded-full animate-spin inline-block" />
            <p className="mt-3 text-sm text-stone-400">{t("report.loading")}</p>
          </div>
        </div>
      </div>
    );
  }

  if (error || !record) {
    return (
      <div className="min-h-screen bg-warm flex flex-col">
        <NavBar />
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-stone-100 flex items-center justify-center">
              <svg className="w-8 h-8 text-stone-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
              </svg>
            </div>
            <p className="text-stone-500 text-sm mb-4">{error || t("report.not_found")}</p>
            <Link href="/history" className="text-xs text-cyan-600 hover:text-cyan-700 font-semibold">
              {t("report.back_history")} &rarr;
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const vc = getVerdictConfig(record.verdict);
  const confidenceRaw = record.safety_confidence ?? record.stages.llm.confidence;
  const confidenceAvailable = confidenceRaw !== null && confidenceRaw !== undefined;
  const confidence = confidenceRaw ?? 0;
  const confidencePct = Math.round(confidence * 100);

  // Group warnings by source
  const SOURCE_MAP: Record<string, string> = {
    "静态分析": t("report.source.static"),
    "LLM 研判": t("report.source.llm"),
    "运行时沙箱": t("report.source.runtime"),
    "跨阶段验证": t("report.source.verify"),
    "能力分析": t("report.source.capability"),
  };
  const warningsBySource: Record<string, typeof record.warnings> = {};
  for (const w of record.warnings) {
    const src = SOURCE_MAP[w.source] || w.source || t("report.source.other");
    if (!warningsBySource[src]) warningsBySource[src] = [];
    warningsBySource[src].push(w);
  }

  // Latency bar segments
  const latency = record.latency || { total: 0, static: 0, llm: 0, runtime: 0, verify: 0 };
  const latencyTotal = latency.total || (latency.static + latency.llm + latency.runtime + latency.verify) || 1;
  const latencySegments = [
    { key: "static", label: t("report.stage.static"), value: latency.static, color: "bg-cyan-500" },
    { key: "llm", label: t("report.stage.llm"), value: latency.llm, color: "bg-violet-500" },
    { key: "runtime", label: t("report.stage.runtime"), value: latency.runtime, color: "bg-amber-500" },
    { key: "verify", label: t("report.stage.verify"), value: latency.verify, color: "bg-emerald-500" },
  ].filter((s) => s.value > 0);

  return (
    <div className="min-h-screen bg-warm flex flex-col">
      <NavBar />

      <div className="flex-1">
        <div className="max-w-7xl mx-auto px-8 py-8">

          {/* Back link */}
          <button onClick={() => router.back()} className="inline-flex items-center gap-1.5 text-xs text-stone-400 hover:text-cyan-600 font-semibold mb-6 transition-colors">
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5" />
            </svg>
            {t("report.back_history")}
          </button>

          {/* ── Header ── */}
          <div className="flex items-start justify-between mb-8">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <h1 className="text-2xl font-bold text-stone-800">{record.skill_name}</h1>
                <span className={cn("text-xs font-bold px-3 py-1 rounded-lg", vc.bg, vc.text)}>
                  {vc.label}
                </span>
                {record.false_negative && (
                  <span className="text-xs font-bold px-3 py-1 rounded-lg bg-amber-50 text-amber-600 border border-amber-200">
                    {t("report.fn_detect")}
                  </span>
                )}
              </div>
              {record.skill_description && (
                <p className="text-sm text-stone-500 max-w-2xl mb-1">{record.skill_description}</p>
              )}
              <div className="flex items-center gap-4 text-xs text-stone-400 font-mono">
                <span>{record.scan_time || "---"}</span>
                {record.source && (
                  <>
                    <span className="text-stone-300">|</span>
                    <span>{(isEn && (record as Record<string, unknown>).source_en as string) || record.source}</span>
                  </>
                )}
                <span className="text-stone-300">|</span>
                <span className="text-stone-300">ID: {record.id}</span>
              </div>
            </div>
          </div>

          {/* ── Overview cards ── */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            {/* Confidence */}
            <div className="card-white rounded-xl border border-stone-200 p-5 flex items-center gap-4">
              {confidenceAvailable ? (
                <CircularProgress value={confidencePct} size={72} strokeWidth={5} />
              ) : (
                <div className="w-[72px] h-[72px] rounded-full bg-stone-100 flex items-center justify-center">
                  <span className="text-sm font-bold text-stone-400">N/A</span>
                </div>
              )}
              <div>
                <div className="text-[10px] font-bold text-stone-400 uppercase tracking-wider mb-0.5">{t("report.score.label")}</div>
                <div className="text-sm font-bold text-stone-700">{t("report.score.name")}</div>
                {confidenceAvailable ? (
                  <div className="text-xs text-stone-400 font-mono mt-0.5">{confidence.toFixed(2)}</div>
                ) : (
                  <div className="text-xs text-amber-500 font-medium mt-0.5">{t("report.score.failed")}</div>
                )}
              </div>
            </div>

            {/* Static findings */}
            <div className="card-white rounded-xl border border-stone-200 p-5">
              <div className="text-[10px] font-bold text-stone-400 uppercase tracking-wider mb-2">{t("report.static.label")}</div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold font-mono text-stone-800">{record.stages.static.findings}</span>
                <span className="text-xs text-stone-400">{t("report.static.count")}</span>
              </div>
              <div className="flex items-center gap-2 mt-2">
                <span className={cn(
                  "text-[10px] font-bold px-2 py-0.5 rounded-md",
                  record.stages.static.severity === "HIGH" || record.stages.static.severity === "CRITICAL"
                    ? "bg-red-50 text-red-600"
                    : record.stages.static.severity === "MEDIUM"
                    ? "bg-amber-50 text-amber-600"
                    : "bg-emerald-50 text-emerald-600"
                )}>
                  {record.stages.static.severity || "NONE"}
                </span>
                <span className={cn(
                  "text-[10px] font-bold px-2 py-0.5 rounded-md",
                  record.stages.static.verdict === "SAFE" || record.stages.static.verdict === "PASSED"
                    ? "bg-emerald-50 text-emerald-600"
                    : "bg-red-50 text-red-600"
                )}>
                  {record.stages.static.verdict}
                </span>
              </div>
            </div>

            {/* Runtime sandbox */}
            <div className="card-white rounded-xl border border-stone-200 p-5">
              <div className="text-[10px] font-bold text-stone-400 uppercase tracking-wider mb-2">{t("report.sandbox.label")}</div>
              <div className="flex items-baseline gap-2">
                <span className={cn(
                  "text-lg font-bold",
                  record.stages.runtime.status === "BLOCKED" ? "text-red-600"
                    : record.stages.runtime.status === "PASSED" || record.stages.runtime.status === "SAFE" ? "text-emerald-600"
                    : "text-stone-600"
                )}>
                  {record.stages.runtime.status}
                </span>
              </div>
              <div className="flex items-center gap-3 mt-2 text-xs text-stone-400 font-mono">
                <span>{record.stages.runtime.elapsed.toFixed(1)}s</span>
                <span className="text-stone-300">|</span>
                <span>{t("report.sandbox.hits")} {record.stages.runtime.blacklist_hits}</span>
              </div>
            </div>

            {/* Latency */}
            <div className="card-white rounded-xl border border-stone-200 p-5">
              <div className="text-[10px] font-bold text-stone-400 uppercase tracking-wider mb-2">{t("report.latency.label")}</div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold font-mono text-cyan-600">{latency.total.toFixed(1)}</span>
                <span className="text-xs text-stone-400">{t("report.latency.unit")}</span>
              </div>
              <div className="flex items-center gap-2 mt-2 text-[10px] text-stone-400 font-mono">
                <span>S:{latency.static.toFixed(1)}s</span>
                {latency.llm > 0 && <span>L:{latency.llm.toFixed(1)}s</span>}
                {latency.runtime > 0 && <span>R:{latency.runtime.toFixed(1)}s</span>}
                {latency.verify > 0 && <span>V:{latency.verify.toFixed(1)}s</span>}
              </div>
            </div>
          </div>

          {/* ── Three-stage analysis pipeline ── */}
          <div className="mb-8">
            <h2 className="text-sm font-bold text-stone-800 mb-4 flex items-center gap-2">
              <svg className="w-4 h-4 text-cyan-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
              </svg>
              {t("report.stages.title")}
            </h2>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-0">
              {/* Stage 1: Static */}
              <div className="relative">
                <div className={cn(
                  "card-white rounded-l-xl lg:rounded-r-none rounded-xl lg:rounded-bl-xl border p-5 h-full",
                  record.stages.static.verdict === "SAFE" || record.stages.static.verdict === "PASSED"
                    ? "border-emerald-200" : "border-red-200"
                )}>
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-8 h-8 rounded-lg bg-cyan-100 text-cyan-600 flex items-center justify-center">
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m5.231 13.481L15 17.25m-4.5-15H5.625c-.621 0-1.125.504-1.125 1.125v16.5c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9zm3.75 11.625a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" />
                      </svg>
                    </div>
                    <div>
                      <span className="text-[10px] font-mono font-bold text-cyan-500">STAGE 1</span>
                      <div className="text-sm font-bold text-stone-700">{t("report.stage.static")}</div>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-stone-400">{t("report.stage.verdict")}</span>
                      <span className={cn("font-bold",
                        record.stages.static.verdict === "SAFE" || record.stages.static.verdict === "PASSED"
                          ? "text-emerald-600" : "text-red-600"
                      )}>{record.stages.static.verdict}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-stone-400">{t("report.stage.findings_count")}</span>
                      <span className="font-bold text-stone-700 font-mono">{record.stages.static.findings}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-stone-400">{t("report.stage.severity")}</span>
                      <span className={cn("font-bold",
                        record.stages.static.severity === "HIGH" || record.stages.static.severity === "CRITICAL"
                          ? "text-red-600" : record.stages.static.severity === "MEDIUM" ? "text-amber-600" : "text-emerald-600"
                      )}>{record.stages.static.severity || "NONE"}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-stone-400">{t("report.stage.elapsed")}</span>
                      <span className="font-mono text-stone-500">{latency.static.toFixed(2)}s</span>
                    </div>
                  </div>
                </div>
                {/* Arrow connector - visible only on lg */}
                <div className="hidden lg:flex absolute right-0 top-1/2 -translate-y-1/2 translate-x-1/2 z-10 w-6 h-6 rounded-full bg-white border border-stone-200 items-center justify-center">
                  <svg className="w-3 h-3 text-stone-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                  </svg>
                </div>
              </div>

              {/* Stage 2: LLM */}
              <div className="relative">
                <div className={cn(
                  "card-white lg:rounded-none rounded-xl border p-5 h-full",
                  !confidenceAvailable ? "border-stone-300 bg-stone-50/50"
                    : confidence >= 0.8 ? "border-red-200" : confidence >= 0.5 ? "border-amber-200" : "border-emerald-200"
                )}>
                  <div className="flex items-center gap-2 mb-3">
                    <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center",
                      confidenceAvailable ? "bg-violet-100 text-violet-600" : "bg-stone-200 text-stone-400"
                    )}>
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
                      </svg>
                    </div>
                    <div>
                      <span className="text-[10px] font-mono font-bold text-violet-500">STAGE 2</span>
                      <div className="text-sm font-bold text-stone-700">{t("report.stage.llm")}</div>
                    </div>
                  </div>
                  {confidenceAvailable ? (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-stone-400">{t("report.stage.confidence")}</span>
                        <span className={cn("font-bold font-mono",
                          confidence >= 0.8 ? "text-red-600" : confidence >= 0.5 ? "text-amber-600" : "text-emerald-600"
                        )}>{(confidence * 100).toFixed(0)}%</span>
                      </div>
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-stone-400">{t("report.stage.elapsed")}</span>
                        <span className="font-mono text-stone-500">{latency.llm.toFixed(2)}s</span>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-stone-400">{t("report.stage.status")}</span>
                        <span className="font-bold text-amber-500">{t("report.score.failed")}</span>
                      </div>
                      <div className="mt-2 p-2 rounded-lg bg-amber-50 border border-amber-100">
                        <p className="text-[11px] text-amber-600">{t("report.score.failed_detail")}</p>
                      </div>
                    </div>
                  )}
                  {record.stages.llm.reason && (
                    <div className="mt-3 p-3 rounded-lg bg-stone-50 border border-stone-100">
                      <div className="text-[10px] font-bold text-stone-400 uppercase tracking-wider mb-1">{t("report.stage.reason")}</div>
                      <p className="text-xs text-stone-600 leading-relaxed">{(isEn && (record.stages.llm.reason_en || record.warnings.find(w => w.source === "LLM 研判" && w.text_en)?.text_en?.replace(/^Safety confidence: [\d.]+ — /, ""))) || record.stages.llm.reason}</p>
                    </div>
                  )}
                </div>
                <div className="hidden lg:flex absolute right-0 top-1/2 -translate-y-1/2 translate-x-1/2 z-10 w-6 h-6 rounded-full bg-white border border-stone-200 items-center justify-center">
                  <svg className="w-3 h-3 text-stone-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                  </svg>
                </div>
              </div>

              {/* Stage 3: Runtime */}
              <div className="relative">
                <div className={cn(
                  "card-white rounded-r-xl lg:rounded-l-none rounded-xl lg:rounded-br-xl border p-5 h-full",
                  record.stages.runtime.status === "BLOCKED" ? "border-red-200"
                    : record.stages.runtime.status === "PASSED" || record.stages.runtime.status === "SAFE" ? "border-emerald-200"
                    : "border-stone-200"
                )}>
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-8 h-8 rounded-lg bg-amber-100 text-amber-600 flex items-center justify-center">
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7" />
                      </svg>
                    </div>
                    <div>
                      <span className="text-[10px] font-mono font-bold text-amber-500">STAGE 3</span>
                      <div className="text-sm font-bold text-stone-700">{t("report.stage.runtime")}</div>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-stone-400">{t("report.stage.status")}</span>
                      <span className={cn("font-bold",
                        record.stages.runtime.status === "BLOCKED" ? "text-red-600"
                          : record.stages.runtime.status === "PASSED" || record.stages.runtime.status === "SAFE" ? "text-emerald-600"
                          : "text-stone-600"
                      )}>{record.stages.runtime.status}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-stone-400">{t("report.stage.exec_time")}</span>
                      <span className="font-mono text-stone-500">{record.stages.runtime.elapsed.toFixed(1)}s</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-stone-400">{t("report.sandbox.hits")}</span>
                      <span className={cn("font-bold font-mono",
                        record.stages.runtime.blacklist_hits > 0 ? "text-red-600" : "text-stone-500"
                      )}>{record.stages.runtime.blacklist_hits}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-stone-400">{t("report.stage.blocks")}</span>
                      <span className={cn("font-bold font-mono",
                        record.stages.runtime.blocks > 0 ? "text-red-600" : "text-stone-500"
                      )}>{record.stages.runtime.blocks}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* ── False Negative alert ── */}
          {record.false_negative && (
            <div className="mb-8 p-5 rounded-xl bg-amber-50 border border-amber-200">
              <div className="flex items-start gap-3">
                <div className="w-8 h-8 shrink-0 rounded-lg bg-amber-100 flex items-center justify-center">
                  <svg className="w-4 h-4 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-sm font-bold text-amber-800 mb-1">{t("report.fn.title")}</h3>
                  <p className="text-xs text-amber-700 leading-relaxed">
                    {t("report.fn.desc")}
                  </p>
                </div>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
            {/* Left column: Threats + Capabilities */}
            <div className="lg:col-span-2 space-y-8">

              {/* ── Threat details ── */}
              {record.warnings.length > 0 && (
                <div>
                  <h2 className="text-sm font-bold text-stone-800 mb-4 flex items-center gap-2">
                    <svg className="w-4 h-4 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                    </svg>
                    {t("report.threats.title")}
                    <span className="text-[10px] font-mono text-stone-400 ml-1">({record.warnings.length})</span>
                  </h2>

                  <div className="space-y-4">
                    {Object.entries(warningsBySource).map(([source, warnings]) => (
                      <div key={source} className="card-white rounded-xl border border-stone-200 overflow-hidden">
                        <div className="px-4 py-2.5 bg-stone-50 border-b border-stone-100">
                          <span className="text-[10px] font-bold text-stone-500 uppercase tracking-wider">{source}</span>
                        </div>
                        <div className="divide-y divide-stone-50">
                          {warnings.map((w, i) => {
                            const lc = getLevelConfig(w.level);
                            return (
                              <div key={i} className="px-4 py-3 flex items-start gap-3">
                                <span className={cn(
                                  "shrink-0 text-[10px] font-bold px-2 py-0.5 rounded-md mt-0.5",
                                  lc.bg, lc.text
                                )}>
                                  {lc.label}
                                </span>
                                <p className="text-xs text-stone-600 leading-relaxed">{(isEn && w.text_en) || w.text}</p>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Static Evidence (per-finding file + line + snippet) ── */}
              {record.stages.static.findings_list && record.stages.static.findings_list.length > 0 && (
                <div>
                  <h2 className="text-sm font-bold text-stone-800 mb-4 flex items-center gap-2">
                    <svg className="w-4 h-4 text-orange-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
                    </svg>
                    {isEn ? "Detection Evidence" : "检测证据"}
                    <span className="text-[10px] font-mono text-stone-400 ml-1">({record.stages.static.findings_list.length})</span>
                  </h2>

                  <div className="space-y-3">
                    {record.stages.static.findings_list.map((f, i) => {
                      const sevColor =
                        f.severity === "CRITICAL" ? "bg-red-100 text-red-700 border-red-200" :
                        f.severity === "HIGH" ? "bg-orange-100 text-orange-700 border-orange-200" :
                        f.severity === "MEDIUM" ? "bg-amber-100 text-amber-700 border-amber-200" :
                        "bg-stone-100 text-stone-600 border-stone-200";
                      return (
                        <div key={i} className="card-white rounded-xl border border-stone-200 overflow-hidden">
                          <div className="px-4 py-2.5 bg-stone-50 border-b border-stone-100 flex items-center gap-2">
                            <span className={cn("text-[10px] font-bold px-2 py-0.5 rounded border", sevColor)}>
                              {f.severity}
                            </span>
                            <span className="text-xs font-semibold text-stone-700 truncate">{f.title}</span>
                            <span className="text-[10px] font-mono text-stone-400 ml-auto shrink-0">{f.rule_id}</span>
                          </div>
                          <div className="px-4 py-3 space-y-2">
                            <p className="text-xs text-stone-500 leading-relaxed">{f.description}</p>
                            {(f.file_path || f.line_number) && (
                              <div className="flex items-center gap-1.5 text-[11px] font-mono text-blue-600">
                                <svg className="w-3 h-3 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                  <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                                </svg>
                                <span>{f.file_path || ""}{f.line_number ? `:${f.line_number}` : ""}</span>
                              </div>
                            )}
                            {f.snippet && (
                              <pre className="text-[11px] font-mono bg-stone-950 text-red-300 rounded-lg px-3 py-2 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed border border-stone-800">
                                {f.snippet}
                              </pre>
                            )}
                            {f.remediation && (
                              <p className="text-[11px] text-emerald-700 bg-emerald-50 rounded-lg px-3 py-2 border border-emerald-100">
                                {isEn ? "Fix: " : "修复建议："}{f.remediation}
                              </p>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

            </div>

            {/* Right column: Capabilities + Recommendations */}
            <div className="space-y-8">

              {/* ── Capabilities ── */}
              {record.capabilities && record.capabilities.length > 0 && (
                <div>
                  <h2 className="text-sm font-bold text-stone-800 mb-4 flex items-center gap-2">
                    <svg className="w-4 h-4 text-violet-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23.693L5 14.5m14.8.8l1.402 1.402c1.232 1.232.65 3.318-1.067 3.611A48.309 48.309 0 0112 21c-2.773 0-5.491-.235-8.135-.687-1.718-.293-2.3-2.379-1.067-3.61L5 14.5" />
                    </svg>
                    {t("report.capabilities.title")}
                  </h2>

                  <div className="card-white rounded-xl border border-stone-200 p-4">
                    <div className="flex flex-wrap gap-2">
                      {record.capabilities.map((cap) => {
                        const isHighRisk = ["exec", "run", "write", "edit", "network", "http", "fetch", "web_fetch"].some(
                          (k) => cap.toLowerCase().includes(k)
                        );
                        return (
                          <span
                            key={cap}
                            className={cn(
                              "text-xs font-semibold px-2.5 py-1 rounded-lg border",
                              isHighRisk
                                ? "bg-red-50 text-red-600 border-red-200"
                                : "bg-stone-50 text-stone-600 border-stone-200"
                            )}
                          >
                            {cap}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}

              {/* ── Recommendations ── */}
              {record.recommendations && record.recommendations.length > 0 && (
                <div>
                  <h2 className="text-sm font-bold text-stone-800 mb-4 flex items-center gap-2">
                    <svg className="w-4 h-4 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    {t("report.rec.unsafe")}
                  </h2>

                  <div className="space-y-2">
                    {(isEn && record.recommendations_en ? record.recommendations_en : record.recommendations).map((rec, i) => (
                      <div key={i} className="card-white rounded-xl border border-stone-200 p-4">
                        <div className="flex items-start gap-3">
                          <span className="shrink-0 w-5 h-5 rounded-full bg-emerald-100 text-emerald-600 flex items-center justify-center text-[10px] font-bold mt-0.5">
                            {i + 1}
                          </span>
                          <p className="text-xs text-stone-600 leading-relaxed">{rec}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}

/** Nav bar component matching the design of other pages */
function NavBar() {
  const { t } = useI18n();
  return (
    <nav className="shrink-0">
      <div className="accent-line" />
      <div className="nav-dark">
        <div className="max-w-7xl mx-auto px-8 h-14 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-400 to-teal-500 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <svg className="w-4.5 h-4.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <div>
              <span className="font-bold text-sm tracking-wider text-white uppercase">{t("nav.title")}</span>
            </div>
          </Link>

          <div className="flex items-center gap-6">
            <Link href="/" className="text-xs font-semibold px-4 py-1.5 rounded-lg text-stone-400 hover:text-white transition-all">
              {t("nav.submit")}
            </Link>
            <Link href="/batch" className="text-xs font-semibold px-4 py-1.5 rounded-lg text-stone-400 hover:text-white transition-all">
              {t("nav.batch")}
            </Link>
            <Link href="/history" className="text-xs font-semibold px-4 py-1.5 rounded-lg text-stone-400 hover:text-white transition-all">
              {t("nav.history")}
            </Link>
            <LanguageToggle />
            <div className="flex items-center gap-2 text-xs text-stone-500 font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              {t("nav.online")}
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}
