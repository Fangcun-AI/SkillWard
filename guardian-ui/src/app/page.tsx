"use client";

import { useState, useCallback, useRef, useEffect } from "react";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useI18n, LanguageToggle } from "@/lib/i18n";
import { UploadPanel, type ScanConfig, type ScanMode, type SubmitMode } from "@/components/upload-panel";
import { ScanModal } from "@/components/scan-modal";

const API_BASE = process.env.NEXT_PUBLIC_GUARDIAN_API || "http://localhost:8899";

interface SkillResult {
  skill_name: string;
  verdict: string;
  false_negative: boolean;
  latency: number;
  findings: number;
  progress: number;
}

interface BatchSummary {
  batch_id: string;
  total_skills: number;
  scanned: number;
  safe: number;
  unsafe: number;
  error: number;
  false_negatives: number;
  latency_total: number;
  latency_avg: number;
}

const VERDICT_STYLES: Record<string, { bg: string; text: string }> = {
  PASSED: { bg: "bg-emerald-50", text: "text-emerald-600" },
  SAFE: { bg: "bg-emerald-50", text: "text-emerald-600" },
  BLOCKED: { bg: "bg-red-50", text: "text-red-600" },
  ALERT: { bg: "bg-amber-50", text: "text-amber-600" },
  CAPABILITY_RISK: { bg: "bg-orange-50", text: "text-orange-600" },
  CONTENT_RISK: { bg: "bg-orange-50", text: "text-orange-600" },
  UNSAFE: { bg: "bg-red-50", text: "text-red-600" },
  ERROR: { bg: "bg-stone-50", text: "text-stone-500" },
  TIMEOUT: { bg: "bg-stone-50", text: "text-stone-500" },
  INCONCLUSIVE: { bg: "bg-amber-50", text: "text-amber-600" },
  // New unified terminology
  "Safe": { bg: "bg-emerald-50", text: "text-emerald-600" },
  "Medium Risk": { bg: "bg-amber-50", text: "text-amber-600" },
  "High Risk": { bg: "bg-red-50", text: "text-red-600" },
  INCOMPLETE: { bg: "bg-stone-50", text: "text-stone-500" },
  SANDBOX_FAILED: { bg: "bg-stone-50", text: "text-stone-500" },
};

export default function Home() {
  const { t, locale } = useI18n();
  const router = useRouter();

  // Single scan state
  const [isScanning, setIsScanning] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [skillPath, setSkillPath] = useState<string | undefined>(undefined);
  const [scanConfig, setScanConfig] = useState<ScanConfig>({
    policy: "balanced", useLlm: true, useRuntime: true, enableAfterTool: true,
  });
  const [scanMode, setScanMode] = useState<ScanMode>("sandbox");
  const [submitMode, setSubmitMode] = useState<SubmitMode>("single");

  // Batch scan state
  const [batchScanning, setBatchScanning] = useState(false);
  const [batchResults, setBatchResults] = useState<SkillResult[]>([]);
  const [batchSummary, setBatchSummary] = useState<BatchSummary | null>(null);
  const [batchTotal, setBatchTotal] = useState(0);
  const [batchScanned, setBatchScanned] = useState(0);
  const [batchError, setBatchError] = useState("");
  const [batchLogs, setBatchLogs] = useState<string[]>([]);
  const [filterVerdict, setFilterVerdict] = useState("all");
  const [historyMap, setHistoryMap] = useState<Record<string, string>>({});
  const logsEndRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  const handleSubmit = useCallback((path: string | undefined, config: ScanConfig) => {
    setSkillPath(path);
    setScanConfig(config);
    setIsScanning(true);
    setModalOpen(true);
    if (!path) {
      setTimeout(() => { setIsScanning(false); }, 45000);
    }
  }, []);

  const handleBatchStart = useCallback((skillsDir: string, concurrency: number, config: ScanConfig) => {
    setBatchScanning(true);
    setBatchResults([]);
    setBatchSummary(null);
    setBatchTotal(0);
    setBatchScanned(0);
    setBatchError("");
    setBatchLogs([]);

    const batchId = `batch-${Date.now().toString(36)}`;
    const params = new URLSearchParams({
      skills_dir: skillsDir,
      concurrency: String(concurrency),
      use_llm: String(config.useLlm),
      use_runtime: String(config.useRuntime),
      enable_after_tool: String(config.enableAfterTool),
      lang: locale,
    });

    const controller = new AbortController();
    abortRef.current = controller;

    fetch(`${API_BASE}/api/batch/${batchId}/stream?${params}`, { signal: controller.signal })
      .then(async (res) => {
        if (!res.ok) { setBatchError(`HTTP ${res.status}`); setBatchScanning(false); return; }
        const reader = res.body?.getReader();
        if (!reader) return;
        const decoder = new TextDecoder();
        let buffer = "";
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";
          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            try {
              const evt = JSON.parse(line.slice(6));
              setBatchLogs((prev) => [...prev, evt.text]);
              if (evt.type === "batch_start" && evt.data) setBatchTotal(evt.data.total);
              else if (evt.type === "skill_done" && evt.data) {
                const d = evt.data as SkillResult;
                setBatchResults((prev) => { const next = [...prev, d]; try { sessionStorage.setItem("batch_results", JSON.stringify(next)); } catch {} return next; });
                setBatchScanned(d.progress);
              } else if (evt.type === "batch_done" && evt.data) {
                const s = evt.data as BatchSummary;
                setBatchSummary(s);
                try { sessionStorage.setItem("batch_summary", JSON.stringify(s)); } catch {}
              } else if (evt.type === "error") setBatchError(evt.text);
            } catch {}
          }
        }
        setBatchScanning(false);
      })
      .catch(async (err) => {
        if (err.name === "AbortError") { setBatchScanning(false); return; }
        // Connection lost — check if batch actually completed on server
        try {
          const res = await fetch(`${API_BASE}/api/batch/${batchId}`);
          const data = await res.json();
          if (data.status === "done" || data.scanned >= data.total_skills) {
            setBatchScanned(data.scanned);
            setBatchTotal(data.total_skills);
            setBatchSummary(data as BatchSummary);
            setBatchScanning(false);
            return;
          }
        } catch {}
        setBatchError("连接中断，请刷新页面查看结果");
        setBatchScanning(false);
      });
  }, []);

  const stopBatch = useCallback(() => { abortRef.current?.abort(); setBatchScanning(false); }, []);

  const handleScanComplete = useCallback(() => { setIsScanning(false); }, []);
  const handleModalClose = useCallback(() => { setModalOpen(false); setIsScanning(false); }, []);

  // Restore batch results from session
  useEffect(() => {
    try {
      const sr = sessionStorage.getItem("batch_results");
      const ss = sessionStorage.getItem("batch_summary");
      if (sr) { const p = JSON.parse(sr) as SkillResult[]; if (p.length > 0) { setBatchResults(p); setBatchScanned(p.length); setBatchTotal(p.length); } }
      if (ss) setBatchSummary(JSON.parse(ss) as BatchSummary);
    } catch {}
  }, []);

  // Fetch history map for batch result links
  useEffect(() => {
    if (batchResults.length === 0) return;
    fetch(`${API_BASE}/api/scan/history?limit=200`).then((r) => r.json()).then((data) => {
      const list = Array.isArray(data) ? data : (data.records || []);
      const map: Record<string, string> = {};
      for (const r of list) { if (r.skill_name && r.id && !map[r.skill_name]) map[r.skill_name] = r.id; }
      setHistoryMap(map);
    }).catch(() => {});
  }, [batchResults.length]);

  useEffect(() => { logsEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [batchLogs]);

  const batchProgressPct = batchTotal > 0 ? Math.round((batchScanned / batchTotal) * 100) : 0;
  const filteredResults = filterVerdict === "all" ? batchResults : batchResults.filter((r) => {
    if (filterVerdict === "safe") return ["PASSED", "SAFE", "Safe"].includes(r.verdict);
    if (filterVerdict === "unsafe") return !["PASSED", "SAFE", "Safe", "ERROR", "TIMEOUT", "INCOMPLETE", "SANDBOX_FAILED"].includes(r.verdict);
    if (filterVerdict === "error") return ["ERROR", "TIMEOUT", "INCOMPLETE", "SANDBOX_FAILED"].includes(r.verdict);
    return true;
  });
  const verdictLabel = (v: string) => {
    const map: Record<string, string> = {
      PASSED: t("batch.verdict.safe"), SAFE: t("batch.verdict.safe"),
      BLOCKED: t("batch.verdict.danger"), UNSAFE: t("batch.verdict.danger"),
      CAPABILITY_RISK: t("batch.verdict.risk"), CONTENT_RISK: t("batch.verdict.risk"),
      ALERT: t("batch.verdict.warn"),
      ERROR: t("batch.verdict.error"), TIMEOUT: t("batch.verdict.timeout"),
      // New unified terminology
      "Safe": t("batch.verdict.safe"),
      "Medium Risk": t("batch.verdict.warn"),
      "High Risk": t("batch.verdict.danger"),
      INCOMPLETE: t("batch.verdict.timeout"),
      SANDBOX_FAILED: t("batch.verdict.error"),
    };
    return map[v] || v;
  };

  const stages = [
    { key: "static", stage: t("stage.1.label"), name: t("stage.1.name"), desc: t("stage.1.desc"), icon: (<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m5.231 13.481L15 17.25m-4.5-15H5.625c-.621 0-1.125.504-1.125 1.125v16.5c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9zm3.75 11.625a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" /></svg>), activeIn: ["static", "sandbox", "deep"] },
    { key: "llm", stage: t("stage.2.label"), name: t("stage.2.name"), desc: t("stage.2.desc"), icon: (<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" /></svg>), activeIn: ["static", "sandbox", "deep"] },
    { key: "sandbox", stage: t("stage.3.label"), name: t("stage.3.name"), desc: t("stage.3.desc"), icon: (<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7" /></svg>), activeIn: ["sandbox", "deep"] },
  ];

  return (
    <div className="min-h-screen bg-warm flex flex-col">
      {/* Nav Bar */}
      <nav className="shrink-0">
        <div className="nav-light bg-white/90 backdrop-blur-sm border-b border-stone-200">
          <div className="max-w-7xl mx-auto px-8 h-14 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <img src="/logo.jpg" alt="SkillWard" className="w-8 h-8 rounded-lg object-cover" />
              <div>
                <span className="font-bold text-sm tracking-wider text-stone-800 uppercase">{t("nav.title")}</span>
              </div>
            </div>

            <div className="flex items-center gap-6">
              <span className="text-xs font-semibold px-4 py-1.5 rounded-lg bg-violet-600 text-white">
                {t("nav.submit")}
              </span>
              <Link
                href="/history"
                className="text-xs font-semibold px-4 py-1.5 rounded-lg text-stone-500 hover:text-violet-600 transition-all"
              >
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

      {/* Content */}
      <div className="flex-1 flex flex-col">
        {/* Hero */}
        <div className="text-center pt-12 pb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-violet-50 border border-violet-200 mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-violet-500" />
            <span className="text-[11px] font-semibold text-violet-700 uppercase tracking-wider">{t("hero.badge")}</span>
          </div>
          <h1 className="text-4xl font-bold tracking-tight text-stone-800 mb-2">
            {t("hero.title_pre")}<span className="text-violet-600">{t("hero.title_accent")}</span>{t("hero.title_post")}
          </h1>
          <p className="text-sm text-stone-400 max-w-lg mx-auto">
            {t("hero.desc")}
          </p>
        </div>

        {/* Upload panel */}
        <div className="max-w-6xl mx-auto px-8 w-full pb-8">
          <UploadPanel
            onSubmit={handleSubmit}
            onBatchStart={handleBatchStart}
            isScanning={isScanning || batchScanning}
            onScanModeChange={setScanMode}
            onSubmitModeChange={setSubmitMode}
          />
        </div>

        {/* Batch results section */}
        {submitMode === "batch" && (batchScanning || batchResults.length > 0 || batchError) && (
          <div className="max-w-6xl mx-auto px-8 w-full pb-24">
            {/* Stop button */}
            {batchScanning && (
              <div className="flex justify-end mb-4">
                <button onClick={stopBatch} className="px-4 py-2 rounded-lg bg-red-600 text-white text-xs font-bold hover:bg-red-700 transition-all">
                  {t("batch.stop")}
                </button>
              </div>
            )}

            {/* Progress */}
            {(batchScanning || batchSummary) && batchTotal > 0 && (
              <div className="card-white rounded-xl border border-stone-200 p-6 mb-6">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm font-bold text-stone-700">{batchScanning ? t("batch.scanning") : t("batch.complete")}</span>
                  <span className="text-sm font-mono text-stone-500">{batchScanned} / {batchTotal} ({batchProgressPct}%)</span>
                </div>
                <div className="h-2.5 bg-stone-100 rounded-full overflow-hidden">
                  <div className={cn("h-full rounded-full transition-all duration-300", batchScanning ? "bg-violet-500" : "bg-emerald-500")} style={{ width: `${batchProgressPct}%` }} />
                </div>
                {batchSummary && (
                  <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 mt-5">
                    {[
                      { label: t("batch.stat.total"), value: batchSummary.total_skills, color: "text-stone-700" },
                      { label: t("batch.stat.safe"), value: batchSummary.safe, color: "text-emerald-600" },
                      { label: t("batch.stat.unsafe"), value: batchSummary.unsafe, color: "text-red-600" },
                      { label: t("batch.stat.error"), value: batchSummary.error, color: "text-stone-500" },
                      { label: t("batch.stat.fn"), value: batchSummary.false_negatives, color: "text-amber-600" },
                      { label: t("batch.stat.avg_latency"), value: `${batchSummary.latency_avg}s`, color: "text-violet-600" },
                    ].map((c) => (
                      <div key={c.label} className="bg-stone-50 rounded-lg p-3 text-center">
                        <div className={cn("text-xl font-bold font-mono", c.color)}>{c.value}</div>
                        <div className="text-[10px] font-semibold text-stone-400 uppercase tracking-wider mt-0.5">{c.label}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Error */}
            {batchError && (
              <div className="mb-6 p-4 rounded-xl bg-red-50 border border-red-200 text-red-600 text-sm">{batchError}</div>
            )}

            {/* Results table */}
            {batchResults.length > 0 && (
              <div className="card-white rounded-xl border border-stone-200 overflow-hidden mb-6">
                <div className="px-6 py-3 border-b border-stone-100 flex items-center justify-between">
                  <span className="text-sm font-bold text-stone-700">{t("batch.results")} ({filteredResults.length})</span>
                  <div className="flex items-center gap-1.5">
                    {["all", "safe", "unsafe", "error"].map((f) => (
                      <button key={f} onClick={() => setFilterVerdict(f)} className={cn("text-[11px] font-semibold px-3 py-1 rounded-md transition-all", filterVerdict === f ? "bg-violet-600 text-white" : "text-stone-400 hover:text-stone-600 hover:bg-stone-100")}>
                        {t(`batch.filter.${f}` as Parameters<typeof t>[0])}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="bg-stone-50/80">
                        <th className="text-left px-6 py-2.5 text-[10px] font-bold text-stone-400 uppercase tracking-wider">#</th>
                        <th className="text-left px-6 py-2.5 text-[10px] font-bold text-stone-400 uppercase tracking-wider">{t("batch.col.name")}</th>
                        <th className="text-left px-6 py-2.5 text-[10px] font-bold text-stone-400 uppercase tracking-wider">{t("batch.col.verdict")}</th>
                        <th className="text-left px-6 py-2.5 text-[10px] font-bold text-stone-400 uppercase tracking-wider">{t("batch.col.findings")}</th>
                        <th className="text-left px-6 py-2.5 text-[10px] font-bold text-stone-400 uppercase tracking-wider">{t("batch.col.latency")}</th>
                        <th className="text-left px-6 py-2.5 text-[10px] font-bold text-stone-400 uppercase tracking-wider">{t("batch.col.fn")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredResults.map((r, i) => {
                        const vs = VERDICT_STYLES[r.verdict] || VERDICT_STYLES.ERROR;
                        return (
                          <tr key={`${r.skill_name}-${i}`} className={cn("border-t border-stone-50 hover:bg-stone-50/50 transition-colors", historyMap[r.skill_name] && "cursor-pointer")} onClick={() => { const rid = historyMap[r.skill_name]; if (rid) router.push(`/scan/${rid}`); }}>
                            <td className="px-6 py-2.5 text-stone-300 font-mono text-xs">{i + 1}</td>
                            <td className="px-6 py-2.5 font-semibold text-stone-700">{r.skill_name}</td>
                            <td className="px-6 py-2.5"><span className={cn("text-[10px] font-bold px-2 py-0.5 rounded-md", vs.bg, vs.text)}>{verdictLabel(r.verdict)}</span></td>
                            <td className="px-6 py-2.5 font-mono text-stone-500">{r.findings}</td>
                            <td className="px-6 py-2.5 font-mono text-violet-600">{r.latency}s</td>
                            <td className="px-6 py-2.5">{r.false_negative && <span className="text-[10px] font-bold px-2 py-0.5 rounded-md bg-amber-50 text-amber-600">FN</span>}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Logs */}
            {batchLogs.length > 0 && (
              <div className="card-white rounded-xl border border-stone-200 overflow-hidden">
                <div className="px-6 py-3 border-b border-stone-100">
                  <span className="text-xs font-bold text-stone-400 uppercase tracking-wider">{t("batch.log")}</span>
                </div>
                <div className="p-4 max-h-48 overflow-y-auto bg-stone-900 rounded-b-xl">
                  {batchLogs.map((line, i) => (
                    <div key={i} className="text-[11px] font-mono text-stone-400 leading-relaxed">
                      <span className="text-stone-600 mr-2">{String(i + 1).padStart(3, " ")}</span>{line}
                    </div>
                  ))}
                  <div ref={logsEndRef} />
                </div>
              </div>
            )}
          </div>
        )}

        {/* Pipeline stages (only show in single mode) */}
        {submitMode === "single" && (
          <div className="max-w-6xl mx-auto px-8 w-full pb-24">
            <div className="text-xs font-bold text-stone-400 uppercase tracking-wider mb-4 px-1">{t("pipeline.title")}</div>
            <div className="flex items-stretch gap-0">
              {stages.map((s, i, arr) => {
                const active = s.activeIn.includes(scanMode);
                return (
                  <div key={s.key} className="flex items-stretch flex-1">
                    <div className={cn(
                      "flex-1 rounded-lg px-4 py-4 transition-all duration-300",
                      active ? "bg-white border border-violet-200 shadow-sm" : "bg-stone-100/60 border border-transparent"
                    )}>
                      <div className="flex items-center gap-2 mb-2">
                        <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center transition-colors duration-300", active ? "bg-violet-100 text-violet-600" : "bg-stone-200/80 text-stone-400")}>{s.icon}</div>
                        <span className={cn("text-[10px] font-mono font-bold transition-colors duration-300", active ? "text-violet-500" : "text-stone-300")}>{s.stage}</span>
                      </div>
                      <div className={cn("text-sm font-bold mb-1 transition-colors duration-300", active ? "text-stone-700" : "text-stone-400")}>{s.name}</div>
                      <p className={cn("text-[11px] leading-relaxed transition-colors duration-300", active ? "text-stone-500" : "text-stone-300")}>{s.desc}</p>
                    </div>
                    {i < arr.length - 1 && (
                      <div className="flex items-center px-1.5 shrink-0">
                        <svg className={cn("w-4 h-4 transition-colors duration-300", active && arr[i+1].activeIn.includes(scanMode) ? "text-violet-400" : "text-stone-300")} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" /></svg>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      <ScanModal isOpen={modalOpen} onClose={handleModalClose} isScanning={isScanning} skillPath={skillPath} config={scanConfig} onScanComplete={handleScanComplete} />
    </div>
  );
}
