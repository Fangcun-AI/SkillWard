"use client";

import { useState, useRef, useCallback, useEffect } from "react";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { useI18n, LanguageToggle } from "@/lib/i18n";

const API_BASE = process.env.NEXT_PUBLIC_GUARDIAN_API || "http://localhost:8899";

interface SkillResult {
  skill_name: string;
  verdict: string;
  false_negative: boolean;
  latency: number;
  findings: number;
  progress: number;
  error?: string;
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

const VERDICT_STYLES: Record<string, { bg: string; text: string; border: string }> = {
  PASSED: { bg: "bg-emerald-50", text: "text-emerald-600", border: "border-emerald-200" },
  SAFE: { bg: "bg-emerald-50", text: "text-emerald-600", border: "border-emerald-200" },
  BLOCKED: { bg: "bg-red-50", text: "text-red-600", border: "border-red-200" },
  ALERT: { bg: "bg-amber-50", text: "text-amber-600", border: "border-amber-200" },
  CAPABILITY_RISK: { bg: "bg-orange-50", text: "text-orange-600", border: "border-orange-200" },
  CONTENT_RISK: { bg: "bg-orange-50", text: "text-orange-600", border: "border-orange-200" },
  UNSAFE: { bg: "bg-red-50", text: "text-red-600", border: "border-red-200" },
  ERROR: { bg: "bg-stone-50", text: "text-stone-500", border: "border-stone-200" },
  TIMEOUT: { bg: "bg-stone-50", text: "text-stone-500", border: "border-stone-200" },
  INCONCLUSIVE: { bg: "bg-amber-50", text: "text-amber-600", border: "border-amber-200" },
};

export default function BatchPage() {
  const { t } = useI18n();
  const router = useRouter();
  const [historyMap, setHistoryMap] = useState<Record<string, string>>({});
  const [skillsDir, setSkillsDir] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [discoveredSkills, setDiscoveredSkills] = useState<number>(0);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [concurrency, setConcurrency] = useState(6);
  const [scanMode, setScanMode] = useState<"static" | "sandbox" | "deep">("deep");
  const useLlm = true;
  const useRuntime = scanMode === "sandbox" || scanMode === "deep";
  const enableAfterTool = scanMode === "deep";

  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<SkillResult[]>([]);
  const [summary, setSummary] = useState<BatchSummary | null>(null);
  const [totalSkills, setTotalSkills] = useState(0);
  const [scannedCount, setScannedCount] = useState(0);
  const [errorMsg, setErrorMsg] = useState("");
  const [logs, setLogs] = useState<string[]>([]);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  // Filter state
  const [filterVerdict, setFilterVerdict] = useState<string>("all");

  const startScan = useCallback(async () => {
    let dir = skillsDir.trim();

    // If file selected, upload first
    if (selectedFile && !dir) {
      setUploading(true);
      setErrorMsg("");
      try {
        const formData = new FormData();
        formData.append("file", selectedFile);
        const uploadRes = await fetch(`${API_BASE}/api/batch/upload`, { method: "POST", body: formData });
        if (!uploadRes.ok) { setErrorMsg(`Upload failed: HTTP ${uploadRes.status}`); setUploading(false); return; }
        const uploadData = await uploadRes.json();
        dir = uploadData.skills_dir;
        setSkillsDir(dir);
        setDiscoveredSkills(uploadData.skill_count || 0);
      } catch (err: unknown) {
        setErrorMsg(`Upload failed: ${err instanceof Error ? err.message : String(err)}`);
        setUploading(false);
        return;
      }
      setUploading(false);
    }

    if (!dir) return;
    setScanning(true);
    setResults([]);
    setSummary(null);
    setTotalSkills(0);
    setScannedCount(0);
    setErrorMsg("");
    setLogs([]);

    const batchId = `batch-${Date.now().toString(36)}`;
    const params = new URLSearchParams({
      skills_dir: dir,
      concurrency: String(concurrency),
      use_llm: String(useLlm),
      use_runtime: String(useRuntime),
      enable_after_tool: String(enableAfterTool),
    });

    const controller = new AbortController();
    abortRef.current = controller;

    const url = `${API_BASE}/api/batch/${batchId}/stream?${params}`;

    fetch(url, { signal: controller.signal })
      .then(async (res) => {
        if (!res.ok) {
          setErrorMsg(`HTTP ${res.status}`);
          setScanning(false);
          return;
        }
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
              handleSSE(evt);
            } catch {
              // ignore parse errors
            }
          }
        }
        setScanning(false);
      })
      .catch((err) => {
        if (err.name !== "AbortError") {
          setErrorMsg(err.message);
        }
        setScanning(false);
      });
  }, [skillsDir, selectedFile, concurrency, scanMode]);

  const handleSSE = useCallback((evt: { stage: number; type: string; text: string; data?: Record<string, unknown> }) => {
    setLogs((prev) => [...prev, evt.text]);

    if (evt.type === "batch_start" && evt.data) {
      setTotalSkills(evt.data.total as number);
    } else if (evt.type === "skill_done" && evt.data) {
      const d = evt.data as unknown as SkillResult;
      setResults((prev) => {
        const next = [...prev, d];
        try { sessionStorage.setItem("batch_results", JSON.stringify(next)); } catch {}
        return next;
      });
      setScannedCount(d.progress);
    } else if (evt.type === "batch_done" && evt.data) {
      const s = evt.data as unknown as BatchSummary;
      setSummary(s);
      try { sessionStorage.setItem("batch_summary", JSON.stringify(s)); } catch {}
    } else if (evt.type === "error") {
      setErrorMsg(evt.text);
    }
  }, []);

  const stopScan = useCallback(() => {
    abortRef.current?.abort();
    setScanning(false);
  }, []);

  // Restore previous scan results from sessionStorage on mount
  useEffect(() => {
    try {
      const savedResults = sessionStorage.getItem("batch_results");
      const savedSummary = sessionStorage.getItem("batch_summary");
      if (savedResults) {
        const parsed = JSON.parse(savedResults) as SkillResult[];
        if (parsed.length > 0) {
          setResults(parsed);
          setScannedCount(parsed.length);
          setTotalSkills(parsed.length);
        }
      }
      if (savedSummary) {
        setSummary(JSON.parse(savedSummary) as BatchSummary);
      }
    } catch {}
  }, []);

  // Fetch history to map skill_name -> id for linking to detail pages
  useEffect(() => {
    if (results.length === 0) return;
    fetch(`${API_BASE}/api/scan/history?limit=200`)
      .then((res) => res.json())
      .then((data) => {
        const list = Array.isArray(data) ? data : (data.records || []);
        const map: Record<string, string> = {};
        for (const r of list) {
          if (r.skill_name && r.id && !map[r.skill_name]) {
            map[r.skill_name] = r.id;  // keep first (newest) match only
          }
        }
        setHistoryMap(map);
      })
      .catch(() => {});
  }, [results.length]);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const progressPct = totalSkills > 0 ? Math.round((scannedCount / totalSkills) * 100) : 0;

  const filteredResults = filterVerdict === "all"
    ? results
    : results.filter((r) => {
        if (filterVerdict === "safe") return r.verdict === "PASSED" || r.verdict === "SAFE";
        if (filterVerdict === "unsafe") return !["PASSED", "SAFE", "ERROR", "TIMEOUT"].includes(r.verdict);
        if (filterVerdict === "error") return r.verdict === "ERROR" || r.verdict === "TIMEOUT";
        return true;
      });

  const verdictLabel = (v: string) => {
    const map: Record<string, string> = {
      PASSED: t("batch.verdict.safe"), SAFE: t("batch.verdict.safe"),
      BLOCKED: t("batch.verdict.danger"), UNSAFE: t("batch.verdict.danger"),
      CAPABILITY_RISK: t("batch.verdict.risk"), CONTENT_RISK: t("batch.verdict.risk"),
      ALERT: t("batch.verdict.warn"),
      ERROR: t("batch.verdict.error"), TIMEOUT: t("batch.verdict.timeout"),
      INCONCLUSIVE: "未确定",
    };
    return map[v] || v;
  };

  return (
    <div className="min-h-screen bg-warm flex flex-col">
      {/* Nav */}
      <nav className="shrink-0">

        <div className="nav-light bg-white/90 backdrop-blur-sm border-b border-stone-200">
          <div className="max-w-7xl mx-auto px-8 h-14 flex items-center justify-between">
            <Link href="/" className="flex items-center gap-3">
              <img src="/logo.jpg" alt="SkillWard" className="w-8 h-8 rounded-lg object-cover" />
              <div>
                <span className="font-bold text-sm tracking-wider text-stone-800 uppercase">{t("nav.title")}</span>
              </div>
            </Link>

            <div className="flex items-center gap-6">
              <Link href="/" className="text-xs font-semibold px-4 py-1.5 rounded-lg text-stone-400 hover:text-white transition-all">
                {t("nav.submit")}
              </Link>
              <span className="text-xs font-semibold px-4 py-1.5 rounded-lg bg-violet-600 text-white">
                {t("nav.batch")}
              </span>
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

      {/* Content */}
      <div className="flex-1">
        <div className="max-w-6xl mx-auto px-8 py-10">
          {/* Title */}
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-stone-800 mb-2">{t("batch.title")}</h1>
            <p className="text-sm text-stone-400">{t("batch.subtitle")}</p>
          </div>

          {/* Upload + Controls */}
          <div className="flex gap-6 mb-8">
            {/* Left: Upload zone */}
            <div className="flex-1 card-white rounded-xl border border-stone-200 p-6">
              <input
                ref={fileInputRef}
                type="file"
                accept=".zip,.tar.gz,.tgz"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) { setSelectedFile(file); setSkillsDir(""); setDiscoveredSkills(0); }
                }}
                disabled={scanning || uploading}
              />
              <div
                onClick={() => fileInputRef.current?.click()}
                className={cn(
                  "drop-zone rounded-xl flex flex-col items-center justify-center py-16 px-6 cursor-pointer group border-2 border-dashed border-stone-200 hover:border-violet-400 bg-stone-50/50 hover:bg-violet-50/30 transition-all",
                  (scanning || uploading) && "opacity-50 pointer-events-none"
                )}
              >
                {selectedFile ? (
                  <>
                    <div className="w-14 h-14 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center mb-4">
                      <svg className="w-7 h-7 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                    <p className="text-sm text-stone-700 font-semibold mb-1">{selectedFile.name}</p>
                    <p className="text-xs text-stone-400 font-mono">{(selectedFile.size / 1024 / 1024).toFixed(1)} MB</p>
                    <button
                      onClick={(e) => { e.stopPropagation(); setSelectedFile(null); setSkillsDir(""); setDiscoveredSkills(0); if (fileInputRef.current) fileInputRef.current.value = ""; }}
                      className="mt-3 text-xs text-stone-400 hover:text-red-500 transition-colors"
                    >
                      {t("upload.drop.remove")}
                    </button>
                  </>
                ) : (
                  <>
                    <div className="w-14 h-14 rounded-xl bg-violet-50 border border-violet-200 flex items-center justify-center mb-4 group-hover:scale-105 transition-transform">
                      <svg className="w-7 h-7 text-violet-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5m8.25 3v6.75m0 0l-3-3m3 3l3-3M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125z" />
                      </svg>
                    </div>
                    <p className="text-sm text-stone-500 mb-2">{t("batch.dir_placeholder")}</p>
                    <p className="text-xs text-stone-400 font-mono">
                      <span className="text-stone-600">.zip</span> · <span className="text-stone-600">.tar.gz</span> · <span className="text-stone-600">.tgz</span>
                    </p>
                  </>
                )}
              </div>
            </div>

            {/* Right: Controls */}
            <div className="w-[280px] shrink-0 flex flex-col gap-4">
              {/* Scan mode */}
              <div className="card-white rounded-xl border border-stone-200 p-5 flex-1">
                <div className="text-xs font-bold text-violet-700 uppercase tracking-wider mb-3">{t("mode.title")}</div>
                <div className="space-y-2">
                  {([
                    { key: "static" as const, label: t("mode.static.name"), sub: "~10s" },
                    { key: "sandbox" as const, label: t("mode.sandbox.name"), sub: "~2-3min" },
                    { key: "deep" as const, label: t("mode.deep.name"), sub: "~2-4min" },
                  ]).map((m) => (
                    <button key={m.key}
                      onClick={() => setScanMode(m.key)}
                      disabled={scanning}
                      className={cn(
                        "w-full flex items-center justify-between px-4 py-3 rounded-lg border transition-all text-left",
                        scanMode === m.key
                          ? "border-violet-400 bg-violet-50 shadow-sm"
                          : "border-stone-200 hover:border-stone-300"
                      )}
                    >
                      <span className={cn("text-sm font-bold", scanMode === m.key ? "text-violet-700" : "text-stone-600")}>{m.label}</span>
                      <span className={cn("text-[10px] font-mono", scanMode === m.key ? "text-violet-500" : "text-stone-400")}>{m.sub}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Concurrency + Start */}
              <div className="card-white rounded-xl border border-stone-200 p-5">
                <div className="flex items-center justify-between mb-4">
                  <label className="text-xs font-bold text-stone-500">{t("batch.concurrency")}</label>
                  <select
                    value={concurrency}
                    onChange={(e) => setConcurrency(Number(e.target.value))}
                    className="px-3 py-1.5 rounded-lg border border-stone-200 bg-stone-50 text-sm font-mono"
                    disabled={scanning}
                  >
                    {[1, 2, 4, 6, 8, 12].map((n) => (
                      <option key={n} value={n}>{n}</option>
                    ))}
                  </select>
                </div>
                {!scanning ? (
                  <button
                    onClick={startScan}
                    disabled={(!selectedFile && !skillsDir.trim()) || uploading}
                    className="w-full py-3 rounded-lg bg-gradient-to-r from-violet-600 to-purple-600 text-white text-sm font-bold hover:from-violet-700 hover:to-purple-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-lg shadow-violet-600/20"
                  >
                    {uploading ? t("upload.scanning") : t("batch.start")}
                  </button>
                ) : (
                  <button
                    onClick={stopScan}
                    className="w-full py-3 rounded-lg bg-red-600 text-white text-sm font-bold hover:bg-red-700 transition-all"
                  >
                    {t("batch.stop")}
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Progress bar */}
          {(scanning || summary) && totalSkills > 0 && (
            <div className="card-white rounded-xl border border-stone-200 p-6 mb-6">
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm font-bold text-stone-700">
                  {scanning ? t("batch.scanning") : t("batch.complete")}
                </span>
                <span className="text-sm font-mono text-stone-500">
                  {scannedCount} / {totalSkills} ({progressPct}%)
                </span>
              </div>
              <div className="h-2.5 bg-stone-100 rounded-full overflow-hidden">
                <div
                  className={cn(
                    "h-full rounded-full transition-all duration-300",
                    scanning ? "bg-violet-500" : "bg-emerald-500"
                  )}
                  style={{ width: `${progressPct}%` }}
                />
              </div>

              {/* Summary cards */}
              {summary && (
                <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 mt-5">
                  <SummaryCard label={t("batch.stat.total")} value={summary.total_skills} color="text-stone-700" />
                  <SummaryCard label={t("batch.stat.safe")} value={summary.safe} color="text-emerald-600" />
                  <SummaryCard label={t("batch.stat.unsafe")} value={summary.unsafe} color="text-red-600" />
                  <SummaryCard label={t("batch.stat.error")} value={summary.error} color="text-stone-500" />
                  <SummaryCard label={t("batch.stat.fn")} value={summary.false_negatives} color="text-amber-600" />
                  <SummaryCard label={t("batch.stat.avg_latency")} value={`${summary.latency_avg}s`} color="text-violet-600" />
                </div>
              )}
            </div>
          )}

          {/* Error message */}
          {errorMsg && (
            <div className="mb-6 p-4 rounded-xl bg-red-50 border border-red-200 text-red-600 text-sm">
              {errorMsg}
            </div>
          )}

          {/* Results table */}
          {results.length > 0 && (
            <div className="card-white rounded-xl border border-stone-200 overflow-hidden mb-6">
              {/* Filter bar */}
              <div className="px-6 py-3 border-b border-stone-100 flex items-center justify-between">
                <span className="text-sm font-bold text-stone-700">
                  {t("batch.results")} ({filteredResults.length})
                </span>
                <div className="flex items-center gap-1.5">
                  {["all", "safe", "unsafe", "error"].map((f) => (
                    <button
                      key={f}
                      onClick={() => setFilterVerdict(f)}
                      className={cn(
                        "text-[11px] font-semibold px-3 py-1 rounded-md transition-all",
                        filterVerdict === f
                          ? "bg-violet-600 text-white"
                          : "text-stone-400 hover:text-stone-600 hover:bg-stone-100"
                      )}
                    >
                      {t(`batch.filter.${f}` as Parameters<typeof t>[0])}
                    </button>
                  ))}
                </div>
              </div>

              {/* Table */}
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
                        <tr key={`${r.skill_name}-${i}`}
                          className={cn("border-t border-stone-50 hover:bg-stone-50/50 transition-colors", historyMap[r.skill_name] && "cursor-pointer")}
                          onClick={() => { const rid = historyMap[r.skill_name]; if (rid) router.push(`/scan/${rid}`); }}>
                          <td className="px-6 py-2.5 text-stone-300 font-mono text-xs">{i + 1}</td>
                          <td className="px-6 py-2.5 font-semibold text-stone-700">{r.skill_name}</td>
                          <td className="px-6 py-2.5">
                            <span className={cn("text-[10px] font-bold px-2 py-0.5 rounded-md", vs.bg, vs.text)}>
                              {verdictLabel(r.verdict)}
                            </span>
                          </td>
                          <td className="px-6 py-2.5 font-mono text-stone-500">{r.findings}</td>
                          <td className="px-6 py-2.5 font-mono text-violet-600">{r.latency}s</td>
                          <td className="px-6 py-2.5">
                            {r.false_negative && (
                              <span className="text-[10px] font-bold px-2 py-0.5 rounded-md bg-amber-50 text-amber-600">FN</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Log viewer */}
          {logs.length > 0 && (
            <div className="card-white rounded-xl border border-stone-200 overflow-hidden">
              <div className="px-6 py-3 border-b border-stone-100">
                <span className="text-xs font-bold text-stone-400 uppercase tracking-wider">{t("batch.log")}</span>
              </div>
              <div className="p-4 max-h-48 overflow-y-auto bg-stone-900 rounded-b-xl">
                {logs.map((line, i) => (
                  <div key={i} className="text-[11px] font-mono text-stone-400 leading-relaxed">
                    <span className="text-stone-600 mr-2">{String(i + 1).padStart(3, " ")}</span>
                    {line}
                  </div>
                ))}
                <div ref={logsEndRef} />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function SummaryCard({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="bg-stone-50 rounded-lg p-3 text-center">
      <div className={cn("text-xl font-bold font-mono", color)}>{value}</div>
      <div className="text-[10px] font-semibold text-stone-400 uppercase tracking-wider mt-0.5">{label}</div>
    </div>
  );
}
