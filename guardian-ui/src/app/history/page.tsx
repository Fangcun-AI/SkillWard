"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { useI18n, LanguageToggle } from "@/lib/i18n";

const API_BASE = process.env.NEXT_PUBLIC_GUARDIAN_API || "http://localhost:8899";

interface ScanRecord {
  id: string;
  verdict: string;
  skill_name: string;
  skill_description?: string;
  false_negative: boolean;
  scan_time?: string;
  source?: string;
  latency?: { total: number; static: number; llm: number; runtime: number; verify: number };
  stages: {
    static: { verdict: string; findings: number; severity: string };
    llm: { confidence: number | null; reason: string };
    runtime: { status: string; elapsed: number; blacklist_hits: number; blocks: number };
  };
  warnings: { level: string; source: string; text: string }[];
  recommendations: string[];
}

export default function HistoryPage() {
  const { t } = useI18n();
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [hasMore, setHasMore] = useState(true);
  const offsetRef = useRef(0);
  const [loadingMore, setLoadingMore] = useState(false);
  const [total, setTotal] = useState(0);
  const PAGE_SIZE = 50;
  const loadMoreRef = useRef<HTMLDivElement>(null);

  const VERDICT_CONFIG: Record<string, { label: string; bg: string; text: string; border: string }> = {
    BLOCKED: { label: t("history.verdict.danger"), bg: "bg-red-50", text: "text-red-600", border: "border-red-200" },
    ALERT: { label: t("history.verdict.warn"), bg: "bg-amber-50", text: "text-amber-600", border: "border-amber-200" },
    PASSED: { label: t("history.verdict.safe"), bg: "bg-emerald-50", text: "text-emerald-600", border: "border-emerald-200" },
    TIMEOUT: { label: t("history.verdict.timeout"), bg: "bg-stone-50", text: "text-stone-500", border: "border-stone-200" },
    ERROR: { label: t("history.verdict.error"), bg: "bg-stone-50", text: "text-stone-500", border: "border-stone-200" },
    WARNING: { label: t("history.verdict.warn"), bg: "bg-amber-50", text: "text-amber-600", border: "border-amber-200" },
    DANGER: { label: t("history.verdict.danger"), bg: "bg-red-50", text: "text-red-600", border: "border-red-200" },
    SAFE: { label: t("history.verdict.safe"), bg: "bg-emerald-50", text: "text-emerald-600", border: "border-emerald-200" },
    UNSAFE: { label: t("history.verdict.danger"), bg: "bg-red-50", text: "text-red-600", border: "border-red-200" },
    INCONCLUSIVE: { label: t("history.verdict.timeout"), bg: "bg-stone-50", text: "text-stone-500", border: "border-stone-200" },
    // New unified terminology (Safe / Medium Risk / High Risk) — produced by refactored guardian.py
    "Safe": { label: t("history.verdict.safe"), bg: "bg-emerald-50", text: "text-emerald-600", border: "border-emerald-200" },
    "Medium Risk": { label: t("history.verdict.warn"), bg: "bg-amber-50", text: "text-amber-600", border: "border-amber-200" },
    "High Risk": { label: t("history.verdict.danger"), bg: "bg-red-50", text: "text-red-600", border: "border-red-200" },
    INCOMPLETE: { label: t("history.verdict.timeout"), bg: "bg-stone-50", text: "text-stone-500", border: "border-stone-200" },
    SANDBOX_FAILED: { label: t("history.verdict.error"), bg: "bg-stone-50", text: "text-stone-500", border: "border-stone-200" },
  };

  function getVerdictConfig(verdict: string) {
    return VERDICT_CONFIG[verdict] || VERDICT_CONFIG.ERROR;
  }

  function getThreatTags(record: ScanRecord): string[] {
    const tags: string[] = [];
    const seen = new Set<string>();
    for (const w of record.warnings) {
      const text = w.text.toLowerCase();
      const mapping: [string, string][] = [
        ["外部", t("tag.data_exfil")],
        ["exfil", t("tag.data_exfil")],
        ["external", t("tag.external_req")],
        ["blacklist", t("tag.blacklist")],
        ["credential", t("tag.credential")],
        ["漏报", t("tag.fn_detect")],
        ["false negative", t("tag.fn_detect")],
        ["blocked", t("tag.runtime_block")],
        ["risk level", t("tag.risk_eval")],
        ["提前终止", t("tag.early_term")],
      ];
      for (const [keyword, tag] of mapping) {
        if (text.includes(keyword) && !seen.has(tag)) {
          seen.add(tag);
          tags.push(tag);
        }
      }
    }
    if (record.stages.static.findings > 0 && !seen.has(t("tag.static_find"))) {
      tags.push(t("tag.static_find"));
    }
    return tags.slice(0, 4);
  }

  const fetchPage = useCallback((currentOffset: number, append: boolean) => {
    if (append) setLoadingMore(true);
    fetch(`${API_BASE}/api/scan/history?limit=${PAGE_SIZE}&offset=${currentOffset}`)
      .then((res) => res.json())
      .then((data) => {
        const list = Array.isArray(data) ? data : (data.records || []);
        const serverTotal = data.total ?? list.length;
        setTotal(serverTotal);
        if (append) {
          setRecords((prev) => [...prev, ...list]);
        } else {
          setRecords(list);
        }
        setHasMore(currentOffset + list.length < serverTotal);
        setLoading(false);
        setLoadingMore(false);
      })
      .catch(() => { setLoading(false); setLoadingMore(false); });
  }, []);

  const loadMore = useCallback(() => {
    if (loadingMore || !hasMore) return;
    offsetRef.current += PAGE_SIZE;
    fetchPage(offsetRef.current, true);
  }, [loadingMore, hasMore, fetchPage]);

  useEffect(() => {
    fetchPage(0, false);
  }, [fetchPage]);

  useEffect(() => {
    const handleScroll = () => {
      if (loadingMore || !hasMore) return;
      const scrollBottom = window.innerHeight + window.scrollY;
      const docHeight = document.documentElement.scrollHeight;
      if (docHeight - scrollBottom < 300) {
        loadMore();
      }
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, [hasMore, loadingMore, loadMore]);

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
              <Link href="/" className="text-xs font-semibold px-4 py-1.5 rounded-lg text-stone-500 hover:text-violet-600 transition-all">
                {t("nav.submit")}
              </Link>
              <span className="text-xs font-semibold px-4 py-1.5 rounded-lg bg-violet-600 text-white">
                {t("nav.history")}
              </span>
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
        <div className="max-w-7xl mx-auto px-8 py-8">
          <div className="mb-6">
            <h1 className="text-2xl font-bold text-stone-800">{t("history.title")}</h1>
          </div>

          {loading ? (
            <div className="text-center py-20 text-stone-400">
              <span className="w-6 h-6 border-2 border-stone-300 border-t-violet-500 rounded-full animate-spin inline-block" />
              <p className="mt-3 text-sm">{t("history.loading")}</p>
            </div>
          ) : records.length === 0 ? (
            <div className="text-center py-20">
              <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-stone-100 flex items-center justify-center">
                <svg className="w-8 h-8 text-stone-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                </svg>
              </div>
              <p className="text-stone-400 text-sm">{t("history.empty")}</p>
              <Link href="/" className="inline-block mt-4 text-xs text-violet-600 hover:text-violet-700 font-semibold">
                {t("history.go_scan")} &rarr;
              </Link>
            </div>
          ) : (
            <>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {records.map((record) => {
                const vc = getVerdictConfig(record.verdict);
                const tags = getThreatTags(record);
                return (
                  <Link
                    href={`/scan/${record.id}`}
                    key={record.id}
                    className={cn(
                      "card-white rounded-xl overflow-hidden border transition-all hover:shadow-md hover:-translate-y-0.5 cursor-pointer block",
                      vc.border
                    )}
                  >
                    <div className="p-4">
                      {/* Header row */}
                      <div className="flex items-start justify-between mb-2">
                        <h3 className="text-sm font-bold text-stone-800 truncate flex-1 mr-2">
                          {record.skill_name}
                        </h3>
                        <span className={cn(
                          "shrink-0 text-[10px] font-bold px-2 py-0.5 rounded-md",
                          vc.bg, vc.text
                        )}>
                          {vc.label}
                        </span>
                      </div>

                      {/* Threat tags */}
                      {tags.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 mb-2.5">
                          {tags.map((tag) => (
                            <span key={tag} className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-violet-50 text-violet-600 border border-violet-100">
                              {tag}
                            </span>
                          ))}
                          {record.warnings.length > tags.length && (
                            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-stone-100 text-stone-400">
                              +{record.warnings.length - tags.length}
                            </span>
                          )}
                        </div>
                      )}

                      {/* Description */}
                      <p className="text-xs text-stone-400 line-clamp-2 mb-3 min-h-[2.5em]">
                        {record.skill_description || record.stages.llm.reason || "—"}
                      </p>

                      {/* Latency */}
                      {record.latency && record.latency.total > 0 && (
                        <div className="flex items-center gap-2 mb-2 text-[10px] text-stone-400 font-mono">
                          <span className="text-violet-600 font-semibold">{record.latency.total.toFixed(1)}s</span>
                          <span className="text-stone-300">|</span>
                          <span>S:{record.latency.static.toFixed(1)}s</span>
                          {record.latency.llm > 0 && <span>L:{record.latency.llm.toFixed(1)}s</span>}
                          {record.latency.runtime > 0 && <span>R:{record.latency.runtime.toFixed(1)}s</span>}
                        </div>
                      )}

                      {/* Footer */}
                      <div className="flex items-center justify-between text-[10px] text-stone-400">
                        <span className="font-mono">
                          {record.scan_time || "—"}
                        </span>
                        <div className="flex items-center gap-3">
                          {record.stages.static.findings > 0 && (
                            <span>{t("history.findings_count", { n: record.stages.static.findings })}</span>
                          )}
                          {record.false_negative && (
                            <span className="text-red-500 font-semibold">{t("history.false_neg")}</span>
                          )}
                        </div>
                      </div>
                    </div>
                  </Link>
                );
              })}
            </div>
            {hasMore && (
              <div ref={loadMoreRef} className="py-8 text-center text-stone-400">
                {loadingMore ? "Loading..." : ""}
              </div>
            )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
