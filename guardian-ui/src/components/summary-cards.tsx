"use client";

import type { PipelineState, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

interface SummaryCardsProps {
  state: PipelineState;
}

export function SummaryCards({ state }: SummaryCardsProps) {
  const prescan = Object.values(state.prescan_results);
  const totalSkills = prescan.length;
  const safeCount = prescan.filter((s) => s.safety_verdict === "SAFE").length;
  const blocked = state.runtime_results.filter((r) => r.status === "BLOCKED").length;
  const runtimeAlerts = state.runtime_results.filter((r) => r.status !== "PASSED").length;
  const falseNegatives = state.verify_results.filter((r) => r.status !== "PASSED").length;
  const safePercent = totalSkills > 0 ? Math.round((safeCount / totalSkills) * 100) : 0;

  const severityCounts: Record<string, number> = {};
  for (const s of prescan) {
    for (const f of s.findings) {
      severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-4 gap-4">
        <div className="stat-info rounded-xl p-5 relative overflow-hidden">
          <div className="absolute top-3 right-3 w-10 h-10 rounded-full bg-amber-100 flex items-center justify-center">
            <svg className="w-5 h-5 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
            </svg>
          </div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-amber-700/50 mb-2">Total Skills</div>
          <div className="text-3xl font-bold font-mono text-amber-800">{totalSkills}</div>
          <div className="text-xs text-amber-600/70 mt-1">Scanned & analyzed</div>
        </div>

        <div className="stat-safe rounded-xl p-5 relative overflow-hidden">
          <div className="absolute top-3 right-3 w-10 h-10 rounded-full bg-emerald-100 flex items-center justify-center">
            <svg className="w-5 h-5 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-emerald-700/50 mb-2">Safe Skills</div>
          <div className="text-3xl font-bold font-mono text-emerald-700">{safeCount}</div>
          <div className="text-xs text-emerald-600/70 mt-1">{safePercent}% pass rate</div>
        </div>

        <div className="stat-danger rounded-xl p-5 relative overflow-hidden">
          <div className="absolute top-3 right-3 w-10 h-10 rounded-full bg-red-100 flex items-center justify-center">
            <svg className="w-5 h-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
            </svg>
          </div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-red-700/50 mb-2">Blocked</div>
          <div className="text-3xl font-bold font-mono text-red-600">{blocked}</div>
          <div className="text-xs text-red-500/70 mt-1">{runtimeAlerts} total alerts</div>
        </div>

        <div className="stat-warn rounded-xl p-5 relative overflow-hidden">
          <div className="absolute top-3 right-3 w-10 h-10 rounded-full bg-amber-100 flex items-center justify-center">
            <svg className="w-5 h-5 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            </svg>
          </div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-amber-700/50 mb-2">False Negatives</div>
          <div className="text-3xl font-bold font-mono text-amber-700">{falseNegatives}</div>
          <div className="text-xs text-amber-600/70 mt-1">Stage 3 verification</div>
        </div>
      </div>

      {/* Severity bar */}
      <div className="card-warm rounded-xl px-6 py-4 flex items-center gap-6">
        <span className="text-[10px] font-bold uppercase tracking-widest text-stone-400">Severity</span>
        <SevPill sev="CRITICAL" count={severityCounts["CRITICAL"] || 0} dot="bg-red-500" text="text-red-700" />
        <SevPill sev="HIGH" count={severityCounts["HIGH"] || 0} dot="bg-orange-500" text="text-orange-700" />
        <SevPill sev="MEDIUM" count={severityCounts["MEDIUM"] || 0} dot="bg-amber-500" text="text-amber-700" />
        <SevPill sev="LOW" count={severityCounts["LOW"] || 0} dot="bg-cyan-500" text="text-cyan-700" />
        <div className="flex-1" />
        <div className="flex items-center gap-2 w-48">
          <div className="flex-1 h-2.5 rounded-full bg-stone-100 overflow-hidden flex border border-stone-200/50">
            <div className="bg-gradient-to-r from-emerald-400 to-emerald-500 transition-all duration-1000" style={{ width: `${safePercent}%` }} />
            <div className="bg-gradient-to-r from-red-400 to-red-500 transition-all duration-1000" style={{ width: `${100 - safePercent}%` }} />
          </div>
          <span className="text-xs font-bold font-mono text-emerald-700">{safePercent}%</span>
        </div>
      </div>
    </div>
  );
}

function SevPill({ sev, count, dot, text }: { sev: string; count: number; dot: string; text: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className={cn("w-2.5 h-2.5 rounded-full", dot)} />
      <span className={cn("text-xs font-mono font-bold", text)}>{count}</span>
      <span className="text-[10px] text-stone-400">{sev}</span>
    </div>
  );
}
