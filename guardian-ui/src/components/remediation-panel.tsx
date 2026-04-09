"use client";

import { useState } from "react";
import type { RemediationSuggestion } from "@/lib/types";
import { cn } from "@/lib/utils";
import { severityBg } from "@/lib/helpers";

interface RemediationPanelProps {
  remediations: RemediationSuggestion[];
  highlightSkill?: string | null;
}

export function RemediationPanel({ remediations, highlightSkill }: RemediationPanelProps) {
  const [expandedIdx, setExpandedIdx] = useState<number | null>(
    highlightSkill ? remediations.findIndex((r) => r.skill_name === highlightSkill) : null
  );

  return (
    <div className="space-y-2">
      {remediations.map((rem, i) => {
        const isExpanded = expandedIdx === i;
        const isHighlighted = highlightSkill === rem.skill_name;
        return (
          <div
            key={i}
            id={`remediation-${rem.skill_name}`}
            className={cn(
              "rounded-xl card-white overflow-hidden transition-all",
              isHighlighted && "glow-cyan"
            )}
          >
            <button
              className="w-full flex items-center gap-4 p-4 text-left group"
              onClick={() => setExpandedIdx(isExpanded ? null : i)}
            >
              <div className="w-9 h-9 rounded-lg bg-cyan-50 flex items-center justify-center shrink-0 border border-cyan-200">
                <svg className="w-4.5 h-4.5 text-cyan-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-[13px] font-bold text-stone-800">{rem.skill_name}</span>
                  <span className={cn("inline-flex px-2 py-0.5 rounded-md text-[10px] font-bold border", severityBg(rem.severity))}>
                    {rem.severity}
                  </span>
                </div>
                <p className="text-[11px] text-stone-400 mt-0.5 truncate">{rem.finding_title}</p>
              </div>
              <svg
                className={cn("w-4 h-4 text-stone-300 transition-transform duration-200 group-hover:text-stone-500 shrink-0", isExpanded && "rotate-180")}
                fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
              </svg>
            </button>

            {isExpanded && (
              <div className="border-t border-stone-200 px-5 py-5 space-y-4 bg-stone-50/50">
                <p className="text-[12px] text-stone-500 leading-relaxed">{rem.description}</p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="rounded-xl overflow-hidden border border-red-200">
                    <div className="px-4 py-2 bg-red-50 border-b border-red-200 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-red-500" />
                      <span className="text-[10px] font-bold uppercase tracking-wider text-red-700">Vulnerable Code</span>
                    </div>
                    <pre className="px-4 py-3 terminal-bg text-[11px] font-mono text-red-300 overflow-x-auto leading-[1.8] whitespace-pre-wrap">
{rem.code_before}
                    </pre>
                  </div>

                  <div className="rounded-xl overflow-hidden border border-emerald-200">
                    <div className="px-4 py-2 bg-emerald-50 border-b border-emerald-200 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-emerald-500" />
                      <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-700">Fixed Code</span>
                    </div>
                    <pre className="px-4 py-3 terminal-bg text-[11px] font-mono text-emerald-300 overflow-x-auto leading-[1.8] whitespace-pre-wrap">
{rem.code_after}
                    </pre>
                  </div>
                </div>

                <div className="rounded-xl bg-cyan-50 border border-cyan-200 px-5 py-4">
                  <div className="text-[10px] font-bold uppercase tracking-widest text-cyan-700 mb-2 flex items-center gap-1.5">
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                    </svg>
                    Explanation
                  </div>
                  <p className="text-[12px] text-cyan-800/70 leading-relaxed">{rem.explanation}</p>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
