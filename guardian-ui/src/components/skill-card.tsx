"use client";

import { useState } from "react";
import type { SkillPrescanResult } from "@/lib/types";
import { cn } from "@/lib/utils";
import { severityBg, severityBorder, confidenceColor, confidenceBarBg } from "@/lib/helpers";

interface SkillCardProps {
  skill: SkillPrescanResult;
  onShowRemediation?: (skillName: string) => void;
}

export function SkillCard({ skill, onShowRemediation }: SkillCardProps) {
  const [expanded, setExpanded] = useState(false);
  const isUnsafe = skill.safety_verdict === "UNSAFE";

  return (
    <div className={cn(
      "rounded-xl card-warm transition-all overflow-hidden",
      isUnsafe && "glow-red"
    )}>
      <button
        className="w-full flex items-center gap-4 p-4 text-left group"
        onClick={() => setExpanded(!expanded)}
      >
        <div className={cn(
          "w-2.5 h-2.5 rounded-full shrink-0 ring-2",
          isUnsafe
            ? "bg-red-500 ring-red-200"
            : "bg-emerald-500 ring-emerald-200"
        )} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2.5">
            <span className="font-mono text-[13px] font-bold text-stone-800">{skill.skill_name}</span>
            <span className={cn(
              "inline-flex px-2 py-0.5 rounded-md text-[10px] font-bold border",
              severityBg(skill.max_severity)
            )}>
              {skill.max_severity}
            </span>
            {skill.findings_count > 0 && (
              <span className="text-[11px] text-stone-400 font-mono">{skill.findings_count} findings</span>
            )}
          </div>
          <p className="text-[11px] text-stone-400 mt-1 truncate max-w-lg">{skill.llm_reason}</p>
        </div>

        <div className="flex items-center gap-4 shrink-0">
          <div className="flex items-center gap-2">
            <div className="w-20 h-1.5 rounded-full bg-stone-100 overflow-hidden border border-stone-200/50">
              <div
                className={cn("h-full rounded-full bg-gradient-to-r transition-all duration-700", confidenceBarBg(skill.safety_confidence))}
                style={{ width: `${skill.safety_confidence * 100}%` }}
              />
            </div>
            <span className={cn("font-mono text-xs font-bold w-10 text-right", confidenceColor(skill.safety_confidence))}>
              {skill.safety_confidence.toFixed(2)}
            </span>
          </div>

          <span className={cn(
            "px-2 py-0.5 rounded-md text-[10px] font-bold border",
            isUnsafe
              ? "bg-red-50 text-red-600 border-red-200"
              : "bg-emerald-50 text-emerald-600 border-emerald-200"
          )}>
            {skill.safety_verdict}
          </span>

          <svg
            className={cn("w-4 h-4 text-stone-300 transition-transform duration-200 group-hover:text-stone-500 shrink-0", expanded && "rotate-180")}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-amber-100 px-5 py-4 space-y-3 bg-amber-50/30">
          <div className="flex items-center gap-4 text-[11px] text-stone-400">
            <span>Analyzers: <span className="text-amber-700/60">{skill.analyzers_used.join(" · ")}</span></span>
            <span className="text-stone-300">|</span>
            <span>Duration: <span className="text-amber-700/60">{skill.scan_duration.toFixed(1)}s</span></span>
          </div>

          {skill.findings.length === 0 ? (
            <div className="text-xs text-emerald-600/60 py-1 flex items-center gap-1.5">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              No findings detected
            </div>
          ) : (
            <div className="space-y-2">
              {skill.findings.map((f, i) => (
                <div key={i} className={cn(
                  "p-3 rounded-lg bg-white border border-stone-200/80",
                  severityBorder(f.severity)
                )}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className={cn(
                      "inline-flex px-1.5 py-0.5 rounded text-[9px] font-bold border uppercase",
                      severityBg(f.severity)
                    )}>
                      {f.severity}
                    </span>
                    <span className="text-xs font-semibold text-stone-700">{f.title}</span>
                  </div>
                  <div className="text-[10px] text-stone-400 font-mono">
                    {f.rule_id} {f.file_path && <span className="text-stone-500">@ {f.file_path}:{f.line_number}</span>}
                  </div>
                  <p className="text-[11px] text-stone-500 mt-1.5 leading-relaxed">{f.description}</p>
                  {f.snippet && (
                    <pre className="mt-2 px-3 py-2 rounded-md terminal-bg text-[10px] font-mono text-red-300/70 overflow-x-auto border border-red-500/10">
{f.snippet}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          )}

          {isUnsafe && onShowRemediation && (
            <button
              className="mt-1 text-[11px] font-semibold text-amber-600 hover:text-amber-500 flex items-center gap-1.5 transition-colors"
              onClick={(e) => { e.stopPropagation(); onShowRemediation(skill.skill_name); }}
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              View Remediation
            </button>
          )}
        </div>
      )}
    </div>
  );
}
