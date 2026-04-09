"use client";

import { useState } from "react";
import type { PipelineState } from "@/lib/types";
import { cn } from "@/lib/utils";
import { TerminalViewer } from "./terminal-viewer";

interface ProcessTimelineProps {
  state: PipelineState;
}

export function ProcessTimeline({ state }: ProcessTimelineProps) {
  const [expandedSkill, setExpandedSkill] = useState<string | null>(null);

  const skills = Object.values(state.prescan_results);
  const safeSkills = skills.filter((s) => s.safety_verdict === "SAFE");
  const unsafeSkills = skills.filter((s) => s.safety_verdict === "UNSAFE");

  const falseNegatives = new Set(
    state.verify_results.filter((r) => r.status !== "PASSED").map((r) => r.skill)
  );

  return (
    <div className="space-y-1 font-mono text-[12px]">
      {/* ── Stage 1 ── */}
      <StageBlock number={1} title="Pre-scan: Static Analysis + LLM Safety Scoring" status={state.stage1}>
        <div className="space-y-0.5">
          <LogSection title="Step 1: Static Analysis" icon="scan">
            {skills.map((s) => (
              <div key={s.skill_name} className="flex items-center gap-2 py-0.5">
                <span className={s.findings_count > 0 ? "text-amber-600" : "text-emerald-600"}>
                  {s.findings_count > 0 ? "!" : "\u2713"}
                </span>
                <span className="text-stone-700">{s.skill_name}</span>
                {s.findings_count > 0 ? (
                  <span className="text-stone-400">
                    {s.findings_count} findings
                    <span className={cn(
                      "ml-1.5 px-1.5 py-0 rounded text-[9px] font-bold",
                      s.max_severity === "CRITICAL" ? "bg-red-100 text-red-700" :
                      s.max_severity === "HIGH" ? "bg-orange-100 text-orange-700" :
                      s.max_severity === "MEDIUM" ? "bg-amber-100 text-amber-700" :
                      "bg-cyan-100 text-cyan-700"
                    )}>
                      {s.max_severity}
                    </span>
                  </span>
                ) : (
                  <span className="text-emerald-500">clean</span>
                )}
              </div>
            ))}
          </LogSection>

          <LogSection title="Step 2: LLM Safety Scoring" icon="brain">
            {skills.map((s) => (
              <div key={s.skill_name} className="flex items-center gap-2 py-0.5">
                <span className={s.safety_verdict === "SAFE" ? "text-emerald-600" : "text-red-600"}>
                  {s.safety_verdict === "SAFE" ? "\u2713" : "\u2717"}
                </span>
                <span className="text-stone-700">{s.skill_name}</span>
                <span className="text-stone-400">confidence:</span>
                <span className={cn(
                  "font-bold",
                  s.safety_confidence >= 0.7 ? "text-emerald-600" :
                  s.safety_confidence >= 0.3 ? "text-amber-600" : "text-red-600"
                )}>
                  {s.safety_confidence.toFixed(2)}
                </span>
                <span className={cn(
                  "px-1.5 py-0 rounded text-[9px] font-bold",
                  s.safety_verdict === "SAFE"
                    ? "bg-emerald-100 text-emerald-700"
                    : "bg-red-100 text-red-700"
                )}>
                  {s.safety_verdict}
                </span>
              </div>
            ))}
          </LogSection>

          <LogSection title="Step 3: Extract Safe Skills" icon="filter">
            <div className="text-stone-500">
              Extracted <span className="text-emerald-600 font-bold">{safeSkills.length}</span> safe skills,
              quarantined <span className="text-red-600 font-bold">{unsafeSkills.length}</span> unsafe skills
            </div>
            <div className="flex flex-wrap gap-1.5 mt-1.5">
              {safeSkills.map((s) => (
                <span key={s.skill_name} className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 text-[10px]">
                  {s.skill_name}
                </span>
              ))}
            </div>
          </LogSection>
        </div>
      </StageBlock>

      {/* ── Stage 2 ── */}
      <StageBlock
        number={2}
        title="Docker Runtime Detection"
        status={state.stage2}
        subtitle="openclaw:fangcun-guard | Phase 1: Env Prep (OFF) → Phase 2: Execution (ON)"
      >
        <div className="space-y-0.5">
          {state.runtime_results.map((r) => {
            const isExpanded = expandedSkill === `s2-${r.skill}`;
            return (
              <div key={r.skill}>
                <button
                  className="w-full flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-stone-50 transition-colors text-left"
                  onClick={() => setExpandedSkill(isExpanded ? null : `s2-${r.skill}`)}
                >
                  <span className={cn(
                    "w-2 h-2 rounded-full shrink-0",
                    r.status === "PASSED" ? "bg-emerald-500" :
                    r.status === "BLOCKED" ? "bg-red-500" :
                    r.status === "ALERT" ? "bg-orange-500" : "bg-amber-500"
                  )} />
                  <span className="text-stone-700 font-medium">{r.skill}</span>
                  <span className={cn(
                    "px-1.5 py-0 rounded text-[9px] font-bold",
                    r.status === "PASSED" ? "bg-emerald-100 text-emerald-700" :
                    r.status === "BLOCKED" ? "bg-red-100 text-red-700" :
                    r.status === "ALERT" ? "bg-orange-100 text-orange-700" :
                    "bg-amber-100 text-amber-700"
                  )}>
                    {r.status}
                  </span>
                  <span className="text-stone-400">{r.elapsed_sec}s</span>
                  {r.blacklist_hits > 0 && <span className="text-red-600 font-medium">blacklist:{r.blacklist_hits}</span>}
                  {r.blocks > 0 && <span className="text-red-600 font-medium">blocks:{r.blocks}</span>}
                  {r.early_stopped && <span className="text-red-600 text-[9px] bg-red-100 px-1 rounded font-bold">EARLY_STOP</span>}
                  <span className="flex-1" />
                  <svg className={cn("w-3.5 h-3.5 text-stone-300 transition-transform", isExpanded && "rotate-180")} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                {isExpanded && (
                  <div className="ml-4 mt-1 mb-3 p-3 bg-stone-50 rounded-lg border border-stone-200">
                    {r.capability_indicators.length > 0 && (
                      <div className="space-y-1 mb-3">
                        {r.capability_indicators.map((ind, i) => (
                          <div key={i} className="text-[11px] text-amber-700 bg-amber-50 px-2.5 py-1.5 rounded border border-amber-200">
                            {ind}
                          </div>
                        ))}
                      </div>
                    )}
                    <TerminalViewer lines={r.log_lines} title={`docker run — ${r.skill}`} />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </StageBlock>

      {/* ── Stage 3 ── */}
      <StageBlock
        number={3}
        title="Verify: Safe Skills Validation"
        status={state.stage3}
        subtitle="Re-run safe skills to detect false negatives"
      >
        <div className="space-y-0.5">
          {state.verify_results.map((r) => {
            const isFN = falseNegatives.has(r.skill);
            const isExpanded = expandedSkill === `s3-${r.skill}`;
            return (
              <div key={r.skill}>
                <button
                  className="w-full flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-stone-50 transition-colors text-left"
                  onClick={() => setExpandedSkill(isExpanded ? null : `s3-${r.skill}`)}
                >
                  <span className={cn(
                    "w-2 h-2 rounded-full shrink-0",
                    r.status === "PASSED" ? "bg-emerald-500" : "bg-amber-500"
                  )} />
                  <span className={cn("text-stone-700", isFN && "text-amber-700 font-bold")}>{r.skill}</span>
                  <span className={cn(
                    "px-1.5 py-0 rounded text-[9px] font-bold",
                    r.status === "PASSED" ? "bg-emerald-100 text-emerald-700" : "bg-amber-100 text-amber-700"
                  )}>
                    {r.status}
                  </span>
                  <span className="text-stone-400">{r.elapsed_sec}s</span>
                  {isFN && (
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-red-100 text-red-700 border border-red-300 flex items-center gap-1">
                      <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                      </svg>
                      FALSE NEGATIVE
                    </span>
                  )}
                  <span className="flex-1" />
                  <svg className={cn("w-3.5 h-3.5 text-stone-300 transition-transform", isExpanded && "rotate-180")} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                {isExpanded && (
                  <div className="ml-4 mt-1 mb-3 p-3 bg-stone-50 rounded-lg border border-stone-200">
                    {r.capability_indicators.length > 0 && (
                      <div className="space-y-1 mb-3">
                        {r.capability_indicators.map((ind, i) => (
                          <div key={i} className="text-[11px] text-amber-700 bg-amber-50 px-2.5 py-1.5 rounded border border-amber-200">
                            {ind}
                          </div>
                        ))}
                      </div>
                    )}
                    <TerminalViewer lines={r.log_lines} title={`docker run — ${r.skill}`} />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </StageBlock>
    </div>
  );
}

function StageBlock({
  number, title, status, subtitle, children,
}: {
  number: number; title: string; status: string; subtitle?: string; children: React.ReactNode;
}) {
  const isDone = status === "completed";
  return (
    <div className="mb-5">
      <div className="flex items-center gap-3 mb-3 pb-2 border-b border-stone-200">
        <div className={cn(
          "w-7 h-7 rounded-lg flex items-center justify-center text-[11px] font-bold",
          isDone ? "bg-emerald-100 text-emerald-700" : "bg-cyan-100 text-cyan-700"
        )}>
          {isDone ? (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          ) : number}
        </div>
        <div className="flex-1">
          <div className="text-[13px] font-bold text-stone-800 font-sans">{title}</div>
          {subtitle && <div className="text-[10px] text-stone-400 font-sans">{subtitle}</div>}
        </div>
        <span className={cn(
          "px-2.5 py-0.5 rounded-full text-[9px] font-bold uppercase",
          isDone ? "bg-emerald-100 text-emerald-700" : "bg-cyan-100 text-cyan-700"
        )}>
          {isDone ? "Done" : "Running"}
        </span>
      </div>
      <div className="pl-3">{children}</div>
    </div>
  );
}

function LogSection({
  title, icon, children,
}: {
  title: string; icon: "scan" | "brain" | "filter"; children: React.ReactNode;
}) {
  const iconMap = {
    scan: (
      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
      </svg>
    ),
    brain: (
      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
      </svg>
    ),
    filter: (
      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 3c2.755 0 5.455.232 8.083.678.533.09.917.556.917 1.096v1.044a2.25 2.25 0 01-.659 1.591l-5.432 5.432a2.25 2.25 0 00-.659 1.591v2.927a2.25 2.25 0 01-1.244 2.013L9.75 21v-6.568a2.25 2.25 0 00-.659-1.591L3.659 7.409A2.25 2.25 0 013 5.818V4.774c0-.54.384-1.006.917-1.096A48.32 48.32 0 0112 3z" />
      </svg>
    ),
  };

  return (
    <div className="mb-4">
      <div className="flex items-center gap-2 text-[11px] font-bold text-stone-500 uppercase tracking-wider mb-1.5 font-sans">
        <span className="text-cyan-600">{iconMap[icon]}</span>
        {title}
      </div>
      <div className="pl-4 border-l-2 border-stone-200">{children}</div>
    </div>
  );
}
