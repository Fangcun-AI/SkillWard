"use client";

import type { StageStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

interface ProgressBarProps {
  stages: { label: string; status: StageStatus }[];
}

export function PipelineProgressBar({ stages }: ProgressBarProps) {
  return (
    <div className="sticky top-0 z-50 border-b border-amber-200/60 bg-[#faf6f0]/90 backdrop-blur-xl">
      <div className="max-w-6xl mx-auto px-8 h-14 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center shadow-md shadow-amber-500/15">
            <svg className="w-4.5 h-4.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <div>
            <span className="font-bold text-sm tracking-tight text-stone-800">Skills Scanner</span>
            <span className="text-[10px] text-amber-600/50 ml-2 font-mono">v1.0</span>
          </div>
        </div>

        <div className="flex items-center bg-white/60 rounded-full px-1.5 py-1 border border-amber-200/50 shadow-sm">
          {stages.map((stage, i) => {
            const isDone = stage.status === "completed";
            const isActive = stage.status === "running";
            return (
              <div key={stage.label} className="flex items-center">
                <div className={cn(
                  "flex items-center gap-1.5 px-3.5 py-1 rounded-full text-xs font-semibold transition-all",
                  isDone && "bg-emerald-50 text-emerald-700",
                  isActive && "bg-amber-50 text-amber-700",
                  !isDone && !isActive && "text-stone-400"
                )}>
                  {isDone ? (
                    <svg className="w-3 h-3 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  ) : isActive ? (
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500" />
                    </span>
                  ) : (
                    <span className="w-1.5 h-1.5 rounded-full bg-stone-300" />
                  )}
                  {stage.label}
                </div>
                {i < stages.length - 1 && (
                  <svg className="w-3.5 h-3.5 text-stone-300 mx-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
