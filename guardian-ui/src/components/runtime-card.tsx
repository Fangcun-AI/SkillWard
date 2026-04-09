"use client";

import { useState } from "react";
import type { RuntimeResult } from "@/lib/types";
import { cn } from "@/lib/utils";
import { runtimeStatusColor, runtimeGlow } from "@/lib/helpers";
import { TerminalViewer } from "./terminal-viewer";

interface RuntimeCardProps {
  result: RuntimeResult;
  isFalseNegative?: boolean;
}

export function RuntimeCard({ result, isFalseNegative }: RuntimeCardProps) {
  const [expanded, setExpanded] = useState(false);
  const hasIssues = result.status !== "PASSED";

  return (
    <div className={cn(
      "rounded-xl card-warm transition-all overflow-hidden",
      hasIssues && runtimeGlow(result.status),
      isFalseNegative && "ring-2 ring-amber-400/50 animate-subtle-pulse"
    )}>
      <button
        className="w-full flex items-center gap-4 p-4 text-left group"
        onClick={() => setExpanded(!expanded)}
      >
        <div className={cn(
          "w-2.5 h-2.5 rounded-full shrink-0 ring-2",
          result.status === "PASSED" ? "bg-emerald-500 ring-emerald-200" :
          result.status === "BLOCKED" ? "bg-red-500 ring-red-200" :
          result.status === "ALERT" ? "bg-orange-500 ring-orange-200" :
          "bg-amber-500 ring-amber-200"
        )} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2.5">
            <span className="font-mono text-[13px] font-bold text-stone-800">{result.skill}</span>
            <span className={cn("inline-flex px-2 py-0.5 rounded-md text-[10px] font-bold border uppercase", runtimeStatusColor(result.status))}>
              {result.status}
            </span>
            {isFalseNegative && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-bold bg-amber-50 text-amber-700 border border-amber-300">
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
                FALSE NEGATIVE
              </span>
            )}
            {result.early_stopped && (
              <span className="text-[10px] text-red-600 font-mono bg-red-50 px-1.5 py-0.5 rounded border border-red-200">EARLY_STOP</span>
            )}
          </div>
          <div className="flex items-center gap-3 text-[11px] text-stone-400 mt-1 font-mono">
            <span>{result.elapsed_sec}s</span>
            {result.blacklist_hits > 0 && <span className="text-red-500">blacklist:{result.blacklist_hits}</span>}
            {result.blocks > 0 && <span className="text-red-500">blocks:{result.blocks}</span>}
            {result.retries_used > 0 && <span>retries:{result.retries_used}</span>}
          </div>
        </div>

        <svg
          className={cn("w-4 h-4 text-stone-300 transition-transform duration-200 group-hover:text-stone-500 shrink-0", expanded && "rotate-180")}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {expanded && (
        <div className="border-t border-amber-100 px-5 py-4 space-y-3 bg-amber-50/30">
          {result.capability_indicators.length > 0 && (
            <div>
              <div className="text-[10px] font-bold uppercase tracking-widest text-amber-600 mb-2 flex items-center gap-1.5">
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
                Capability Indicators
              </div>
              <div className="space-y-1">
                {result.capability_indicators.map((ind, i) => (
                  <div key={i} className="text-[11px] font-mono px-3 py-2 rounded-lg bg-amber-50 border border-amber-200 text-amber-800">
                    {ind}
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.details.length > 0 && (
            <div>
              <div className="text-[10px] font-bold uppercase tracking-widest text-red-500 mb-2 flex items-center gap-1.5">
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                </svg>
                Detection Details
              </div>
              <div className="space-y-1">
                {result.details.map((d, i) => (
                  <div key={i} className="text-[11px] font-mono px-3 py-2 rounded-lg bg-red-50 border border-red-200 text-red-700">
                    {d}
                  </div>
                ))}
              </div>
            </div>
          )}

          <TerminalViewer
            lines={result.log_lines}
            title={`docker run openclaw:fangcun-guard — ${result.skill}`}
          />
        </div>
      )}
    </div>
  );
}
