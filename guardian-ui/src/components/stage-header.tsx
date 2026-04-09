"use client";

import type { StageStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

interface StageHeaderProps {
  number: number;
  title: string;
  subtitle: string;
  status: StageStatus;
}

export function StageHeader({ number, title, subtitle, status }: StageHeaderProps) {
  const isDone = status === "completed";
  const isRunning = status === "running";

  return (
    <div className="relative overflow-hidden rounded-xl card-gradient-border px-6 py-5 bg-white">
      <div className="relative flex items-center gap-5">
        <div className={cn(
          "w-11 h-11 rounded-xl flex items-center justify-center font-mono text-sm font-bold shadow-md",
          isDone && "bg-gradient-to-br from-emerald-400 to-teal-500 text-white shadow-emerald-500/15",
          isRunning && "bg-gradient-to-br from-amber-400 to-orange-500 text-white shadow-amber-500/15",
          !isDone && !isRunning && "bg-stone-100 text-stone-400 shadow-none border border-stone-200"
        )}>
          {isDone ? (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          ) : number}
        </div>
        <div className="flex-1">
          <h2 className="text-base font-bold tracking-tight text-stone-800">{title}</h2>
          <p className="text-xs text-stone-400 mt-0.5">{subtitle}</p>
        </div>
        <div className={cn(
          "px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider",
          isDone && "bg-emerald-50 text-emerald-600 border border-emerald-200",
          isRunning && "bg-amber-50 text-amber-600 border border-amber-200",
          !isDone && !isRunning && "bg-stone-50 text-stone-400 border border-stone-200"
        )}>
          {isDone ? "Complete" : isRunning ? "Running" : "Pending"}
        </div>
      </div>
    </div>
  );
}
