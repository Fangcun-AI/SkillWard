"use client";

import { useRef, useEffect } from "react";
import type { LogLine } from "@/lib/types";
import { cn } from "@/lib/utils";

interface TerminalViewerProps {
  lines: LogLine[];
  title?: string;
  maxHeight?: string;
}

const levelStyles: Record<LogLine["level"], string> = {
  info: "text-slate-400",
  warn: "text-amber-300",
  error: "text-red-400",
  guardian: "text-cyan-400",
  system: "text-indigo-400",
};

function getLineHighlight(content: string): string | null {
  if (/Blacklist hit/i.test(content)) return "bg-red-500/[0.06] text-red-300";
  if (/EARLY_STOP/i.test(content)) return "bg-red-500/10 text-red-300 font-semibold";
  if (/risk=3|high_risk/i.test(content)) return "bg-red-500/[0.06] text-red-400";
  if (/拦截/.test(content)) return "bg-red-500/[0.06] text-red-400";
  if (/risk=0.*label=safe/i.test(content)) return "text-emerald-400/80";
  if (/"stopReason": "stop"/.test(content)) return "text-emerald-400/60";
  if (/PHASE\d_START|PHASE\d_ATTEMPT/.test(content)) return "text-indigo-300 font-semibold";
  return null;
}

export function TerminalViewer({ lines, title, maxHeight = "260px" }: TerminalViewerProps) {
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines.length]);

  return (
    <div className="rounded-xl overflow-hidden border border-slate-700/50 shadow-lg shadow-black/20">
      {title && (
        <div className="flex items-center gap-3 px-4 py-2.5 bg-slate-800/50 border-b border-slate-700/50">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-[#ff5f57] shadow-sm shadow-red-500/30" />
            <span className="w-3 h-3 rounded-full bg-[#febc2e] shadow-sm shadow-yellow-500/20" />
            <span className="w-3 h-3 rounded-full bg-[#28c840] shadow-sm shadow-green-500/20" />
          </div>
          <span className="text-[10px] font-mono text-slate-500 ml-1 truncate">{title}</span>
        </div>
      )}
      <div className="terminal-bg overflow-y-auto font-mono text-[11px] leading-[1.8] px-4 py-3" style={{ maxHeight }}>
        {lines.map((line, i) => {
          const hl = getLineHighlight(line.content);
          return (
            <div
              key={i}
              className={cn(
                "flex gap-3 px-1.5 -mx-1.5 rounded",
                hl || levelStyles[line.level]
              )}
            >
              <span className="text-slate-700 select-none shrink-0 w-14 text-right tabular-nums">{line.timestamp}</span>
              <span className="break-all">{line.content}</span>
            </div>
          );
        })}
        <div ref={endRef} />
      </div>
    </div>
  );
}
