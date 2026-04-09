"use client";

import { useState } from "react";
import type { RuntimeResult, StageStatus } from "@/lib/types";
import { StageHeader } from "./stage-header";
import { RuntimeCard } from "./runtime-card";
import { cn } from "@/lib/utils";

interface Stage2Props {
  status: StageStatus;
  results: RuntimeResult[];
  title?: string;
  subtitle?: string;
  stageNumber?: number;
  falseNegativeSkills?: Set<string>;
}

export function Stage2Section({
  status,
  results,
  title = "Docker Runtime Detection (All Skills)",
  subtitle = "Two-phase Docker test: Phase 1 (Guardian OFF) environment prep → Phase 2 (Guardian ON) skill execution",
  stageNumber = 2,
  falseNegativeSkills,
}: Stage2Props) {
  const [filter, setFilter] = useState<"all" | "issues" | "passed">("all");

  const filtered = results.filter((r) => {
    if (filter === "issues") return r.status !== "PASSED";
    if (filter === "passed") return r.status === "PASSED";
    return true;
  });

  filtered.sort((a, b) => {
    if ((a.status !== "PASSED") !== (b.status !== "PASSED")) return a.status !== "PASSED" ? -1 : 1;
    return 0;
  });

  const issueCount = results.filter((r) => r.status !== "PASSED").length;
  const passedCount = results.filter((r) => r.status === "PASSED").length;

  return (
    <section className="space-y-4">
      <StageHeader number={stageNumber} title={title} subtitle={subtitle} status={status} />

      {/* Phase explanation */}
      <div className="grid grid-cols-2 gap-3">
        <div className="flex items-center gap-3 p-3.5 rounded-xl bg-gradient-to-r from-stone-50 to-stone-100/50 border border-stone-200">
          <div className="w-8 h-8 rounded-lg bg-stone-200 flex items-center justify-center">
            <span className="text-[10px] font-mono font-bold text-stone-600">P1</span>
          </div>
          <div>
            <div className="text-[12px] font-semibold text-stone-700">Environment Prep</div>
            <div className="text-[10px] text-stone-400">Guardian OFF · install deps · create files</div>
          </div>
        </div>
        <div className="flex items-center gap-3 p-3.5 rounded-xl bg-gradient-to-r from-cyan-50 to-blue-50 border border-cyan-200">
          <div className="w-8 h-8 rounded-lg bg-cyan-100 flex items-center justify-center">
            <span className="text-[10px] font-mono font-bold text-cyan-600">P2</span>
          </div>
          <div>
            <div className="text-[12px] font-semibold text-stone-700">Skill Execution</div>
            <div className="text-[10px] text-stone-400">Guardian ON · monitor tool calls · detect threats</div>
          </div>
        </div>
      </div>

      {/* Filter */}
      <div className="flex items-center gap-1 bg-white rounded-lg p-1 w-fit border border-stone-200 shadow-sm">
        {([
          { key: "all" as const, label: `All ${results.length}` },
          { key: "issues" as const, label: `Issues ${issueCount}` },
          { key: "passed" as const, label: `Passed ${passedCount}` },
        ]).map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setFilter(key)}
            className={cn(
              "px-3.5 py-1.5 text-[11px] font-bold rounded-md transition-all",
              filter === key
                ? key === "issues" ? "bg-red-50 text-red-600 border border-red-200"
                : key === "passed" ? "bg-emerald-50 text-emerald-600 border border-emerald-200"
                : "bg-amber-50 text-amber-700 border border-amber-200"
                : "text-stone-400 hover:text-stone-600 border border-transparent"
            )}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="space-y-2">
        {filtered.map((r) => (
          <RuntimeCard
            key={r.skill}
            result={r}
            isFalseNegative={falseNegativeSkills?.has(r.skill)}
          />
        ))}
      </div>
    </section>
  );
}
