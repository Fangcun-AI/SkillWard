"use client";

import { useState } from "react";
import type { SkillPrescanResult, StageStatus } from "@/lib/types";
import { StageHeader } from "./stage-header";
import { SkillCard } from "./skill-card";
import { cn } from "@/lib/utils";

interface Stage1Props {
  status: StageStatus;
  results: Record<string, SkillPrescanResult>;
  onShowRemediation: (skillName: string) => void;
}

export function Stage1Section({ status, results, onShowRemediation }: Stage1Props) {
  const [filter, setFilter] = useState<"all" | "unsafe" | "safe">("all");

  const skills = Object.values(results);
  const filtered = skills.filter((s) => {
    if (filter === "unsafe") return s.safety_verdict === "UNSAFE";
    if (filter === "safe") return s.safety_verdict === "SAFE";
    return true;
  });

  filtered.sort((a, b) => {
    if (a.safety_verdict !== b.safety_verdict) return a.safety_verdict === "UNSAFE" ? -1 : 1;
    return a.safety_confidence - b.safety_confidence;
  });

  const safeCount = skills.filter((s) => s.safety_verdict === "SAFE").length;
  const unsafeCount = skills.length - safeCount;

  return (
    <section className="space-y-4">
      <StageHeader
        number={1}
        title="Pre-scan: Static Analysis + LLM Safety Scoring"
        subtitle={`YARA, regex, behavioral dataflow + LLM confidence scoring on ${skills.length} skills`}
        status={status}
      />

      {/* Pipeline steps */}
      <div className="grid grid-cols-3 gap-3">
        <StepCard icon="1" label="Static Analysis" detail="Pattern · YARA · Behavioral" color="from-blue-50 to-cyan-50" borderColor="border-blue-200" iconBg="bg-blue-100 text-blue-600" />
        <StepCard icon="2" label="LLM Scoring" detail={`${skills.length} skills · threshold 0.3`} color="from-violet-50 to-purple-50" borderColor="border-violet-200" iconBg="bg-violet-100 text-violet-600" />
        <StepCard icon="3" label="Extraction" detail={`${safeCount} safe → safe-skills/`} color="from-emerald-50 to-teal-50" borderColor="border-emerald-200" iconBg="bg-emerald-100 text-emerald-600" />
      </div>

      {/* Filter tabs */}
      <div className="flex items-center gap-1 bg-white rounded-lg p-1 w-fit border border-stone-200 shadow-sm">
        {([
          { key: "all" as const, label: `All ${skills.length}` },
          { key: "unsafe" as const, label: `Unsafe ${unsafeCount}` },
          { key: "safe" as const, label: `Safe ${safeCount}` },
        ]).map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setFilter(key)}
            className={cn(
              "px-3.5 py-1.5 text-[11px] font-bold rounded-md transition-all",
              filter === key
                ? key === "unsafe" ? "bg-red-50 text-red-600 border border-red-200"
                : key === "safe" ? "bg-emerald-50 text-emerald-600 border border-emerald-200"
                : "bg-amber-50 text-amber-700 border border-amber-200"
                : "text-stone-400 hover:text-stone-600 border border-transparent"
            )}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="space-y-2">
        {filtered.map((skill) => (
          <SkillCard key={skill.skill_name} skill={skill} onShowRemediation={onShowRemediation} />
        ))}
      </div>
    </section>
  );
}

function StepCard({ icon, label, detail, color, borderColor, iconBg }: { icon: string; label: string; detail: string; color: string; borderColor: string; iconBg: string }) {
  return (
    <div className={cn("flex items-center gap-3 p-3.5 rounded-xl bg-gradient-to-r border", color, borderColor)}>
      <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center text-xs font-mono font-bold", iconBg)}>
        {icon}
      </div>
      <div>
        <div className="text-[12px] font-semibold text-stone-700">{label}</div>
        <div className="text-[10px] text-stone-400">{detail}</div>
      </div>
    </div>
  );
}
