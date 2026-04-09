import type { Severity, RuntimeStatus } from "./types";

export function severityColor(s: Severity): string {
  switch (s) {
    case "CRITICAL": return "text-red-600";
    case "HIGH": return "text-orange-600";
    case "MEDIUM": return "text-amber-600";
    case "LOW": return "text-cyan-700";
    case "INFO": return "text-stone-500";
    case "SAFE": return "text-emerald-600";
  }
}

export function severityBg(s: Severity): string {
  switch (s) {
    case "CRITICAL": return "bg-red-100 text-red-700 border-red-300";
    case "HIGH": return "bg-orange-100 text-orange-700 border-orange-300";
    case "MEDIUM": return "bg-amber-100 text-amber-700 border-amber-300";
    case "LOW": return "bg-cyan-100 text-cyan-700 border-cyan-300";
    case "INFO": return "bg-stone-100 text-stone-600 border-stone-300";
    case "SAFE": return "bg-emerald-100 text-emerald-700 border-emerald-300";
  }
}

export function severityBorder(s: Severity): string {
  switch (s) {
    case "CRITICAL": return "sev-critical";
    case "HIGH": return "sev-high";
    case "MEDIUM": return "sev-medium";
    case "LOW": return "sev-low";
    case "INFO": return "";
    case "SAFE": return "sev-safe";
  }
}

export function runtimeStatusColor(s: RuntimeStatus): string {
  switch (s) {
    case "BLOCKED": return "bg-red-100 text-red-700 border-red-300";
    case "ALERT": return "bg-orange-100 text-orange-700 border-orange-300";
    case "CONTENT_RISK": return "bg-orange-100 text-orange-700 border-orange-300";
    case "CAPABILITY_RISK": return "bg-amber-100 text-amber-700 border-amber-300";
    case "TIMEOUT": return "bg-stone-100 text-stone-600 border-stone-300";
    case "ERROR": return "bg-stone-100 text-stone-600 border-stone-300";
    case "INCOMPLETE": return "bg-stone-100 text-stone-600 border-stone-300";
    case "PASSED": return "bg-emerald-100 text-emerald-700 border-emerald-300";
  }
}

export function runtimeGlow(s: RuntimeStatus): string {
  switch (s) {
    case "BLOCKED": return "glow-red";
    case "ALERT": case "CONTENT_RISK": return "glow-orange";
    case "CAPABILITY_RISK": return "glow-yellow";
    default: return "";
  }
}

export function confidenceColor(c: number): string {
  if (c >= 0.7) return "text-emerald-600";
  if (c >= 0.3) return "text-amber-600";
  return "text-red-600";
}

export function confidenceBarBg(c: number): string {
  if (c >= 0.7) return "from-emerald-400 to-teal-500";
  if (c >= 0.3) return "from-amber-400 to-yellow-500";
  return "from-red-400 to-rose-500";
}
