"use client";

import { useEffect } from "react";
import { cn } from "@/lib/utils";
import { useI18n } from "@/lib/i18n";
import { PipelinePreview } from "./pipeline-preview";
import type { ScanConfig } from "./upload-panel";

interface ScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  isScanning: boolean;
  skillPath?: string;
  config: ScanConfig;
  onScanComplete: () => void;
}

export function ScanModal({ isOpen, onClose, isScanning, skillPath, config, onScanComplete }: ScanModalProps) {
  const { t } = useI18n();

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "";
    }
    return () => { document.body.style.overflow = ""; };
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/40 backdrop-blur-sm"
        onClick={!isScanning ? onClose : undefined}
      />

      {/* Modal */}
      <div className="relative w-[90vw] max-w-5xl h-[85vh] bg-white rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="shrink-0 flex items-center justify-between px-6 py-4 border-b border-stone-200 bg-stone-50/50">
          <div className="flex items-center gap-3">
            <img src="/logo.jpg" alt="SkillWard" className="w-8 h-8 rounded-lg object-cover" />
            <div>
              <span className="text-sm font-bold text-stone-800">
                {isScanning ? t("modal.title.scanning") : t("modal.title.complete")}
              </span>
              <span className="text-[10px] text-stone-400 ml-2 font-mono">
                {skillPath ? skillPath.split("/").pop() : ""}
              </span>
            </div>
            {isScanning && (
              <span className="ml-3 flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-cyan-50 border border-cyan-200">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500" />
                </span>
                <span className="text-[10px] font-semibold text-cyan-700">LIVE</span>
              </span>
            )}
          </div>

          <button
            onClick={onClose}
            className={cn(
              "w-8 h-8 rounded-lg flex items-center justify-center transition-all",
              "text-stone-400 hover:text-stone-600 hover:bg-stone-100"
            )}
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-hidden p-6">
          <PipelinePreview
            isScanning={isScanning}
            skillPath={skillPath}
            policy={config.policy}
            useLlm={config.useLlm}
            useRuntime={config.useRuntime}
            enableAfterTool={config.enableAfterTool}
            onComplete={onScanComplete}
          />
        </div>
      </div>
    </div>
  );
}
