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
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-400 to-teal-500 flex items-center justify-center">
              <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
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
            disabled={isScanning}
            className={cn(
              "w-8 h-8 rounded-lg flex items-center justify-center transition-all",
              isScanning
                ? "text-stone-300 cursor-not-allowed"
                : "text-stone-400 hover:text-stone-600 hover:bg-stone-100"
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
            useVerify={config.useVerify}
            onComplete={onScanComplete}
          />
        </div>
      </div>
    </div>
  );
}
