"use client";

import { useState, useRef } from "react";
import { cn } from "@/lib/utils";
import { useI18n } from "@/lib/i18n";

const API_BASE = process.env.NEXT_PUBLIC_GUARDIAN_API || "http://localhost:8899";

export type ScanMode = "static" | "sandbox" | "deep";

export interface ScanConfig {
  policy: string;
  useLlm: boolean;
  useRuntime: boolean;
  enableAfterTool: boolean;
}

interface UploadPanelProps {
  onSubmit: (skillPath: string | undefined, config: ScanConfig) => void;
  isScanning: boolean;
  onScanModeChange?: (mode: ScanMode) => void;
}

export function UploadPanel({ onSubmit, isScanning, onScanModeChange }: UploadPanelProps) {
  const { t } = useI18n();
  const [tab, setTab] = useState<"file" | "url">("file");
  const [scanMode, setScanMode] = useState<ScanMode>("deep");
  const policy = "balanced";
  const llmAnalysis = true;
  const runtimeTest = scanMode === "sandbox" || scanMode === "deep";
  const enableAfterTool = scanMode === "deep";
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedFiles, setSelectedFiles] = useState<FileList | null>(null);
  const [selectedFileCount, setSelectedFileCount] = useState(0);
  const [isDragOver, setIsDragOver] = useState(false);
  const [localPath, setLocalPath] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const scanConfig: ScanConfig = { policy, useLlm: llmAnalysis, useRuntime: runtimeTest, enableAfterTool };

  const handleSubmit = async () => {
    if (localPath.trim()) {
      onSubmit(localPath.trim(), scanConfig);
      return;
    }
    if (selectedFiles && selectedFiles.length > 0) {
      try {
        const formData = new FormData();
        for (let i = 0; i < selectedFiles.length; i++) {
          const file = selectedFiles[i];
          formData.append("files", file, file.webkitRelativePath || file.name);
        }
        const res = await fetch(`${API_BASE}/api/scan/upload-folder`, { method: "POST", body: formData });
        const data = await res.json();
        if (data.skill_path) {
          onSubmit(data.skill_path, scanConfig);
          return;
        }
      } catch {
        // Fall through to demo mode
      }
    }
    onSubmit(undefined, scanConfig);
  };

  const scanModes: { key: ScanMode; icon: React.ReactNode; name: string; sub: string; desc: string }[] = [
    {
      key: "static",
      icon: (
        <svg className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
        </svg>
      ),
      name: t("mode.static.name"),
      sub: t("mode.static.sub"),
      desc: t("mode.static.desc"),
    },
    {
      key: "sandbox",
      icon: (
        <svg className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008z" />
        </svg>
      ),
      name: t("mode.sandbox.name"),
      sub: t("mode.sandbox.sub"),
      desc: t("mode.sandbox.desc"),
    },
    {
      key: "deep",
      icon: (
        <svg className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5a17.92 17.92 0 01-8.716-2.247m0 0A9.015 9.015 0 003 12c0-1.605.42-3.113 1.157-4.418" />
        </svg>
      ),
      name: t("mode.deep.name"),
      sub: t("mode.deep.sub"),
      desc: t("mode.deep.desc"),
    },
  ];

  return (
    <div className="flex gap-6">
      {/* Left: Upload */}
      <div className="flex-1 card-white rounded-xl p-6">
        {/* Tabs */}
        <div className="flex gap-6 mb-6 border-b border-stone-200 pb-3">
          <button
            onClick={() => setTab("file")}
            className={cn(
              "text-sm font-bold pb-1 border-b-2 transition-colors",
              tab === "file" ? "text-cyan-700 border-cyan-600" : "text-stone-400 border-transparent hover:text-stone-600"
            )}
          >
            {t("upload.tab.file")}
          </button>
          <button
            onClick={() => setTab("url")}
            className={cn(
              "text-sm font-bold pb-1 border-b-2 transition-colors",
              tab === "url" ? "text-cyan-700 border-cyan-600" : "text-stone-400 border-transparent hover:text-stone-600"
            )}
          >
            {t("upload.tab.url")}
          </button>
        </div>

        {tab === "file" ? (
          <>
            <input
              ref={fileInputRef}
              type="file"
              {...{ webkitdirectory: "", directory: "" } as Record<string, string>}
              multiple
              className="hidden"
              onChange={(e) => {
                const files = e.target.files;
                if (files && files.length > 0) {
                  const path = files[0].webkitRelativePath;
                  const folderName = path ? path.split("/")[0] : files[0].name;
                  setSelectedFile(new File(["placeholder"], folderName));
                  setSelectedFiles(files);
                  setSelectedFileCount(files.length);
                }
              }}
            />
            <div
              onClick={() => fileInputRef.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
              onDragLeave={() => setIsDragOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDragOver(false);
                const file = e.dataTransfer.files?.[0];
                if (file) setSelectedFile(file);
              }}
              className={cn(
                "drop-zone rounded-xl flex flex-col items-center justify-center py-14 px-6 cursor-pointer group mb-6",
                isDragOver && "!border-cyan-500 !bg-cyan-50/50"
              )}
            >
              {selectedFile ? (
                <>
                  <div className="w-14 h-14 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center mb-4">
                    <svg className="w-7 h-7 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <p className="text-sm text-stone-700 font-semibold mb-1">{selectedFile.name}</p>
                  <p className="text-xs text-stone-400 font-mono">
                    {selectedFileCount > 0 ? `${selectedFileCount}${t("upload.drop.files_count")}` : `${(selectedFile.size / 1024).toFixed(1)} KB`}
                  </p>
                  <button
                    onClick={(e) => { e.stopPropagation(); setSelectedFile(null); setSelectedFiles(null); setSelectedFileCount(0); if (fileInputRef.current) fileInputRef.current.value = ""; }}
                    className="mt-3 text-xs text-stone-400 hover:text-red-500 transition-colors"
                  >
                    {t("upload.drop.remove")}
                  </button>
                </>
              ) : (
                <>
                  <div className="w-14 h-14 rounded-xl bg-cyan-50 border border-cyan-200 flex items-center justify-center mb-4 group-hover:scale-105 transition-transform">
                    <svg className="w-7 h-7 text-cyan-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5m8.25 3v6.75m0 0l-3-3m3 3l3-3M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125z" />
                    </svg>
                  </div>
                  <p className="text-sm text-stone-500 mb-3">{t("upload.drop.prompt")}</p>
                  <p className="text-xs text-stone-400 font-mono">
                    {t("upload.drop.formats")}<span className="text-stone-600">.zip</span> · <span className="text-stone-600">.tar.gz</span> · <span className="text-stone-600">.tgz</span>
                  </p>
                  <p className="text-xs text-stone-400 mt-1">
                    {t("upload.drop.must_contain")}<span className="text-cyan-700 font-bold">SKILL.md</span>
                  </p>
                </>
              )}
            </div>
          </>
        ) : (
          <div className="py-8">
            <label className="text-xs text-stone-500 mb-2 block font-medium">{t("upload.url.label")}</label>
            <input
              type="url"
              placeholder="https://github.com/org/skill-name"
              className="w-full bg-white border border-stone-300 rounded-lg px-3 py-2.5 text-sm text-stone-700 placeholder:text-stone-400 focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 transition-all font-mono"
            />
            <p className="text-[11px] text-stone-400 mt-2">{t("upload.url.hint")}</p>
          </div>
        )}
      </div>

      {/* Right: Scan Mode */}
      <div className="w-[380px] shrink-0 flex flex-col">
        <div className="card-white rounded-xl p-5 flex-1 flex flex-col">
          <div className="text-xs font-bold text-cyan-700 uppercase tracking-wider mb-4">{t("mode.title")}</div>
          <div className="space-y-3 flex-1 flex flex-col justify-center">
            {scanModes.map((m) => (
              <button
                key={m.key}
                onClick={() => { setScanMode(m.key); onScanModeChange?.(m.key); }}
                className={cn(
                  "w-full flex items-center gap-4 px-5 py-4 rounded-lg border transition-all text-left",
                  scanMode === m.key
                    ? "border-cyan-500 bg-cyan-50 shadow-sm"
                    : "border-stone-200 hover:border-stone-300"
                )}
              >
                <div className={cn(
                  "shrink-0 w-12 h-12 rounded-lg flex items-center justify-center",
                  scanMode === m.key ? "bg-cyan-100 text-cyan-700" : "bg-stone-100 text-stone-400"
                )}>
                  {m.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={cn("text-sm font-bold", scanMode === m.key ? "text-cyan-700" : "text-stone-700")}>{m.name}</span>
                    <span className={cn("text-[10px] font-mono whitespace-nowrap", scanMode === m.key ? "text-cyan-500" : "text-stone-400")}>{m.sub}</span>
                  </div>
                  <div className={cn("text-[11px] mt-0.5", scanMode === m.key ? "text-cyan-600" : "text-stone-400")}>{m.desc}</div>
                </div>
                {scanMode === m.key && (
                  <svg className="w-5 h-5 text-cyan-600 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                )}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom submit bar */}
      <div className="fixed bottom-0 left-0 right-0 border-t border-stone-300 bg-white/90 backdrop-blur-xl px-8 py-4 z-50 shadow-lg shadow-black/5">
        <div className="max-w-6xl mx-auto flex items-center justify-end gap-4">
          <button
            onClick={handleSubmit}
            disabled={isScanning}
            className={cn(
              "px-8 py-2.5 rounded-lg text-sm font-bold flex items-center gap-2 transition-all",
              isScanning
                ? "bg-stone-200 text-stone-400 cursor-wait"
                : "bg-gradient-to-r from-cyan-600 to-teal-600 text-white hover:from-cyan-700 hover:to-teal-700 shadow-lg shadow-cyan-600/20"
            )}
          >
            {isScanning ? (
              <>
                <span className="w-4 h-4 border-2 border-stone-400 border-t-transparent rounded-full animate-spin" />
                {t("upload.scanning")}
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z" />
                </svg>
                {t("upload.submit")}
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
