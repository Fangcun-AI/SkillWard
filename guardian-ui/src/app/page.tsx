"use client";

import { useState, useCallback } from "react";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { useI18n, LanguageToggle } from "@/lib/i18n";
import { UploadPanel, type ScanConfig, type ScanMode } from "@/components/upload-panel";
import { ScanModal } from "@/components/scan-modal";
import { SettingsModal } from "@/components/settings-modal";

export default function Home() {
  const { t } = useI18n();
  const [isScanning, setIsScanning] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [skillPath, setSkillPath] = useState<string | undefined>(undefined);
  const [scanConfig, setScanConfig] = useState<ScanConfig>({
    policy: "balanced", useLlm: true, useRuntime: true, useVerify: true,
  });
  const [scanMode, setScanMode] = useState<ScanMode>("deep");
  const [settingsOpen, setSettingsOpen] = useState(false);

  const handleSubmit = useCallback((path: string | undefined, config: ScanConfig) => {
    setSkillPath(path);
    setScanConfig(config);
    setIsScanning(true);
    setModalOpen(true);
    if (!path) {
      setTimeout(() => {
        setIsScanning(false);
      }, 45000);
    }
  }, []);

  const handleScanComplete = useCallback(() => {
    setIsScanning(false);
  }, []);

  const handleModalClose = useCallback(() => {
    setModalOpen(false);
    setIsScanning(false);
  }, []);

  const stages = [
    { key: "static", stage: t("stage.1.label"), name: t("stage.1.name"), desc: t("stage.1.desc"), icon: (<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m5.231 13.481L15 17.25m-4.5-15H5.625c-.621 0-1.125.504-1.125 1.125v16.5c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9zm3.75 11.625a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" /></svg>), activeIn: ["static", "sandbox", "deep"] },
    { key: "llm", stage: t("stage.2.label"), name: t("stage.2.name"), desc: t("stage.2.desc"), icon: (<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" /></svg>), activeIn: ["static", "sandbox", "deep"] },
    { key: "sandbox", stage: t("stage.3.label"), name: t("stage.3.name"), desc: t("stage.3.desc"), icon: (<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7" /></svg>), activeIn: ["sandbox", "deep"] },
    { key: "trace", stage: t("stage.4.label"), name: t("stage.4.name"), desc: t("stage.4.desc"), icon: (<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5a17.92 17.92 0 01-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" /></svg>), activeIn: ["deep"] },
  ];

  return (
    <div className="min-h-screen bg-warm flex flex-col">
      {/* ── Nav Bar (dark) ── */}
      <nav className="shrink-0">
        <div className="accent-line" />
        <div className="nav-dark">
          <div className="max-w-7xl mx-auto px-8 h-14 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-400 to-teal-500 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                <svg className="w-4.5 h-4.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
              </div>
              <div>
                <span className="font-bold text-sm tracking-wider text-white uppercase">{t("nav.title")}</span>
              </div>
            </div>

            <div className="flex items-center gap-6">
              <span className="text-xs font-semibold px-4 py-1.5 rounded-lg bg-cyan-600 text-white">
                {t("nav.submit")}
              </span>
              <Link
                href="/batch"
                className="text-xs font-semibold px-4 py-1.5 rounded-lg text-stone-400 hover:text-white transition-all"
              >
                {t("nav.batch")}
              </Link>
              <Link
                href="/history"
                className="text-xs font-semibold px-4 py-1.5 rounded-lg text-stone-400 hover:text-white transition-all"
              >
                {t("nav.history")}
              </Link>
              <button
                onClick={() => setSettingsOpen(true)}
                className="flex items-center gap-1.5 text-stone-400 hover:text-white transition-colors px-2.5 py-1.5 rounded-md hover:bg-white/10"
                title={t("settings.title")}
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.24-.438.613-.431.992a6.759 6.759 0 010 .255c-.007.378.138.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.02-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.99l-1.004-.828a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281z" />
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
              </button>
              <LanguageToggle />
              <div className="flex items-center gap-2 text-xs text-stone-500 font-mono">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                {t("nav.online")}
              </div>
            </div>
          </div>
        </div>
      </nav>

      {/* ── Content ── */}
      <div className="flex-1 flex flex-col">
        {/* Hero */}
        <div className="text-center pt-12 pb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-50 border border-cyan-200 mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-500" />
            <span className="text-[11px] font-semibold text-cyan-700 uppercase tracking-wider">{t("hero.badge")}</span>
          </div>
          <h1 className="text-4xl font-bold tracking-tight text-stone-800 mb-2">
            {t("hero.title_pre")}<span className="text-cyan-600">{t("hero.title_accent")}</span>{t("hero.title_post")}
          </h1>
          <p className="text-sm text-stone-400 max-w-lg mx-auto">
            {t("hero.desc")}
          </p>
        </div>

        {/* Upload panel */}
        <div className="max-w-6xl mx-auto px-8 w-full pb-8">
          <UploadPanel onSubmit={handleSubmit} isScanning={isScanning} onScanModeChange={setScanMode} />
        </div>

        {/* Pipeline stages */}
        <div className="max-w-6xl mx-auto px-8 w-full pb-24">
          <div className="text-xs font-bold text-stone-400 uppercase tracking-wider mb-4 px-1">{t("pipeline.title")}</div>
          <div className="flex items-stretch gap-0">
            {stages.map((s, i, arr) => {
              const active = s.activeIn.includes(scanMode);
              return (
                <div key={s.key} className="flex items-stretch flex-1">
                  <div className={cn(
                    "flex-1 rounded-lg px-4 py-4 transition-all duration-300",
                    active ? "bg-white border border-cyan-200 shadow-sm" : "bg-stone-100/60 border border-transparent"
                  )}>
                    <div className="flex items-center gap-2 mb-2">
                      <div className={cn(
                        "w-8 h-8 rounded-lg flex items-center justify-center transition-colors duration-300",
                        active ? "bg-cyan-100 text-cyan-600" : "bg-stone-200/80 text-stone-400"
                      )}>
                        {s.icon}
                      </div>
                      <span className={cn(
                        "text-[10px] font-mono font-bold transition-colors duration-300",
                        active ? "text-cyan-500" : "text-stone-300"
                      )}>{s.stage}</span>
                    </div>
                    <div className={cn(
                      "text-sm font-bold mb-1 transition-colors duration-300",
                      active ? "text-stone-700" : "text-stone-400"
                    )}>{s.name}</div>
                    <p className={cn(
                      "text-[11px] leading-relaxed transition-colors duration-300",
                      active ? "text-stone-500" : "text-stone-300"
                    )}>{s.desc}</p>
                  </div>
                  {i < arr.length - 1 && (
                    <div className="flex items-center px-1.5 shrink-0">
                      <svg className={cn("w-4 h-4 transition-colors duration-300", active && arr[i+1].activeIn.includes(scanMode) ? "text-cyan-400" : "text-stone-300")} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                      </svg>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── Scan Modal ── */}
      <ScanModal
        isOpen={modalOpen}
        onClose={handleModalClose}
        isScanning={isScanning}
        skillPath={skillPath}
        config={scanConfig}
        onScanComplete={handleScanComplete}
      />

      {/* ── Settings Modal ── */}
      <SettingsModal isOpen={settingsOpen} onClose={() => setSettingsOpen(false)} />
    </div>
  );
}
