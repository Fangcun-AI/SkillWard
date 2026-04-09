"use client";

import { useState, useEffect, useCallback } from "react";
import { cn } from "@/lib/utils";
import { useI18n } from "@/lib/i18n";

const API_BASE = process.env.NEXT_PUBLIC_GUARDIAN_API || "http://localhost:8899";

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface Settings {
  llm_provider: string;
  llm_model: string;
  llm_api_key: string;
  llm_base_url: string;
  llm_api_version: string;
  docker_image: string;
  docker_model: string;
  docker_azure_url: string;
  docker_azure_key: string;
  safety_threshold: number;
  phase1_timeout: number;
  phase2_timeout: number;
  max_retries: number;
  retry_delay: number;
  fangcun_api_url: string;
  fangcun_api_key: string;
  guard_plugin_api_url: string;
  guard_plugin_api_key: string;
}

const defaultSettings: Settings = {
  llm_provider: "openai",
  llm_model: "gpt-4o-mini",
  llm_api_key: "",
  llm_base_url: "",
  llm_api_version: "2025-04-01-preview",
  docker_image: "openclaw:fangcun-guard-arm64",
  docker_model: "",
  docker_azure_url: "",
  docker_azure_key: "",
  safety_threshold: 0.3,
  phase1_timeout: 300,
  phase2_timeout: 300,
  max_retries: 2,
  retry_delay: 10,
  fangcun_api_url: "",
  fangcun_api_key: "",
  guard_plugin_api_url: "",
  guard_plugin_api_key: "",
};

const providers = [
  { id: "azure", name: "Azure OpenAI" },
  { id: "openai", name: "OpenAI" },
  { id: "local_vllm", name: "Local vLLM" },
  { id: "custom", name: "Custom (litellm)" },
];

export function SettingsModal({ isOpen, onClose }: SettingsModalProps) {
  const { t } = useI18n();
  const [settings, setSettings] = useState<Settings>(defaultSettings);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [showKeys, setShowKeys] = useState<Record<string, boolean>>({});

  const fetchSettings = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/settings`);
      if (res.ok) {
        const data = await res.json();
        setSettings({ ...defaultSettings, ...data });
      }
    } catch {
      // Backend not available, use defaults
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      fetchSettings();
      setSaved(false);
      setTestResult(null);
    }
  }, [isOpen, fetchSettings]);

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "";
    }
    return () => { document.body.style.overflow = ""; };
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await fetch(`${API_BASE}/api/settings`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings),
      });
      if (res.ok) {
        const data = await res.json();
        setSettings({ ...defaultSettings, ...data });
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
      }
    } catch {
      // ignore
    }
    setSaving(false);
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/debug/llm`);
      const data = await res.json();
      if (data.ok) {
        setTestResult({ ok: true, msg: `${t("settings.test.ok")}: ${data.response}` });
      } else {
        setTestResult({ ok: false, msg: `${t("settings.test.fail")}: ${data.error}` });
      }
    } catch (e) {
      setTestResult({ ok: false, msg: `${t("settings.test.fail")}: API unreachable` });
    }
    setTesting(false);
  };

  const handleReset = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/settings/reset`, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        setSettings({ ...defaultSettings, ...data });
      }
    } catch {
      setSettings(defaultSettings);
    }
  };

  const update = (key: keyof Settings, value: string | number) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  };

  const toggleKeyVisibility = (key: string) => {
    setShowKeys(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const InputField = ({ label, field, type = "text", placeholder = "" }: {
    label: string; field: keyof Settings; type?: string; placeholder?: string;
  }) => {
    const isPassword = type === "password";
    const visible = showKeys[field] || false;
    return (
      <div>
        <label className="text-[11px] text-stone-500 font-medium block mb-1">{label}</label>
        <div className="relative">
          <input
            type={isPassword && !visible ? "password" : "text"}
            value={String(settings[field])}
            onChange={e => update(field, type === "number" ? Number(e.target.value) : e.target.value)}
            placeholder={placeholder}
            className="w-full bg-white border border-stone-300 rounded-lg px-3 py-2 text-sm text-stone-700 placeholder:text-stone-400 focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 font-mono"
          />
          {isPassword && (
            <button
              type="button"
              onClick={() => toggleKeyVisibility(field)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-stone-400 hover:text-stone-600"
            >
              {visible ? (
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" />
                </svg>
              ) : (
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
              )}
            </button>
          )}
        </div>
      </div>
    );
  };

  const showBaseUrl = settings.llm_provider !== "openai";
  const showApiVersion = settings.llm_provider === "azure";

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center">
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={onClose} />

      <div className="relative w-[680px] max-h-[85vh] bg-white rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="shrink-0 flex items-center justify-between px-6 py-4 border-b border-stone-200 bg-stone-50/50">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-stone-600 to-stone-800 flex items-center justify-center">
              <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.24-.438.613-.431.992a6.759 6.759 0 010 .255c-.007.378.138.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.02-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.99l-1.004-.828a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281z" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
            </div>
            <span className="text-sm font-bold text-stone-700">{t("settings.title")}</span>
          </div>
          <button onClick={onClose} className="text-stone-400 hover:text-stone-600 transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">

          {/* LLM Configuration */}
          <section>
            <h3 className="text-xs font-bold text-cyan-700 uppercase tracking-wider mb-3">{t("settings.llm.title")}</h3>
            <div className="space-y-3">
              <div>
                <label className="text-[11px] text-stone-500 font-medium block mb-1">{t("settings.llm.provider")}</label>
                <div className="grid grid-cols-4 gap-2">
                  {providers.map(p => (
                    <button
                      key={p.id}
                      onClick={() => update("llm_provider", p.id)}
                      className={cn(
                        "text-xs py-2 px-3 rounded-lg border font-medium transition-all",
                        settings.llm_provider === p.id
                          ? "border-cyan-500 bg-cyan-50 text-cyan-700"
                          : "border-stone-200 text-stone-500 hover:border-stone-300"
                      )}
                    >
                      {p.name}
                    </button>
                  ))}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <InputField label={t("settings.llm.model")} field="llm_model" placeholder="gpt-4o-mini" />
                <InputField label={t("settings.llm.api_key")} field="llm_api_key" type="password" placeholder="sk-..." />
              </div>
              {showBaseUrl && (
                <InputField label={t("settings.llm.base_url")} field="llm_base_url" placeholder="https://your-instance.openai.azure.com" />
              )}
              {showApiVersion && (
                <InputField label={t("settings.llm.api_version")} field="llm_api_version" placeholder="2025-04-01-preview" />
              )}
            </div>
          </section>

          {/* Docker Sandbox */}
          <section>
            <h3 className="text-xs font-bold text-cyan-700 uppercase tracking-wider mb-3">{t("settings.docker.title")}</h3>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <InputField label={t("settings.docker.image")} field="docker_image" placeholder="openclaw:fangcun-guard-arm64" />
                <InputField label={t("settings.docker.model")} field="docker_model" placeholder="azure-openai-responses/gpt-5.4@azure" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <InputField label={t("settings.docker.azure_url")} field="docker_azure_url" placeholder="https://..." />
                <InputField label={t("settings.docker.azure_key")} field="docker_azure_key" type="password" placeholder="API key for Docker container" />
              </div>
            </div>
          </section>

          {/* Safety Thresholds */}
          <section>
            <h3 className="text-xs font-bold text-cyan-700 uppercase tracking-wider mb-3">{t("settings.safety.title")}</h3>
            <div className="space-y-3">
              <div>
                <label className="text-[11px] text-stone-500 font-medium block mb-1">
                  {t("settings.safety.threshold")}: <span className="text-cyan-600 font-bold">{settings.safety_threshold}</span>
                </label>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={settings.safety_threshold}
                  onChange={e => update("safety_threshold", Number(e.target.value))}
                  className="w-full h-1.5 bg-stone-200 rounded-full appearance-none cursor-pointer accent-cyan-600"
                />
                <div className="flex justify-between text-[10px] text-stone-400 mt-1">
                  <span>0.0 (strict)</span>
                  <span>1.0 (permissive)</span>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <InputField label={t("settings.safety.phase1_timeout")} field="phase1_timeout" type="number" />
                <InputField label={t("settings.safety.phase2_timeout")} field="phase2_timeout" type="number" />
              </div>
            </div>
          </section>

          {/* FangcunGuard API (host-side) */}
          <section>
            <h3 className="text-xs font-bold text-stone-400 uppercase tracking-wider mb-3">{t("settings.fangcun.title")}</h3>
            <div className="grid grid-cols-2 gap-3">
              <InputField label={t("settings.fangcun.url")} field="fangcun_api_url" placeholder="http://..." />
              <InputField label={t("settings.fangcun.key")} field="fangcun_api_key" type="password" />
            </div>
          </section>

          {/* Guard Plugin (inside Docker container) */}
          <section>
            <h3 className="text-xs font-bold text-stone-400 uppercase tracking-wider mb-3">{t("settings.guard_plugin.title")}</h3>
            <p className="text-[11px] text-stone-400 mb-3">{t("settings.guard_plugin.desc")}</p>
            <div className="grid grid-cols-2 gap-3">
              <InputField label={t("settings.guard_plugin.url")} field="guard_plugin_api_url" placeholder="http://your-server:5001/v1/guardrails" />
              <InputField label={t("settings.guard_plugin.key")} field="guard_plugin_api_key" type="password" placeholder="your-api-key" />
            </div>
          </section>
        </div>

        {/* Footer */}
        <div className="shrink-0 flex items-center justify-between px-6 py-4 border-t border-stone-200 bg-stone-50/30">
          <div className="flex items-center gap-3">
            <button
              onClick={handleReset}
              className="text-xs text-stone-400 hover:text-red-500 transition-colors font-medium"
            >
              {t("settings.reset")}
            </button>
            {testResult && (
              <span className={cn("text-xs font-medium", testResult.ok ? "text-emerald-600" : "text-red-500")}>
                {testResult.msg.slice(0, 80)}
              </span>
            )}
            {saved && (
              <span className="text-xs font-medium text-emerald-600 flex items-center gap-1">
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                </svg>
                {t("settings.saved")}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleTest}
              disabled={testing}
              className={cn(
                "px-4 py-2 rounded-lg text-xs font-bold border transition-all",
                testing
                  ? "border-stone-200 text-stone-400 cursor-wait"
                  : "border-stone-300 text-stone-600 hover:border-cyan-500 hover:text-cyan-600"
              )}
            >
              {testing ? (
                <span className="flex items-center gap-1.5">
                  <span className="w-3 h-3 border-2 border-stone-400 border-t-transparent rounded-full animate-spin" />
                  Testing...
                </span>
              ) : t("settings.test")}
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className={cn(
                "px-6 py-2 rounded-lg text-xs font-bold transition-all",
                saving
                  ? "bg-stone-200 text-stone-400 cursor-wait"
                  : "bg-gradient-to-r from-cyan-600 to-teal-600 text-white hover:from-cyan-700 hover:to-teal-700 shadow-lg shadow-cyan-600/20"
              )}
            >
              {saving ? "..." : t("settings.save")}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
