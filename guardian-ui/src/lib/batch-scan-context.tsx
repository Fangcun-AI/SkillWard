"use client";

import {
  createContext,
  useContext,
  useState,
  useRef,
  useCallback,
  useEffect,
  ReactNode,
} from "react";
import { useI18n } from "./i18n";

const API_BASE = process.env.NEXT_PUBLIC_GUARDIAN_API || "http://localhost:8899";

export interface SkillResult {
  skill_name: string;
  verdict: string;
  false_negative: boolean;
  latency: number;
  findings: number;
  progress: number;
  error?: string;
}

export interface BatchSummary {
  batch_id: string;
  total_skills: number;
  scanned: number;
  safe: number;
  unsafe: number;
  error: number;
  false_negatives: number;
  latency_total: number;
  latency_avg: number;
}

interface StartParams {
  skillsDir: string;
  concurrency: number;
  useLlm: boolean;
  useRuntime: boolean;
  enableAfterTool: boolean;
}

interface BatchScanContextValue {
  scanning: boolean;
  batchId: string | null;
  results: SkillResult[];
  summary: BatchSummary | null;
  totalSkills: number;
  scannedCount: number;
  errorMsg: string;
  logs: string[];
  startScan: (p: StartParams) => void;
  stopScan: () => void;
  resetScan: () => void;
}

const BatchScanContext = createContext<BatchScanContextValue | null>(null);

export function BatchScanProvider({ children }: { children: ReactNode }) {
  const { locale } = useI18n();
  const [scanning, setScanning] = useState(false);
  const [batchId, setBatchId] = useState<string | null>(null);
  const [results, setResults] = useState<SkillResult[]>([]);
  const [summary, setSummary] = useState<BatchSummary | null>(null);
  const [totalSkills, setTotalSkills] = useState(0);
  const [scannedCount, setScannedCount] = useState(0);
  const [errorMsg, setErrorMsg] = useState("");
  const [logs, setLogs] = useState<string[]>([]);
  const abortRef = useRef<AbortController | null>(null);

  const startScan = useCallback(
    async (p: StartParams) => {
      if (!p.skillsDir) return;
      abortRef.current?.abort();
      setScanning(true);
      setResults([]);
      setSummary(null);
      setTotalSkills(0);
      setScannedCount(0);
      setErrorMsg("");
      setLogs([]);
      const bid = `batch-${Date.now().toString(36)}`;
      setBatchId(bid);
      const params = new URLSearchParams({
        skills_dir: p.skillsDir,
        concurrency: String(p.concurrency),
        use_llm: String(p.useLlm),
        use_runtime: String(p.useRuntime),
        enable_after_tool: String(p.enableAfterTool),
        lang: locale,
      });
      const controller = new AbortController();
      abortRef.current = controller;
      try {
        const res = await fetch(
          `${API_BASE}/api/batch/${bid}/stream?${params}`,
          { signal: controller.signal }
        );
        if (!res.ok) {
          setErrorMsg(`HTTP ${res.status}`);
          if (abortRef.current === controller) setScanning(false);
          return;
        }
        const reader = res.body?.getReader();
        if (!reader) {
          if (abortRef.current === controller) setScanning(false);
          return;
        }
        const decoder = new TextDecoder();
        let buffer = "";
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";
          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            try {
              const evt = JSON.parse(line.slice(6));
              setLogs((prev) => [...prev, evt.text]);
              if (evt.type === "batch_start" && evt.data) {
                setTotalSkills(evt.data.total as number);
              } else if (evt.type === "skill_done" && evt.data) {
                const d = evt.data as SkillResult;
                setResults((prev) => [...prev, d]);
                setScannedCount(d.progress);
              } else if (evt.type === "batch_done" && evt.data) {
                setSummary(evt.data as BatchSummary);
              } else if (evt.type === "error") {
                setErrorMsg(evt.text);
              }
            } catch {
              // ignore parse errors
            }
          }
        }
        if (abortRef.current === controller) setScanning(false);
      } catch (err) {
        if ((err as Error).name === "AbortError") {
          if (abortRef.current === controller) setScanning(false);
          return;
        }
        // Real network error (not user abort): fall back to /api/batch/{bid}
        // to check if the batch actually completed server-side.
        try {
          const res = await fetch(`${API_BASE}/api/batch/${bid}`);
          const data = await res.json();
          if (
            data.status === "done" ||
            (typeof data.scanned === "number" &&
              typeof data.total_skills === "number" &&
              data.scanned >= data.total_skills)
          ) {
            setScannedCount(data.scanned);
            setTotalSkills(data.total_skills);
            setSummary(data as BatchSummary);
            if (abortRef.current === controller) setScanning(false);
            return;
          }
        } catch {
          // fallback fetch failed — fall through to error message
        }
        setErrorMsg("连接中断，请刷新页面查看结果");
        if (abortRef.current === controller) setScanning(false);
      }
    },
    [locale]
  );

  const stopScan = useCallback(() => {
    abortRef.current?.abort();
    setScanning(false);
  }, []);

  const resetScan = useCallback(() => {
    abortRef.current?.abort();
    setScanning(false);
    setResults([]);
    setSummary(null);
    setTotalSkills(0);
    setScannedCount(0);
    setErrorMsg("");
    setLogs([]);
    setBatchId(null);
  }, []);

  useEffect(() => () => { abortRef.current?.abort(); }, []);

  return (
    <BatchScanContext.Provider
      value={{
        scanning,
        batchId,
        results,
        summary,
        totalSkills,
        scannedCount,
        errorMsg,
        logs,
        startScan,
        stopScan,
        resetScan,
      }}
    >
      {children}
    </BatchScanContext.Provider>
  );
}

export function useBatchScan() {
  const ctx = useContext(BatchScanContext);
  if (!ctx) {
    throw new Error("useBatchScan must be used within BatchScanProvider");
  }
  return ctx;
}
