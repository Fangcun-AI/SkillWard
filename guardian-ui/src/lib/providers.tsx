"use client";

import { I18nProvider } from "./i18n";
import { BatchScanProvider } from "./batch-scan-context";
import type { ReactNode } from "react";

export function Providers({ children }: { children: ReactNode }) {
  return (
    <I18nProvider>
      <BatchScanProvider>{children}</BatchScanProvider>
    </I18nProvider>
  );
}
