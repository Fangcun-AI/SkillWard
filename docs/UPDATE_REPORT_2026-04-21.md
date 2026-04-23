# Update Report · 2026-04-22

---

## 1. Backend API rewrite + UI updates

- Consolidated redundant pipeline branches and logging cleanup, unified entry signatures, and removed duplicated cache-check branches.

- Introduced a scan-result reuse mechanism: **once a skill has been scanned, subsequent submissions return the existing result directly without re-running the Stage A+B+C pipeline.** In batch re-scans and multi-user shared-skill scenarios, this materially reduces wait time as well as the repeated cost of LLM triage and Docker sandboxing.

- The batch-scan page, pipeline preview, scan-modal, and upload-panel components completed a round of **interface-layer alignment**.

---

## 2. Scan progress & UI refresh

- Logo updated.

- The landing screen visually separates "single-file scan" from "batch scan" and adds a progress card area; live progress is now driven by streaming events instead of polling.
- The scan detail, history, and batch pages adopt a new color palette, rearranged stage-card layouts, and adjusted risk-level label styling.
- Removed the unused demo placeholder data from the pipeline preview — it now renders purely from real SSE events.

---

## 3. Batch scanning: abortable + progress persistence

Before this change, batch-scan progress lived inside a single page; switching pages or refreshing the browser would lose it entirely.

**Approach**: promote the batch-scan progress from per-page state to **global front-end state + browser local storage**, surfacing three user-visible changes:

- **Cross-page visibility**: the current batch progress is visible on the home page, batch page, scan detail page, and anywhere else; navigating between pages no longer interrupts state.
- **Survives refresh**: progress is persisted automatically — **after refreshing the page, closing the tab, or reopening the browser, the progress is still there** and can be resumed.
- **Abortable mid-run**: clicking "Stop" cancels the data stream on the client and notifies the backend to terminate the scan; aborted records are preserved in the database and are not overwritten by subsequent operations.
