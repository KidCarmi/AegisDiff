"use client";

import { useState } from "react";
import { Toast } from "./Toast";

export function RescanButton({ scanId }: { scanId: string }) {
  const [state, setstate] = useState<"idle" | "loading" | "queued" | "error">("idle");
  const [msg, setMsg] = useState("");

  const trigger = async () => {
    if (state === "loading" || state === "queued") return;
    setstate("loading");
    try {
      const resp = await fetch(`/api/scans/${scanId}/rescan`, { method: "POST" });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        setMsg(data.error ?? "Failed to queue rescan");
        setstate("error");
        return;
      }
      setMsg("Re-scan queued — results in ~90s");
      setstate("queued");
    } catch {
      setMsg("Network error — rescan not queued");
      setstate("error");
    }
  };

  return (
    <>
      {(state === "queued" || state === "error") && (
        <Toast
          message={msg}
          type={state === "queued" ? "success" : "error"}
          onDismiss={() => setstate("idle")}
        />
      )}
      <button
        onClick={trigger}
        disabled={state === "loading" || state === "queued"}
        className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-1.5 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-50 transition-colors"
      >
        {state === "loading" ? "Queuing…" : state === "queued" ? "✓ Queued" : "🔄 Re-scan"}
      </button>
    </>
  );
}
