"use client";

import { useState } from "react";

export function SyncButton() {
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [message, setMessage] = useState("");

  async function sync() {
    setState("loading");
    try {
      const res = await fetch("/api/repos/sync", { method: "POST" });
      const text = await res.text();
      let data: any = {};
      try { data = JSON.parse(text); } catch { /* non-JSON body */ }
      if (!res.ok) throw new Error(data.error ?? `Server error ${res.status}`);
      setMessage(data.message ?? "Done");
      setState("done");
      setTimeout(() => window.location.reload(), 1200);
    } catch (e: any) {
      setMessage(e.message ?? "Unknown error");
      setState("error");
    }
  }

  return (
    <div className="flex items-center gap-2">
      <button
        onClick={sync}
        disabled={state === "loading"}
        className="rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-50 transition-colors flex items-center gap-1.5"
      >
        {state === "loading" ? (
          <>
            <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
            </svg>
            Syncing…
          </>
        ) : state === "done" ? (
          "✓ Synced"
        ) : (
          "↻ Sync from GitHub"
        )}
      </button>
      {message && (
        <span className={`text-xs ${state === "error" ? "text-red-500" : "text-gray-500 dark:text-gray-400"}`}>
          {message}
        </span>
      )}
    </div>
  );
}
