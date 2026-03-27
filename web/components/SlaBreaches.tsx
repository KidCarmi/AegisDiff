"use client";

/**
 * SlaBreaches — always-visible SLA tracker.
 * Shows a green "all clear" when no breaches, red alert when there are.
 * Lazy-loads after main dashboard render.
 */
import { useEffect, useState } from "react";

interface SLABreach {
  id: string;
  repoOwner: string;
  repoName: string;
  prNumber: number | null;
  prUrl: string | null;
  severity: string;
  cweId: string | null;
  title: string | null;
  createdAt: string;
  daysOpen: number;
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 border-red-300 dark:border-red-800",
  HIGH:     "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300 border-orange-300 dark:border-orange-800",
};

export function SlaBreaches({ slaDays = 7 }: { slaDays?: number }) {
  const [breaches, setBreaches] = useState<SLABreach[] | null>(null);

  useEffect(() => {
    fetch(`/api/scans/sla-breaches?sla_days=${slaDays}`)
      .then((r) => r.json())
      .then((data) => setBreaches(data.breaches ?? []))
      .catch(() => setBreaches([]));
  }, [slaDays]);

  // Still loading — show skeleton
  if (breaches === null) {
    return (
      <div className="mb-6 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-4 animate-pulse">
        <div className="h-4 w-48 bg-gray-200 dark:bg-gray-700 rounded" />
      </div>
    );
  }

  // All clear
  if (breaches.length === 0) {
    return (
      <div className="mb-6 rounded-xl border border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-950/30 px-4 py-3 flex items-center gap-2">
        <span className="text-green-600 dark:text-green-400 text-base">✓</span>
        <div>
          <span className="text-sm font-semibold text-green-800 dark:text-green-200">
            SLA — All clear
          </span>
          <span className="ml-2 text-xs text-green-600 dark:text-green-400">
            No CRITICAL/HIGH findings unresolved &gt;{slaDays} days
          </span>
        </div>
      </div>
    );
  }

  // Group breaches by repo
  const byRepo = breaches.reduce<Record<string, SLABreach[]>>((acc, b) => {
    const key = `${b.repoOwner}/${b.repoName}`;
    if (!acc[key]) acc[key] = [];
    acc[key].push(b);
    return acc;
  }, {});

  return (
    <div className="mb-6 rounded-xl border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-950/40 p-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-base">🚨</span>
        <h2 className="text-sm font-semibold text-red-900 dark:text-red-100">
          SLA Breach — {breaches.length} CRITICAL/HIGH finding{breaches.length !== 1 ? "s" : ""} unresolved &gt;{slaDays} days
        </h2>
      </div>

      <div className="space-y-3">
        {Object.entries(byRepo).map(([repoSlug, repoBreaches]) => (
          <div key={repoSlug}>
            <div className="text-xs font-semibold text-red-700 dark:text-red-300 mb-1.5">
              {repoSlug} · {repoBreaches.length} breach{repoBreaches.length !== 1 ? "es" : ""}
            </div>
            <div className="space-y-1.5">
              {repoBreaches.map((b) => (
                <div
                  key={b.id}
                  className="flex flex-wrap items-center gap-2 rounded-lg border bg-white dark:bg-gray-900 border-gray-200 dark:border-gray-700 px-3 py-2 text-xs"
                >
                  <span
                    className={`rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase ${
                      SEVERITY_COLOR[b.severity] ?? "bg-gray-100 text-gray-700"
                    }`}
                  >
                    {b.severity}
                  </span>

                  <span className="flex-1 font-medium text-gray-800 dark:text-gray-200 truncate">
                    {b.title ?? b.cweId ?? "Untitled finding"}
                  </span>

                  {b.cweId && b.cweId !== "N/A" && (
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${b.cweId.replace(/\D/g, "")}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-brand-blue hover:underline shrink-0"
                    >
                      {b.cweId}
                    </a>
                  )}

                  <span className="text-gray-400 dark:text-gray-500 shrink-0">
                    {b.daysOpen}d open
                  </span>

                  {b.prUrl && (
                    <a
                      href={b.prUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-brand-blue hover:underline shrink-0"
                    >
                      PR #{b.prNumber}
                    </a>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      <p className="mt-3 text-[11px] text-red-600 dark:text-red-400">
        Mark findings as false positive to dismiss, or open the PR to fix the vulnerability.
      </p>
    </div>
  );
}
