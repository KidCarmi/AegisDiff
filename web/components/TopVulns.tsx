"use client";

import { useEffect, useState } from "react";
import { SEVERITY_COLORS } from "../lib/types";

interface VulnRow {
  cwe_id: string;
  severity: string | null;
  title: string | null;
  total: string;
  true_positives: string;
  needs_review: string;
  false_positives: string;
  last_seen: string;
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const days = Math.floor(diff / 86400000);
  if (days === 0) return "today";
  if (days === 1) return "yesterday";
  return `${days}d ago`;
}

export function TopVulns() {
  const [vulns, setVulns] = useState<VulnRow[] | null>(null);

  useEffect(() => {
    fetch("/api/scans/top-vulns")
      .then((r) => r.json())
      .then((d) => setVulns(d.vulns ?? []))
      .catch(() => setVulns([]));
  }, []);

  if (vulns === null) {
    return (
      <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
        <div className="h-4 w-48 bg-gray-100 dark:bg-gray-800 rounded animate-pulse mb-4" />
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-12 bg-gray-50 dark:bg-gray-800 rounded mb-2 animate-pulse" />
        ))}
      </div>
    );
  }

  if (vulns.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-gray-200 dark:border-gray-700 p-8 text-center">
        <p className="text-sm text-gray-400 dark:text-gray-500">No confirmed findings in the last 30 days.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 shadow-sm overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-100 dark:border-gray-800">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-200">Top Vulnerabilities</h3>
        <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">Last 30 days · grouped by CWE</p>
      </div>
      <div className="divide-y divide-gray-100 dark:divide-gray-800">
        {vulns.map((v, i) => {
          const cweNum = v.cwe_id?.match(/\d+/)?.[0];
          const severityClass = SEVERITY_COLORS[v.severity ?? "N/A"] ?? "text-gray-400";
          const tp = Number(v.true_positives);
          const nr = Number(v.needs_review);
          const total = Number(v.total);

          return (
            <div key={i} className="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">
              {/* Rank */}
              <span className="w-5 text-xs font-bold text-gray-300 dark:text-gray-600 shrink-0">{i + 1}</span>

              {/* CWE + title */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  {cweNum ? (
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs font-mono font-semibold text-blue-600 dark:text-blue-400 hover:underline"
                    >
                      {v.cwe_id}
                    </a>
                  ) : (
                    <span className="text-xs font-mono font-semibold text-gray-500">{v.cwe_id}</span>
                  )}
                  {v.severity && v.severity !== "N/A" && (
                    <span className={`text-xs font-semibold ${severityClass}`}>{v.severity}</span>
                  )}
                </div>
                {v.title && (
                  <p className="text-sm text-gray-800 dark:text-gray-100 truncate mt-0.5" title={v.title}>
                    {v.title}
                  </p>
                )}
              </div>

              {/* Counts */}
              <div className="shrink-0 flex items-center gap-3 text-right">
                <div className="hidden sm:flex flex-col items-end">
                  <div className="flex items-center gap-1.5">
                    {tp > 0 && (
                      <span className="inline-flex items-center gap-0.5 rounded-full bg-red-100 dark:bg-red-900/30 px-1.5 py-0.5 text-[11px] font-semibold text-red-700 dark:text-red-400">
                        🚨 {tp}
                      </span>
                    )}
                    {nr > 0 && (
                      <span className="inline-flex items-center gap-0.5 rounded-full bg-yellow-100 dark:bg-yellow-900/30 px-1.5 py-0.5 text-[11px] font-semibold text-yellow-700 dark:text-yellow-400">
                        ⚠️ {nr}
                      </span>
                    )}
                  </div>
                  <span className="text-[10px] text-gray-400 dark:text-gray-500 mt-0.5">
                    {total} scan{total !== 1 ? "s" : ""} · {timeAgo(v.last_seen)}
                  </span>
                </div>
                {/* Mobile: just the total */}
                <span className="sm:hidden text-xs font-semibold text-gray-500 dark:text-gray-400">
                  {total}×
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
