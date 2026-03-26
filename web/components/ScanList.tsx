"use client";

import { useState, useMemo } from "react";
import { ScanCard } from "./ScanCard";
import type { Scan, VerdictType } from "../lib/types";

const VERDICT_FILTERS: { label: string; value: VerdictType | "ALL" }[] = [
  { label: "All", value: "ALL" },
  { label: "🚨 Issues", value: "TRUE_POSITIVE" },
  { label: "⚠️ Review", value: "NEEDS_REVIEW" },
  { label: "✅ Clean", value: "FALSE_POSITIVE" },
];

export function ScanList({ scans, canFeedback = false }: { scans: Scan[]; canFeedback?: boolean }) {
  const [filter, setFilter] = useState<VerdictType | "ALL">("ALL");
  const [search, setSearch] = useState("");

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return scans.filter((s) => {
      if (filter !== "ALL" && s.verdict !== filter) return false;
      if (!q) return true;
      return (
        s.repoOwner.toLowerCase().includes(q) ||
        s.repoName.toLowerCase().includes(q) ||
        s.title?.toLowerCase().includes(q) ||
        s.cweId?.toLowerCase().includes(q) ||
        s.severity?.toLowerCase().includes(q) ||
        s.commitSha.slice(0, 7).includes(q) ||
        String(s.prNumber ?? "").includes(q)
      );
    });
  }, [scans, filter, search]);

  const counts = {
    TRUE_POSITIVE: scans.filter((s) => s.verdict === "TRUE_POSITIVE").length,
    NEEDS_REVIEW: scans.filter((s) => s.verdict === "NEEDS_REVIEW").length,
    FALSE_POSITIVE: scans.filter((s) => s.verdict === "FALSE_POSITIVE").length,
  };

  return (
    <div>
      {/* Search + filter row */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <input
          type="search"
          placeholder="Search repo, title, CWE, SHA…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-1.5 text-sm text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-gray-900 dark:focus:ring-gray-400 w-56"
        />
        <div className="flex items-center gap-1.5">
          {VERDICT_FILTERS.map((f) => {
            const count = f.value === "ALL" ? scans.length : counts[f.value as keyof typeof counts];
            const active = filter === f.value;
            return (
              <button key={f.value} onClick={() => setFilter(f.value)}
                className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                  active ? "bg-gray-900 dark:bg-gray-100 text-white dark:text-gray-900" : "bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
                }`}>
                {f.label}
                <span className={`rounded-full px-1.5 py-0.5 text-[10px] font-bold ${
                  active ? "bg-white/20 text-white dark:bg-black/20 dark:text-gray-900" : "bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400"
                }`}>{count}</span>
              </button>
            );
          })}
        </div>
      </div>

      {visible.length === 0 ? (
        <div className="rounded-lg border border-dashed border-gray-200 dark:border-gray-700 p-10 text-center">
          <p className="text-sm text-gray-400 dark:text-gray-500">
            {search ? `No results for "${search}"` : "No scans yet."}
          </p>
          {search && (
            <button onClick={() => setSearch("")} className="mt-2 text-xs text-blue-600 hover:underline">
              Clear search
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {visible.map((scan) => (
            <a key={scan.id} href={`/scans/${scan.id}`}>
              <ScanCard scan={scan} canFeedback={canFeedback} />
            </a>
          ))}
          {visible.length < scans.length && (
            <p className="text-center text-xs text-gray-400 pt-2">
              Showing {visible.length} of {scans.length} scans
            </p>
          )}
        </div>
      )}
    </div>
  );
}
