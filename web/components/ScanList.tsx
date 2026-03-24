"use client";

import { useState } from "react";
import { ScanCard } from "./ScanCard";
import type { Scan, VerdictType } from "../lib/types";

const FILTERS: { label: string; value: VerdictType | "ALL" }[] = [
  { label: "All", value: "ALL" },
  { label: "🚨 Issues", value: "TRUE_POSITIVE" },
  { label: "⚠️ Review", value: "NEEDS_REVIEW" },
  { label: "✅ Clean", value: "FALSE_POSITIVE" },
];

interface Props {
  scans: Scan[];
}

export function ScanList({ scans }: Props) {
  const [filter, setFilter] = useState<VerdictType | "ALL">("ALL");

  const visible =
    filter === "ALL" ? scans : scans.filter((s) => s.verdict === filter);

  const counts = {
    TRUE_POSITIVE: scans.filter((s) => s.verdict === "TRUE_POSITIVE").length,
    NEEDS_REVIEW: scans.filter((s) => s.verdict === "NEEDS_REVIEW").length,
    FALSE_POSITIVE: scans.filter((s) => s.verdict === "FALSE_POSITIVE").length,
  };

  return (
    <div>
      {/* Filter pills */}
      <div className="flex items-center gap-2 flex-wrap mb-4">
        {FILTERS.map((f) => {
          const count =
            f.value === "ALL"
              ? scans.length
              : counts[f.value as keyof typeof counts];
          const active = filter === f.value;
          return (
            <button
              key={f.value}
              onClick={() => setFilter(f.value)}
              className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                active
                  ? "bg-gray-900 text-white"
                  : "bg-white border border-gray-200 text-gray-600 hover:bg-gray-50"
              }`}
            >
              {f.label}
              <span
                className={`rounded-full px-1.5 py-0.5 text-[10px] font-bold ${
                  active ? "bg-white/20 text-white" : "bg-gray-100 text-gray-500"
                }`}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Scan cards */}
      {visible.length === 0 ? (
        <div className="rounded-lg border border-dashed border-gray-200 p-10 text-center">
          <p className="text-sm text-gray-400">
            No{filter !== "ALL" ? ` ${filter.replace("_", " ").toLowerCase()}` : ""} scans yet.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {visible.map((scan) => (
            <a key={scan.id} href={`/scans/${scan.id}`}>
              <ScanCard scan={scan} />
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
