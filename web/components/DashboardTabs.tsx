"use client";

import { useState } from "react";
import { ScanList } from "./ScanList";
import { TopVulns } from "./TopVulns";
import type { Scan } from "../lib/types";

interface DashboardTabsProps {
  scans: Scan[];
  canFeedback: boolean;
}

export function DashboardTabs({ scans, canFeedback }: DashboardTabsProps) {
  const [tab, setTab] = useState<"recent" | "top">("recent");

  return (
    <div>
      {/* Tab bar */}
      <div className="mb-4 flex items-center gap-1 border-b border-gray-200 dark:border-gray-700">
        <button
          onClick={() => setTab("recent")}
          className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
            tab === "recent"
              ? "border-blue-600 text-blue-600 dark:text-blue-400 dark:border-blue-400"
              : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
          }`}
        >
          Recent Scans
          {scans.length > 0 && (
            <span className="ml-1.5 rounded-full bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 text-[10px] font-semibold text-gray-500 dark:text-gray-400">
              {scans.length}
            </span>
          )}
        </button>
        <button
          onClick={() => setTab("top")}
          className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
            tab === "top"
              ? "border-blue-600 text-blue-600 dark:text-blue-400 dark:border-blue-400"
              : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
          }`}
        >
          Top Vulnerabilities
        </button>
      </div>

      {tab === "recent" ? (
        <ScanList scans={scans} canFeedback={canFeedback} />
      ) : (
        <TopVulns />
      )}
    </div>
  );
}
