/**
 * Shared TypeScript types for the AegisDiff dashboard.
 * These mirror the database schema and the Python verdict dataclass.
 */

export type VerdictType = "TRUE_POSITIVE" | "FALSE_POSITIVE" | "NEEDS_REVIEW" | "ERROR";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "N/A";

export interface Scan {
  id: string;
  repoOwner: string;
  repoName: string;
  prNumber: number | null;
  commitSha: string;
  prUrl: string | null;
  verdict: VerdictType;
  severity: Severity | null;
  cweId: string | null;
  confidence: number | null;
  title: string | null;
  provider: string | null;
  scanMs: number | null;
  createdAt: string;
}

export interface Repo {
  id: number;
  owner: string;
  name: string;
  createdAt: string;
}

export interface IngestPayload {
  verdict: VerdictType;
  severity: string;
  cwe_id: string;
  confidence: number;
  title: string;
  provider: string;
  pr_number: number | null;
  commit_sha: string;
  pr_url: string | null;
  scan_ms: number;
  // Phase 4 — aegisdiff-ignore suppression
  suppressed?: boolean;
  ignore_reason?: string | null;
}

export const VERDICT_COLORS: Record<VerdictType, string> = {
  TRUE_POSITIVE: "bg-red-100 text-red-800 border-red-200",
  FALSE_POSITIVE: "bg-green-100 text-green-800 border-green-200",
  NEEDS_REVIEW: "bg-yellow-100 text-yellow-800 border-yellow-200",
  ERROR: "bg-gray-100 text-gray-800 border-gray-200",
};

export const VERDICT_EMOJI: Record<VerdictType, string> = {
  TRUE_POSITIVE: "🚨",
  FALSE_POSITIVE: "✅",
  NEEDS_REVIEW: "⚠️",
  ERROR: "❌",
};

export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "text-red-700 font-bold",
  HIGH: "text-orange-600 font-semibold",
  MEDIUM: "text-yellow-600",
  LOW: "text-blue-600",
  INFO: "text-gray-500",
  "N/A": "text-gray-400",
};
