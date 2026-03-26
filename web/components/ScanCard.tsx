"use client";

import { useState } from "react";
import { VerdictBadge } from "./VerdictBadge";
import { SEVERITY_COLORS, type Scan, type VerdictType } from "../lib/types";

const VERDICT_BORDER: Record<VerdictType, string> = {
  TRUE_POSITIVE: "border-l-red-400",
  FALSE_POSITIVE: "border-l-green-400",
  NEEDS_REVIEW: "border-l-yellow-400",
  ERROR: "border-l-gray-300",
};

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

type FeedbackState = "idle" | "loading" | "done" | "error";

/**
 * ScanCard — displays scan metadata and optionally a feedback row.
 *
 * `canFeedback`: pass true when the current user is repo:developer or higher.
 * The feedback buttons are hidden when false so viewers never see them.
 */
export function ScanCard({
  scan,
  canFeedback = false,
}: {
  scan: Scan;
  canFeedback?: boolean;
}) {
  const repoSlug = `${scan.repoOwner}/${scan.repoName}`;
  const severityClass = SEVERITY_COLORS[scan.severity ?? "N/A"] ?? "text-gray-400";
  const sha = scan.commitSha.slice(0, 7);
  const borderColor = VERDICT_BORDER[scan.verdict] ?? "border-l-gray-300";

  const [feedbackState, setFeedbackState] = useState<FeedbackState>("idle");
  const [submittedVerdict, setSubmittedVerdict] = useState<VerdictType | null>(null);

  const submitFeedback = async (e: React.MouseEvent, correct_verdict: VerdictType) => {
    e.preventDefault();
    e.stopPropagation();
    if (feedbackState === "loading" || feedbackState === "done") return;
    setFeedbackState("loading");
    try {
      const resp = await fetch(`/api/scans/${scan.id}/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ correct_verdict }),
      });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        console.error("[feedback] API error:", data);
        setFeedbackState("error");
        return;
      }
      setSubmittedVerdict(correct_verdict);
      setFeedbackState("done");
    } catch {
      setFeedbackState("error");
    }
  };

  // Which thumbs button makes sense depends on the current verdict
  const showThumbsDown =
    canFeedback &&
    (scan.verdict === "FALSE_POSITIVE" || scan.verdict === "NEEDS_REVIEW");
  const showThumbsUp =
    canFeedback &&
    (scan.verdict === "TRUE_POSITIVE" || scan.verdict === "NEEDS_REVIEW");

  return (
    <div
      className={`rounded-lg border border-gray-200 dark:border-gray-700 border-l-4 ${borderColor} bg-white dark:bg-gray-900 px-4 py-3 shadow-sm hover:shadow-md transition-shadow`}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          {/* Repo + PR + SHA */}
          <div className="flex items-center gap-2 text-xs text-gray-400 dark:text-gray-500 mb-1 flex-wrap">
            <span className="font-mono font-semibold text-gray-700 dark:text-gray-200 truncate">{repoSlug}</span>
            {scan.prNumber && (
              <>
                <span>·</span>
                {scan.prUrl ? (
                  <a
                    href={scan.prUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={(e) => e.stopPropagation()}
                    className="text-blue-500 hover:underline"
                  >
                    PR #{scan.prNumber}
                  </a>
                ) : (
                  <span>PR #{scan.prNumber}</span>
                )}
              </>
            )}
            <span>·</span>
            <span className="font-mono">{sha}</span>
            <span>·</span>
            <span>{timeAgo(scan.createdAt)}</span>
          </div>

          {/* Title */}
          {scan.title && (
            <p className="text-sm text-gray-900 dark:text-gray-50 font-medium truncate">{scan.title}</p>
          )}

          {/* Meta chips */}
          <div className="flex items-center gap-2 mt-1.5 flex-wrap">
            {scan.severity && scan.severity !== "N/A" && (
              <span className={`text-xs font-semibold ${severityClass}`}>{scan.severity}</span>
            )}
            {scan.cweId && scan.cweId !== "N/A" && (
              <span className="rounded bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 text-[11px] font-mono text-gray-600 dark:text-gray-300">
                {scan.cweId}
              </span>
            )}
            {scan.confidence != null && (
              <span className="text-xs text-gray-400 dark:text-gray-500">
                {Math.round(scan.confidence * 100)}% confidence
              </span>
            )}
            {scan.provider && (
              <span className="text-xs text-gray-400 dark:text-gray-500 capitalize">{scan.provider}</span>
            )}
          </div>
        </div>

        {/* Right column: verdict badge + feedback buttons */}
        <div className="shrink-0 self-center flex flex-col items-end gap-2">
          <VerdictBadge verdict={scan.verdict} />

          {/* Feedback buttons — developer+ only */}
          {canFeedback && feedbackState !== "done" && (
            <div className="flex items-center gap-1">
              {feedbackState === "error" && (
                <span className="text-[11px] text-red-500 mr-1">Failed</span>
              )}
              {showThumbsDown && (
                <button
                  title="Mark as missed finding (true positive)"
                  disabled={feedbackState === "loading"}
                  onClick={(e) => submitFeedback(e, "TRUE_POSITIVE")}
                  className="rounded p-1 text-gray-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-40 transition-colors"
                >
                  👎
                </button>
              )}
              {showThumbsUp && (
                <button
                  title="Mark as false positive"
                  disabled={feedbackState === "loading"}
                  onClick={(e) => submitFeedback(e, "FALSE_POSITIVE")}
                  className="rounded p-1 text-gray-400 hover:text-green-600 hover:bg-green-50 dark:hover:bg-green-900/20 disabled:opacity-40 transition-colors"
                >
                  👍
                </button>
              )}
              {feedbackState === "loading" && (
                <span className="text-[11px] text-gray-400 ml-1">…</span>
              )}
            </div>
          )}

          {feedbackState === "done" && submittedVerdict && (
            <span className="text-[11px] text-gray-500 dark:text-gray-400">
              {submittedVerdict === "FALSE_POSITIVE" ? "Marked FP ✓" : "Marked TP ✓"}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
