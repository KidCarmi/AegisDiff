"use client";

import { useState } from "react";
import { VerdictBadge } from "./VerdictBadge";
import { Toast } from "./Toast";
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

/** QW1 — Color-code confidence so developers can immediately assess trust level. */
function confidenceClass(conf: number): string {
  if (conf >= 0.9) return "bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300";
  if (conf >= 0.7) return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300";
  if (conf >= 0.5) return "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300";
  return "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300";
}

type FeedbackState = "idle" | "loading" | "done" | "error";

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
  const [showToast, setShowToast] = useState(false);
  const [toastType, setToastType] = useState<"success" | "error">("success");
  const [toastMsg, setToastMsg] = useState("");

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
        setFeedbackState("error");
        setToastType("error");
        setToastMsg("Couldn't save feedback — try again.");
        setShowToast(true);
        return;
      }
      setSubmittedVerdict(correct_verdict);
      setFeedbackState("done");
      setToastType("success");
      setToastMsg(
        correct_verdict === "FALSE_POSITIVE"
          ? "Marked as false positive. This CWE will be suppressed in future scans."
          : "Thanks! Confirmed as true positive."
      );
      setShowToast(true);
    } catch {
      setFeedbackState("error");
      setToastType("error");
      setToastMsg("Network error — feedback not saved.");
      setShowToast(true);
    }
  };

  const showFPButton =
    canFeedback &&
    feedbackState !== "done" &&
    (scan.verdict === "TRUE_POSITIVE" || scan.verdict === "NEEDS_REVIEW");

  const showTPButton =
    canFeedback &&
    feedbackState !== "done" &&
    (scan.verdict === "FALSE_POSITIVE" || scan.verdict === "NEEDS_REVIEW");

  // QW2 — extract CWE number for mitre.org link
  const cweNum = scan.cweId?.match(/\d+/)?.[0];

  return (
    <>
      {showToast && (
        <Toast
          message={toastMsg}
          type={toastType}
          onDismiss={() => setShowToast(false)}
        />
      )}
      <div
        className={`rounded-lg border border-gray-200 dark:border-gray-700 border-l-4 ${borderColor} bg-white dark:bg-gray-900 px-4 py-3 shadow-sm hover:shadow-md transition-shadow`}
      >
        {/* QW6 — flex-col on mobile, flex-row on sm+ */}
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
          <div className="flex-1 min-w-0">
            {/* Repo + PR + SHA + time */}
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
              <p className="text-sm text-gray-900 dark:text-gray-50 font-medium truncate" title={scan.title}>
                {scan.title}
              </p>
            )}

            {/* Meta chips */}
            <div className="flex items-center gap-2 mt-1.5 flex-wrap">
              {scan.severity && scan.severity !== "N/A" && (
                <span className={`text-xs font-semibold ${severityClass}`}>{scan.severity}</span>
              )}
              {/* QW2 — CWE is now a clickable link to mitre.org */}
              {scan.cweId && scan.cweId !== "N/A" && (
                cweNum ? (
                  <a
                    href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={(e) => e.stopPropagation()}
                    className="rounded bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 text-[11px] font-mono text-blue-600 dark:text-blue-400 hover:underline"
                  >
                    {scan.cweId}
                  </a>
                ) : (
                  <span className="rounded bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 text-[11px] font-mono text-gray-600 dark:text-gray-300">
                    {scan.cweId}
                  </span>
                )
              )}
              {/* QW1 — color-coded confidence */}
              {scan.confidence != null && (
                <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${confidenceClass(scan.confidence)}`}>
                  {Math.round(scan.confidence * 100)}% confident
                </span>
              )}
              {scan.provider && (
                <span className="text-xs text-gray-400 dark:text-gray-500 capitalize">{scan.provider}</span>
              )}
            </div>
          </div>

          {/* Right column: verdict + QW5 labeled feedback buttons */}
          <div className="flex items-center sm:flex-col sm:items-end gap-2 shrink-0">
            <VerdictBadge verdict={scan.verdict} />

            {feedbackState === "done" && submittedVerdict && (
              <span className="text-[11px] text-gray-500 dark:text-gray-400">
                {submittedVerdict === "FALSE_POSITIVE" ? "Marked FP ✓" : "Marked TP ✓"}
              </span>
            )}

            {(showFPButton || showTPButton) && (
              <div className="flex items-center gap-1.5">
                {feedbackState === "loading" && (
                  <span className="text-[11px] text-gray-400">…</span>
                )}
                {/* QW5 — labeled buttons, not emoji-only */}
                {showFPButton && (
                  <button
                    title="Not a real vulnerability — we'll suppress this CWE in future scans"
                    disabled={feedbackState === "loading"}
                    onClick={(e) => submitFeedback(e, "FALSE_POSITIVE")}
                    className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] font-medium text-green-700 dark:text-green-400 bg-green-50 dark:bg-green-900/20 hover:bg-green-100 dark:hover:bg-green-900/40 border border-green-200 dark:border-green-800 disabled:opacity-40 transition-colors"
                  >
                    ✓ Mark FP
                  </button>
                )}
                {showTPButton && (
                  <button
                    title="This is a real vulnerability that was missed"
                    disabled={feedbackState === "loading"}
                    onClick={(e) => submitFeedback(e, "TRUE_POSITIVE")}
                    className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] font-medium text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40 border border-red-200 dark:border-red-800 disabled:opacity-40 transition-colors"
                  >
                    ⚠ Mark TP
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
