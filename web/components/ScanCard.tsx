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

export function ScanCard({ scan }: { scan: Scan }) {
  const repoSlug = `${scan.repoOwner}/${scan.repoName}`;
  const severityClass = SEVERITY_COLORS[scan.severity ?? "N/A"] ?? "text-gray-400";
  const sha = scan.commitSha.slice(0, 7);
  const borderColor = VERDICT_BORDER[scan.verdict] ?? "border-l-gray-300";

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

        {/* Verdict badge */}
        <div className="shrink-0 self-center">
          <VerdictBadge verdict={scan.verdict} />
        </div>
      </div>
    </div>
  );
}
