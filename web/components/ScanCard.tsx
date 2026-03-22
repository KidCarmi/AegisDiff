import { VerdictBadge } from "./VerdictBadge";
import { SEVERITY_COLORS, type Scan } from "../lib/types";

interface ScanCardProps {
  scan: Scan;
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function ScanCard({ scan }: ScanCardProps) {
  const repoSlug = `${scan.repoOwner}/${scan.repoName}`;
  const severityClass = SEVERITY_COLORS[scan.severity ?? "N/A"] ?? "text-gray-400";
  const sha = scan.commitSha.slice(0, 7);

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          {/* Repo + PR */}
          <div className="flex items-center gap-2 text-sm text-gray-500 mb-1">
            <span className="font-mono font-medium text-gray-700 truncate">{repoSlug}</span>
            {scan.prNumber && (
              <>
                <span>·</span>
                {scan.prUrl ? (
                  <a
                    href={scan.prUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-600 hover:underline"
                  >
                    PR #{scan.prNumber}
                  </a>
                ) : (
                  <span>PR #{scan.prNumber}</span>
                )}
              </>
            )}
            <span>·</span>
            <span className="font-mono text-xs">{sha}</span>
          </div>

          {/* Title */}
          {scan.title && (
            <p className="text-sm text-gray-900 font-medium truncate">{scan.title}</p>
          )}

          {/* Metadata row */}
          <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
            {scan.severity && scan.severity !== "N/A" && (
              <span className={severityClass}>{scan.severity}</span>
            )}
            {scan.cweId && scan.cweId !== "N/A" && (
              <span className="font-mono">{scan.cweId}</span>
            )}
            {scan.confidence != null && (
              <span>{Math.round(scan.confidence * 100)}% confidence</span>
            )}
            {scan.provider && (
              <span className="capitalize">{scan.provider}</span>
            )}
            <span>{timeAgo(scan.createdAt)}</span>
          </div>
        </div>

        {/* Verdict badge */}
        <div className="flex-shrink-0">
          <VerdictBadge verdict={scan.verdict} />
        </div>
      </div>
    </div>
  );
}
