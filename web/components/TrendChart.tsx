/**
 * Weekly verdict trend chart — pure SVG, no dependencies.
 * Shows the last 8 weeks of TRUE_POSITIVE / NEEDS_REVIEW / FALSE_POSITIVE counts.
 */
import { sql } from "../lib/db";

interface WeekBucket {
  week: string;
  true_positives: number;
  needs_review: number;
  false_positives: number;
}

interface Props {
  githubId: number;
  username: string;
}

export async function TrendChart({ githubId, username }: Props) {
  const rows = await sql`
    SELECT
      TO_CHAR(DATE_TRUNC('week', s.created_at), 'Mon DD') AS week,
      COUNT(*) FILTER (WHERE s.verdict = 'TRUE_POSITIVE')  AS true_positives,
      COUNT(*) FILTER (WHERE s.verdict = 'NEEDS_REVIEW')   AS needs_review,
      COUNT(*) FILTER (WHERE s.verdict = 'FALSE_POSITIVE') AS false_positives
    FROM scans s
    JOIN repos r ON s.repo_id = r.id
    WHERE (
      r.id IN (
        SELECT r2.id FROM repos r2 JOIN users u ON r2.user_id = u.id
        WHERE u.github_id = ${githubId}
      )
      OR (r.installation_id IS NOT NULL AND r.owner = ${username})
    )
    AND s.created_at > NOW() - INTERVAL '8 weeks'
    GROUP BY DATE_TRUNC('week', s.created_at)
    ORDER BY DATE_TRUNC('week', s.created_at) ASC
  `;

  const buckets = rows as unknown as WeekBucket[];
  if (buckets.length === 0) return null;

  const W = 600;
  const H = 120;
  const padL = 8;
  const padR = 8;
  const padT = 8;
  const padB = 24;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;

  const maxVal = Math.max(
    1,
    ...buckets.map((b) =>
      Number(b.true_positives) + Number(b.needs_review) + Number(b.false_positives),
    ),
  );

  const barW = Math.floor(chartW / buckets.length) - 4;

  const bars = buckets.map((b, i) => {
    const tp = Number(b.true_positives);
    const nr = Number(b.needs_review);
    const fp = Number(b.false_positives);
    const total = tp + nr + fp;
    const x = padL + i * (chartW / buckets.length) + 2;

    const tpH = (tp / maxVal) * chartH;
    const nrH = (nr / maxVal) * chartH;
    const fpH = (fp / maxVal) * chartH;
    const totalH = (total / maxVal) * chartH;

    const y0 = padT + chartH; // baseline
    return { x, tpH, nrH, fpH, totalH, y0, label: b.week, total };
  });

  return (
    <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-4 shadow-sm">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-200">Weekly Trend</h3>
        <div className="flex items-center gap-4 text-xs text-gray-500 dark:text-gray-400">
          <span className="flex items-center gap-1">
            <span className="inline-block w-2.5 h-2.5 rounded-sm bg-red-400" />
            True Positive
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block w-2.5 h-2.5 rounded-sm bg-yellow-400" />
            Needs Review
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block w-2.5 h-2.5 rounded-sm bg-green-400" />
            False Positive
          </span>
        </div>
      </div>
      {/* QW6 — responsive: viewBox scales to fill container, fixed height removed */}
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto">
        {bars.map((b, i) => {
          let y = b.y0;
          const segments = [
            { h: b.tpH, fill: "#f87171" },
            { h: b.nrH, fill: "#fbbf24" },
            { h: b.fpH, fill: "#4ade80" },
          ];
          const rects = segments
            .filter((s) => s.h > 0)
            .map((s) => {
              y -= s.h;
              return (
                <rect
                  key={s.fill}
                  x={b.x}
                  y={y}
                  width={barW}
                  height={s.h}
                  fill={s.fill}
                  rx="2"
                />
              );
            });
          return (
            <g key={i}>
              {rects}
              <text
                x={b.x + barW / 2}
                y={H - 6}
                textAnchor="middle"
                fontSize="9"
                fill="currentColor"
              className="text-gray-400 dark:text-gray-500"
              >
                {b.label}
              </text>
            </g>
          );
        })}
        {/* Baseline */}
        <line
          x1={padL}
          y1={padT + chartH}
          x2={W - padR}
          y2={padT + chartH}
          stroke="currentColor"
          className="text-gray-200 dark:text-gray-700"
          strokeWidth="1"
        />
      </svg>
    </div>
  );
}
