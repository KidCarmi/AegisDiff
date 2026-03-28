/**
 * GET /api/badge/[owner]/[name]
 * Returns a shields.io-style SVG badge showing the last scan verdict.
 * Public endpoint — no auth required (only shows last verdict, no PII).
 */
import { NextRequest, NextResponse } from "next/server";
import { sql } from "../../../../../lib/db";

const COLORS: Record<string, string> = {
  TRUE_POSITIVE: "#e11d48",
  FALSE_POSITIVE: "#16a34a",
  NEEDS_REVIEW: "#d97706",
  ERROR: "#6b7280",
};

const LABELS: Record<string, string> = {
  TRUE_POSITIVE: "issues found",
  FALSE_POSITIVE: "clean",
  NEEDS_REVIEW: "needs review",
  ERROR: "error",
};

function badge(verdict: string): string {
  const color = COLORS[verdict] ?? "#6b7280";
  const label = LABELS[verdict] ?? verdict.toLowerCase();
  const leftW = 72;
  const rightW = Math.max(label.length * 7 + 14, 50);
  const totalW = leftW + rightW;
  const leftX = leftW / 2;
  const rightX = leftW + rightW / 2;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalW}" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${totalW}" height="20" rx="3"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${leftW}" height="20" fill="#555"/>
    <rect x="${leftW}" width="${rightW}" height="20" fill="${color}"/>
    <rect width="${totalW}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="${leftX}" y="15" fill="#010101" fill-opacity=".3">AegisDiff</text>
    <text x="${leftX}" y="14">AegisDiff</text>
    <text x="${rightX}" y="15" fill="#010101" fill-opacity=".3">${label}</text>
    <text x="${rightX}" y="14">${label}</text>
  </g>
</svg>`;
}

export async function GET(
  _req: NextRequest,
  { params }: { params: { owner: string; name: string } },
) {
  const { owner, name } = params;

  const rows = await sql`
    SELECT s.verdict FROM scans s
    JOIN repos r ON s.repo_id = r.id
    WHERE r.owner = ${owner} AND r.name = ${name}
      AND s.verdict != 'ERROR'
    ORDER BY s.created_at DESC
    LIMIT 1
  `;

  const verdict = rows.length > 0 ? (rows[0] as any).verdict : "unknown";
  const svg = badge(verdict === "unknown" ? "ERROR" : verdict);

  return new NextResponse(svg, {
    headers: {
      "Content-Type": "image/svg+xml",
      "Cache-Control": "public, max-age=300, stale-while-revalidate=600",
    },
  });
}
