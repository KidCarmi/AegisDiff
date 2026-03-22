import { VERDICT_COLORS, VERDICT_EMOJI, type VerdictType } from "../lib/types";

interface VerdictBadgeProps {
  verdict: VerdictType;
  className?: string;
}

export function VerdictBadge({ verdict, className = "" }: VerdictBadgeProps) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${VERDICT_COLORS[verdict]} ${className}`}
    >
      <span>{VERDICT_EMOJI[verdict]}</span>
      <span>{verdict.replace("_", " ")}</span>
    </span>
  );
}
