"use client";

import { useState } from "react";
import Image from "next/image";

// ── Types ──────────────────────────────────────────────────────────────────

interface ScanStats {
  today: number;
  week: number;
  month: number;
  total: number;
  tp_month: number;
  errors_week: number;
}

interface TopRepo {
  owner: string;
  name: string;
  scans: number;
  tps: number;
}

interface RateLimitedRepo {
  owner: string;
  name: string;
  scans_today: number;
  daily_limit: number;
}

interface AuditEvent {
  action: string;
  repo_owner?: string;
  repo_name?: string;
  details?: any;
  created_at: string;
}

interface UserStats {
  total: number;
  new_week: number;
}

interface ProviderFailure {
  provider: string;
  total: number;
  today: number;
  last_24h: number;
}

interface FailureReason {
  title: string;
  count: number;
  last_seen: string;
}

interface FailureTrendDay {
  day: string;
  errors: number;
}

interface AdminTabsProps {
  scans: ScanStats;
  topRepos: TopRepo[];
  rateLimited: RateLimitedRepo[];
  recentAudit: AuditEvent[];
  users: UserStats;
  providerFailures: ProviderFailure[];
  failureReasons: FailureReason[];
  failureTrend: FailureTrendDay[];
}

// ── Overview Tab ───────────────────────────────────────────────────────────

function OverviewTab({
  scans,
  topRepos,
  rateLimited,
  recentAudit,
  users,
}: AdminTabsProps) {
  const tpRate =
    scans.month > 0 ? Math.round((scans.tp_month / scans.month) * 100) : 0;

  const statCards = [
    {
      label: "Scans today",
      value: scans.today,
      sub: `${scans.week} this week`,
      color: "text-blue-600 dark:text-blue-400",
    },
    {
      label: "Scans (30d)",
      value: scans.month,
      sub: `${scans.total} all-time`,
      color: "text-gray-900 dark:text-gray-50",
    },
    {
      label: "True positives (30d)",
      value: scans.tp_month,
      sub: "confirmed findings",
      color: "text-red-600 dark:text-red-400",
    },
    {
      label: "TP rate (30d)",
      value: `${tpRate}%`,
      sub: "of all scans",
      color: "text-purple-600 dark:text-purple-400",
    },
    {
      label: "Engine errors (7d)",
      value: scans.errors_week,
      sub: "failed scans",
      color: "text-orange-600 dark:text-orange-400",
    },
    {
      label: "Total users",
      value: users.total,
      sub: `+${users.new_week} this week`,
      color: "text-green-600 dark:text-green-400",
    },
  ];

  return (
    <div className="space-y-6">
      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        {statCards.map((c) => (
          <div
            key={c.label}
            className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-4 shadow-sm"
          >
            <p className={`text-2xl font-bold ${c.color}`}>{c.value ?? 0}</p>
            <p className="text-xs font-medium text-gray-700 dark:text-gray-300 mt-0.5">
              {c.label}
            </p>
            <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">
              {c.sub}
            </p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Top repos */}
        <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm">
          <div className="border-b border-gray-200 dark:border-gray-800 px-5 py-3">
            <h2 className="text-sm font-semibold text-gray-800 dark:text-gray-200">
              Top Repos (30 days)
            </h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800 text-left text-xs text-gray-500 dark:text-gray-400">
                <th className="px-5 py-2 font-medium">Repo</th>
                <th className="px-5 py-2 font-medium text-right">Scans</th>
                <th className="px-5 py-2 font-medium text-right">TPs</th>
              </tr>
            </thead>
            <tbody>
              {topRepos.map((r) => (
                <tr
                  key={`${r.owner}/${r.name}`}
                  className="border-b border-gray-100 dark:border-gray-800 last:border-0 hover:bg-gray-50 dark:hover:bg-gray-800"
                >
                  <td className="px-5 py-2 font-mono text-xs text-gray-700 dark:text-gray-300">
                    {r.owner}/{r.name}
                  </td>
                  <td className="px-5 py-2 text-right text-gray-900 dark:text-gray-100">
                    {r.scans}
                  </td>
                  <td className="px-5 py-2 text-right text-red-600 dark:text-red-400 font-medium">
                    {r.tps}
                  </td>
                </tr>
              ))}
              {topRepos.length === 0 && (
                <tr>
                  <td
                    colSpan={3}
                    className="px-5 py-6 text-center text-sm text-gray-400"
                  >
                    No scans yet
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Rate-limited repos */}
        <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm">
          <div className="border-b border-gray-200 dark:border-gray-800 px-5 py-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-800 dark:text-gray-200">
              Rate-Limited Today
            </h2>
            <span className="rounded-full bg-orange-100 dark:bg-orange-900/40 px-2 py-0.5 text-xs text-orange-700 dark:text-orange-400">
              {rateLimited.length} repos
            </span>
          </div>
          {rateLimited.length === 0 ? (
            <p className="px-5 py-6 text-sm text-gray-400 text-center">
              No repos are near their daily limit
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800 text-left text-xs text-gray-500 dark:text-gray-400">
                  <th className="px-5 py-2 font-medium">Repo</th>
                  <th className="px-5 py-2 font-medium text-right">
                    Scans today
                  </th>
                </tr>
              </thead>
              <tbody>
                {rateLimited.map((r) => (
                  <tr
                    key={`${r.owner}/${r.name}`}
                    className="border-b border-gray-100 dark:border-gray-800 last:border-0"
                  >
                    <td className="px-5 py-2 font-mono text-xs text-gray-700 dark:text-gray-300">
                      {r.owner}/{r.name}
                    </td>
                    <td className="px-5 py-2 text-right font-semibold text-orange-600 dark:text-orange-400">
                      {r.scans_today}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Recent audit log */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm">
        <div className="border-b border-gray-200 dark:border-gray-800 px-5 py-3">
          <h2 className="text-sm font-semibold text-gray-800 dark:text-gray-200">
            Recent Audit Events
          </h2>
        </div>
        <div className="divide-y divide-gray-100 dark:divide-gray-800 text-sm">
          {recentAudit.map((e, i) => (
            <div key={i} className="flex items-start gap-3 px-5 py-3">
              <span className="mt-0.5 shrink-0 rounded bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 font-mono text-xs text-gray-600 dark:text-gray-400">
                {e.action}
              </span>
              <span className="text-gray-700 dark:text-gray-300">
                {e.repo_owner && e.repo_name
                  ? `${e.repo_owner}/${e.repo_name}`
                  : "—"}
              </span>
              <span className="ml-auto shrink-0 text-xs text-gray-400 dark:text-gray-500">
                {new Date(e.created_at).toLocaleString()}
              </span>
            </div>
          ))}
          {recentAudit.length === 0 && (
            <p className="px-5 py-6 text-center text-sm text-gray-400">
              No audit events yet
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Users Tab ──────────────────────────────────────────────────────────────

interface PlatformUser {
  github_id: number;
  username: string;
  email?: string;
  created_at: string;
  repo_count: number;
  total_scans: number;
  last_scan_at?: string;
  daily_limit: number;
  has_custom_limit: boolean;
}

function UsersTab() {
  const [users, setUsers] = useState<PlatformUser[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    if (users !== null) return;
    setLoading(true);
    try {
      const res = await fetch("/api/admin/users");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Failed");
      setUsers(data.users);
    } catch (e: any) {
      setError(e.message ?? "Failed to load users");
    } finally {
      setLoading(false);
    }
  }

  // Load on first render
  if (users === null && !loading && !error) {
    load();
  }

  if (loading)
    return (
      <div className="flex items-center justify-center py-16 text-gray-400">
        Loading users…
      </div>
    );
  if (error)
    return (
      <div className="rounded-lg bg-red-50 dark:bg-red-900/20 px-5 py-4 text-sm text-red-600 dark:text-red-400">
        {error}
      </div>
    );
  if (!users) return null;

  return (
    <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm overflow-hidden">
      <div className="border-b border-gray-200 dark:border-gray-800 px-5 py-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-gray-800 dark:text-gray-200">
          All Users
        </h2>
        <span className="text-xs text-gray-400 dark:text-gray-500">
          {users.length} total
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800 text-left text-xs text-gray-500 dark:text-gray-400">
              <th className="px-5 py-2 font-medium">User</th>
              <th className="px-5 py-2 font-medium text-right">Repos</th>
              <th className="px-5 py-2 font-medium text-right">Scans</th>
              <th className="px-5 py-2 font-medium text-right">Daily limit</th>
              <th className="px-5 py-2 font-medium">Last scan</th>
              <th className="px-5 py-2 font-medium">Joined</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr
                key={u.github_id}
                className="border-b border-gray-100 dark:border-gray-800 last:border-0 hover:bg-gray-50 dark:hover:bg-gray-800"
              >
                <td className="px-5 py-2">
                  <div className="flex items-center gap-2">
                    <Image
                      src={`https://avatars.githubusercontent.com/${u.username}?size=48`}
                      alt={u.username}
                      width={24}
                      height={24}
                      className="rounded-full"
                    />
                    <div>
                      <a
                        href={`https://github.com/${u.username}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-medium text-gray-900 dark:text-gray-100 hover:underline"
                      >
                        {u.username}
                      </a>
                      {u.email && (
                        <p className="text-xs text-gray-400 dark:text-gray-500">
                          {u.email}
                        </p>
                      )}
                    </div>
                  </div>
                </td>
                <td className="px-5 py-2 text-right text-gray-700 dark:text-gray-300">
                  {u.repo_count}
                </td>
                <td className="px-5 py-2 text-right text-gray-700 dark:text-gray-300">
                  {u.total_scans}
                </td>
                <td className="px-5 py-2 text-right">
                  <span className={`text-xs font-medium ${u.has_custom_limit ? "text-brand-blue" : "text-gray-400 dark:text-gray-500"}`}>
                    {u.daily_limit ?? 100}
                    {u.has_custom_limit && <span className="ml-1 text-[10px] opacity-70">custom</span>}
                  </span>
                </td>
                <td className="px-5 py-2 text-xs text-gray-500 dark:text-gray-400">
                  {u.last_scan_at
                    ? new Date(u.last_scan_at).toLocaleDateString()
                    : "—"}
                </td>
                <td className="px-5 py-2 text-xs text-gray-500 dark:text-gray-400">
                  {new Date(u.created_at).toLocaleDateString()}
                </td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  className="px-5 py-8 text-center text-sm text-gray-400"
                >
                  No users yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Rate Limits Tab ────────────────────────────────────────────────────────

function RateLimitsTab({ rateLimited }: { rateLimited: RateLimitedRepo[] }) {
  const [owner, setOwner] = useState("");
  const [name, setName] = useState("");
  const [limit, setLimit] = useState("");
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");
  const [isError, setIsError] = useState(false);

  async function applyOverride(e: React.FormEvent) {
    e.preventDefault();
    if (!owner.trim() || !name.trim()) return;
    setSaving(true);
    setMsg("");
    try {
      const parsed = limit.trim() === "" ? null : parseInt(limit, 10);
      if (limit.trim() !== "" && (isNaN(parsed!) || parsed! < 0)) {
        throw new Error("Limit must be a non-negative number, or blank to reset");
      }
      const res = await fetch("/api/admin/rate-limit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ owner: owner.trim(), name: name.trim(), limit: parsed }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Failed");
      setMsg(
        parsed === null
          ? `Reset ${owner}/${name} to default (100/day)`
          : `Set ${owner}/${name} limit to ${parsed}/day`
      );
      setIsError(false);
      setOwner("");
      setName("");
      setLimit("");
    } catch (err: any) {
      setMsg(err.message ?? "Failed");
      setIsError(true);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Override form */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm p-5">
        <h2 className="text-sm font-semibold text-gray-800 dark:text-gray-200 mb-4">
          Override Rate Limit
        </h2>
        <form onSubmit={applyOverride} className="flex flex-wrap items-end gap-3">
          <div className="flex flex-col gap-1">
            <label className="text-xs text-gray-500 dark:text-gray-400">
              Owner
            </label>
            <input
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              placeholder="octocat"
              className="rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs text-gray-500 dark:text-gray-400">
              Repo name
            </label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="my-repo"
              className="rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs text-gray-500 dark:text-gray-400">
              Daily limit (blank = reset to 100)
            </label>
            <input
              type="number"
              value={limit}
              onChange={(e) => setLimit(e.target.value)}
              placeholder="e.g. 500"
              min={0}
              max={10000}
              className="w-32 rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <button
            type="submit"
            disabled={saving}
            className="rounded-md bg-gray-900 dark:bg-gray-100 px-4 py-1.5 text-sm font-semibold text-white dark:text-gray-900 hover:bg-gray-700 dark:hover:bg-gray-300 disabled:opacity-50 transition-colors"
          >
            {saving ? "Saving…" : "Apply"}
          </button>
        </form>
        {msg && (
          <p
            className={`mt-3 text-sm ${
              isError
                ? "text-red-600 dark:text-red-400"
                : "text-green-600 dark:text-green-400"
            }`}
          >
            {isError ? "✗" : "✓"} {msg}
          </p>
        )}
      </div>

      {/* Current rate-limited repos */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm">
        <div className="border-b border-gray-200 dark:border-gray-800 px-5 py-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-800 dark:text-gray-200">
            Repos Near/At Limit Today
          </h2>
          <span className="rounded-full bg-orange-100 dark:bg-orange-900/40 px-2 py-0.5 text-xs text-orange-700 dark:text-orange-400">
            {rateLimited.length}
          </span>
        </div>
        {rateLimited.length === 0 ? (
          <p className="px-5 py-8 text-center text-sm text-gray-400">
            No repos are near their daily limit today
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800 text-left text-xs text-gray-500 dark:text-gray-400">
                <th className="px-5 py-2 font-medium">Repo</th>
                <th className="px-5 py-2 font-medium text-right">
                  Scans today
                </th>
                <th className="px-5 py-2 font-medium text-right">Limit</th>
                <th className="px-5 py-2 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {rateLimited.map((r) => (
                <tr
                  key={`${r.owner}/${r.name}`}
                  className="border-b border-gray-100 dark:border-gray-800 last:border-0"
                >
                  <td className="px-5 py-2 font-mono text-xs text-gray-700 dark:text-gray-300">
                    {r.owner}/{r.name}
                  </td>
                  <td className="px-5 py-2 text-right font-semibold text-orange-600 dark:text-orange-400">
                    {r.scans_today}
                  </td>
                  <td className="px-5 py-2 text-right text-gray-500 dark:text-gray-400 text-xs">
                    {r.daily_limit}
                  </td>
                  <td className="px-5 py-2 text-right">
                    <button
                      onClick={() => {
                        setOwner(r.owner);
                        setName(r.name);
                        setLimit(String(r.daily_limit));
                      }}
                      className="text-xs text-brand-blue hover:underline"
                    >
                      Set limit
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ── Failures Tab ───────────────────────────────────────────────────────────

const PROVIDER_COLORS: Record<string, string> = {
  openrouter:    "bg-blue-500",
  github_models: "bg-purple-500",
  cerebras:      "bg-green-500",
  unknown:       "bg-gray-400",
};

function providerColor(name: string) {
  return PROVIDER_COLORS[name] ?? "bg-orange-500";
}

function FailuresTab({
  providerFailures,
  failureReasons,
  failureTrend,
  errorsWeek,
}: {
  providerFailures: ProviderFailure[];
  failureReasons: FailureReason[];
  failureTrend: FailureTrendDay[];
  errorsWeek: number;
}) {
  const maxBar = Math.max(...failureTrend.map((d) => d.errors), 1);
  const totalToday = providerFailures.reduce((s, p) => s + Number(p.today), 0);

  return (
    <div className="space-y-6">
      {/* Summary banner */}
      <div className={`rounded-xl border px-5 py-4 flex items-center gap-4 ${
        errorsWeek === 0
          ? "border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20"
          : "border-orange-200 dark:border-orange-800 bg-orange-50 dark:bg-orange-900/20"
      }`}>
        <span className="text-3xl font-bold text-orange-600 dark:text-orange-400">
          {errorsWeek}
        </span>
        <div>
          <p className="text-sm font-semibold text-gray-800 dark:text-gray-200">
            Engine errors in the last 7 days
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {totalToday} today · across {providerFailures.length} provider module{providerFailures.length !== 1 ? "s" : ""}
          </p>
        </div>
        {errorsWeek === 0 && (
          <span className="ml-auto text-sm font-medium text-green-600 dark:text-green-400">
            All clear ✓
          </span>
        )}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Failures by provider */}
        <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm">
          <div className="border-b border-gray-200 dark:border-gray-800 px-5 py-3">
            <h2 className="text-sm font-semibold text-gray-800 dark:text-gray-200">
              Failures by Provider Module (7d)
            </h2>
          </div>
          {providerFailures.length === 0 ? (
            <p className="px-5 py-8 text-center text-sm text-gray-400">No failures recorded</p>
          ) : (
            <div className="divide-y divide-gray-100 dark:divide-gray-800">
              {providerFailures.map((p) => {
                const pct = errorsWeek > 0 ? Math.round((Number(p.total) / errorsWeek) * 100) : 0;
                return (
                  <div key={p.provider} className="px-5 py-3 flex items-center gap-3">
                    <span className={`h-2.5 w-2.5 rounded-full shrink-0 ${providerColor(p.provider)}`} />
                    <span className="font-mono text-sm text-gray-700 dark:text-gray-300 flex-1">
                      {p.provider}
                    </span>
                    {/* Mini bar */}
                    <div className="w-24 h-1.5 rounded-full bg-gray-100 dark:bg-gray-800 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${providerColor(p.provider)}`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <span className="text-sm font-semibold text-gray-900 dark:text-gray-100 w-8 text-right">
                      {p.total}
                    </span>
                    <span className="text-xs text-gray-400 dark:text-gray-500 w-16 text-right">
                      {p.today > 0
                        ? <span className="text-orange-500">+{p.today} today</span>
                        : "0 today"}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* 7-day trend chart (bar) */}
        <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm">
          <div className="border-b border-gray-200 dark:border-gray-800 px-5 py-3">
            <h2 className="text-sm font-semibold text-gray-800 dark:text-gray-200">
              Daily Error Trend (7d)
            </h2>
          </div>
          <div className="px-5 py-4">
            {failureTrend.length === 0 ? (
              <p className="text-center text-sm text-gray-400 py-4">No data</p>
            ) : (
              <div className="flex items-end gap-2 h-24">
                {failureTrend.map((d) => {
                  const h = maxBar > 0 ? Math.max(4, Math.round((d.errors / maxBar) * 96)) : 4;
                  const label = new Date(d.day).toLocaleDateString(undefined, { weekday: "short" });
                  return (
                    <div key={d.day} className="flex-1 flex flex-col items-center gap-1">
                      <span className="text-[10px] text-gray-500 dark:text-gray-400">
                        {d.errors > 0 ? d.errors : ""}
                      </span>
                      <div
                        className="w-full rounded-t bg-orange-400 dark:bg-orange-500"
                        style={{ height: `${h}px` }}
                        title={`${label}: ${d.errors} errors`}
                      />
                      <span className="text-[10px] text-gray-400 dark:text-gray-500">{label}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Top error messages */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm">
        <div className="border-b border-gray-200 dark:border-gray-800 px-5 py-3">
          <h2 className="text-sm font-semibold text-gray-800 dark:text-gray-200">
            Top Error Messages (7d)
          </h2>
        </div>
        {failureReasons.length === 0 ? (
          <p className="px-5 py-8 text-center text-sm text-gray-400">No error messages recorded</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800 text-left text-xs text-gray-500 dark:text-gray-400">
                <th className="px-5 py-2 font-medium">Error message</th>
                <th className="px-5 py-2 font-medium text-right">Count</th>
                <th className="px-5 py-2 font-medium text-right">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {failureReasons.map((r, i) => (
                <tr key={i} className="border-b border-gray-100 dark:border-gray-800 last:border-0 hover:bg-gray-50 dark:hover:bg-gray-800">
                  <td className="px-5 py-2.5 font-mono text-xs text-gray-700 dark:text-gray-300 max-w-md truncate">
                    {r.title}
                  </td>
                  <td className="px-5 py-2.5 text-right font-semibold text-orange-600 dark:text-orange-400">
                    {r.count}
                  </td>
                  <td className="px-5 py-2.5 text-right text-xs text-gray-400 dark:text-gray-500">
                    {new Date(r.last_seen).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ── Main AdminTabs ─────────────────────────────────────────────────────────

type Tab = "overview" | "users" | "rate-limits" | "failures";

export function AdminTabs(props: AdminTabsProps) {
  const [tab, setTab] = useState<Tab>("overview");

  const tabs: { id: Tab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "users", label: `Users (${props.users.total})` },
    { id: "rate-limits", label: `Rate Limits (${props.rateLimited.length})` },
    {
      id: "failures",
      label: `Failures (${props.scans.errors_week ?? 0})`,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Tab bar */}
      <div className="flex gap-1 border-b border-gray-200 dark:border-gray-800">
        {tabs.map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              tab === id
                ? "border-gray-900 dark:border-gray-100 text-gray-900 dark:text-gray-100"
                : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "overview" && <OverviewTab {...props} />}
      {tab === "users" && <UsersTab />}
      {tab === "rate-limits" && <RateLimitsTab rateLimited={props.rateLimited} />}
      {tab === "failures" && (
        <FailuresTab
          providerFailures={props.providerFailures}
          failureReasons={props.failureReasons}
          failureTrend={props.failureTrend}
          errorsWeek={Number(props.scans.errors_week ?? 0)}
        />
      )}
    </div>
  );
}
