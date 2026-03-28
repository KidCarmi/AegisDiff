"use client";

import { useEffect, useState } from "react";
import { SlackForm } from "../slack/SlackForm";
import { DiscordForm } from "../discord/DiscordForm";
import { TeamsForm } from "../teams/TeamsForm";
import { NotifyForm } from "../notify/NotifyForm";

type Tab = "integrations" | "notifications" | "ignore" | "usage";

interface IgnoreRule {
  id: number;
  cwe_id: string | null;
  title_keyword: string | null;
  reason: string | null;
  created_at: string;
}

interface UsageData {
  scans_today: number;
  scans_7d: number;
  scans_30d: number;
  tp_today: number;
  limit: number;
  remaining: number;
}

// ── Ignore Rules panel ────────────────────────────────────────────────────────

function IgnoreRulesPanel({ owner, name }: { owner: string; name: string }) {
  const [rules, setRules] = useState<IgnoreRule[] | null>(null);
  const [cweId, setCweId] = useState("");
  const [keyword, setKeyword] = useState("");
  const [reason, setReason] = useState("");
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    fetch(`/api/repos/${owner}/${name}/ignore`)
      .then((r) => r.json())
      .then((d) => setRules(d.rules ?? []));
  };

  useEffect(load, [owner, name]);

  const add = async () => {
    if (!cweId.trim() && !keyword.trim()) {
      setError("Enter a CWE ID or title keyword.");
      return;
    }
    setAdding(true);
    setError(null);
    const r = await fetch(`/api/repos/${owner}/${name}/ignore`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        cweId: cweId.trim() || null,
        titleKeyword: keyword.trim() || null,
        reason: reason.trim() || null,
      }),
    });
    setAdding(false);
    if (r.ok) {
      setCweId("");
      setKeyword("");
      setReason("");
      load();
    } else {
      setError("Failed to add rule.");
    }
  };

  const remove = async (id: number) => {
    await fetch(`/api/repos/${owner}/${name}/ignore?id=${id}`, { method: "DELETE" });
    load();
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-200 mb-1">
          Ignore Rules
        </h3>
        <p className="text-xs text-gray-400 dark:text-gray-500">
          Suppress notifications for findings matching a CWE ID or title keyword. Does not
          affect scans already in the database.
        </p>
      </div>

      {/* Existing rules */}
      {rules === null ? (
        <div className="space-y-2">
          {[1, 2].map((i) => (
            <div key={i} className="h-12 rounded-lg bg-gray-100 dark:bg-gray-800 animate-pulse" />
          ))}
        </div>
      ) : rules.length === 0 ? (
        <div className="rounded-lg border border-dashed border-gray-200 dark:border-gray-700 p-6 text-center">
          <p className="text-sm text-gray-400 dark:text-gray-500">No ignore rules configured.</p>
        </div>
      ) : (
        <div className="divide-y divide-gray-100 dark:divide-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
          {rules.map((rule) => (
            <div
              key={rule.id}
              className="flex items-center justify-between px-4 py-3 bg-white dark:bg-gray-900"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  {rule.cwe_id && (
                    <span className="inline-flex items-center rounded bg-gray-100 dark:bg-gray-800 px-2 py-0.5 text-xs font-mono font-semibold text-gray-700 dark:text-gray-200">
                      {rule.cwe_id}
                    </span>
                  )}
                  {rule.title_keyword && (
                    <span className="inline-flex items-center rounded bg-blue-50 dark:bg-blue-900/30 px-2 py-0.5 text-xs font-semibold text-blue-700 dark:text-blue-300">
                      &quot;{rule.title_keyword}&quot;
                    </span>
                  )}
                  {rule.reason && (
                    <span className="text-xs text-gray-400 dark:text-gray-500 truncate">
                      — {rule.reason}
                    </span>
                  )}
                </div>
              </div>
              <button
                onClick={() => remove(rule.id)}
                className="ml-3 shrink-0 text-xs text-red-500 hover:underline"
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Add new rule */}
      <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-4 space-y-3">
        <p className="text-xs font-semibold text-gray-700 dark:text-gray-200">Add rule</p>
        <div className="grid sm:grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">
              CWE ID (e.g. CWE-89)
            </label>
            <input
              type="text"
              placeholder="CWE-89"
              value={cweId}
              onChange={(e) => setCweId(e.target.value)}
              className="w-full rounded border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">
              Title keyword
            </label>
            <input
              type="text"
              placeholder="SQL Injection"
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
              className="w-full rounded border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>
        <div>
          <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">
            Reason (optional)
          </label>
          <input
            type="text"
            placeholder="False positive — input is validated upstream"
            value={reason}
            maxLength={200}
            onChange={(e) => setReason(e.target.value)}
            className="w-full rounded border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        {error && <p className="text-xs text-red-500">{error}</p>}
        <button
          onClick={add}
          disabled={adding}
          className="rounded-md bg-gray-900 dark:bg-gray-100 px-4 py-1.5 text-sm font-medium text-white dark:text-gray-900 hover:bg-gray-700 dark:hover:bg-gray-200 disabled:opacity-50"
        >
          {adding ? "Adding…" : "Add rule"}
        </button>
      </div>
    </div>
  );
}

// ── Usage panel ───────────────────────────────────────────────────────────────

function UsagePanel({ owner, name }: { owner: string; name: string }) {
  const [data, setData] = useState<UsageData | null>(null);

  useEffect(() => {
    fetch(`/api/repos/${owner}/${name}/usage`)
      .then((r) => r.json())
      .then(setData);
  }, [owner, name]);

  if (!data) {
    return (
      <div className="space-y-3">
        <div className="h-6 w-48 rounded bg-gray-100 dark:bg-gray-800 animate-pulse" />
        <div className="h-4 rounded bg-gray-100 dark:bg-gray-800 animate-pulse" />
      </div>
    );
  }

  const pct = Math.min(100, Math.round((data.scans_today / data.limit) * 100));
  const barColor =
    pct >= 90 ? "bg-red-500" : pct >= 70 ? "bg-yellow-400" : "bg-green-500";

  return (
    <div className="space-y-6">
      {/* Rate limit meter */}
      <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-gray-700 dark:text-gray-200">
              Platform scan quota
            </p>
            <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">
              Resets every 24 hours. Add your own API keys for unlimited scans.
            </p>
          </div>
          <div className="text-right shrink-0">
            <span className="text-2xl font-bold text-gray-900 dark:text-gray-50">
              {data.scans_today}
            </span>
            <span className="text-sm text-gray-400 dark:text-gray-500">
              {" "}/ {data.limit}
            </span>
          </div>
        </div>

        {/* Bar */}
        <div className="h-2.5 w-full rounded-full bg-gray-100 dark:bg-gray-800 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${barColor}`}
            style={{ width: `${pct}%` }}
          />
        </div>

        <div className="flex items-center justify-between text-xs text-gray-400 dark:text-gray-500">
          <span>{data.remaining} scans remaining today</span>
          <span>{pct}% used</span>
        </div>

        {pct >= 90 && (
          <div className="rounded-md bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 px-3 py-2 text-xs text-red-700 dark:text-red-300">
            You&apos;re near the daily limit. Add{" "}
            <code className="font-mono">OPENROUTER_API_KEY</code> to your repo secrets for
            unlimited scans.
          </div>
        )}
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Scans today", value: data.scans_today },
          { label: "True positives today", value: data.tp_today, color: "text-red-600" },
          { label: "Scans (7 days)", value: data.scans_7d },
          { label: "Scans (30 days)", value: data.scans_30d },
        ].map((s) => (
          <div
            key={s.label}
            className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-4 text-center"
          >
            <div
              className={`text-2xl font-bold ${s.color ?? "text-gray-900 dark:text-gray-50"}`}
            >
              {s.value}
            </div>
            <div className="text-[11px] text-gray-400 dark:text-gray-500 mt-0.5">{s.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Tab bar ───────────────────────────────────────────────────────────────────

const TABS: { id: Tab; label: string }[] = [
  { id: "integrations", label: "Integrations" },
  { id: "notifications", label: "Notifications" },
  { id: "ignore", label: "Ignore Rules" },
  { id: "usage", label: "Usage" },
];

// ── Main export ───────────────────────────────────────────────────────────────

export function RepoSettingsTabs({ owner, name }: { owner: string; name: string }) {
  const [tab, setTab] = useState<Tab>("integrations");

  return (
    <div>
      {/* Tab bar */}
      <div className="flex gap-0.5 border-b border-gray-200 dark:border-gray-700 mb-6 overflow-x-auto">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm font-medium whitespace-nowrap transition-colors border-b-2 -mb-px ${
              tab === t.id
                ? "border-blue-600 text-blue-600 dark:text-blue-400 dark:border-blue-400"
                : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "integrations" && (
        <div className="space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-200 mb-1">
              Slack
            </h3>
            <SlackForm owner={owner} name={name} />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-200 mb-1">
              Discord
            </h3>
            <DiscordForm owner={owner} name={name} />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-200 mb-1">
              Microsoft Teams
            </h3>
            <TeamsForm owner={owner} name={name} />
          </div>
        </div>
      )}

      {tab === "notifications" && <NotifyForm owner={owner} name={name} />}

      {tab === "ignore" && <IgnoreRulesPanel owner={owner} name={name} />}

      {tab === "usage" && <UsagePanel owner={owner} name={name} />}
    </div>
  );
}
