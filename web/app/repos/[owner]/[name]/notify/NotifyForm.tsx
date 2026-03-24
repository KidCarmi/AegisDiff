"use client";
import { useEffect, useState } from "react";

const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

export function NotifyForm({ owner, name }: { owner: string; name: string }) {
  const [minSeverity, setMinSeverity] = useState("INFO");
  const [notifyNeedsReview, setNotifyNeedsReview] = useState(false);
  const [autoGithubIssue, setAutoGithubIssue] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    fetch(`/api/repos/${owner}/${name}/notify`)
      .then((r) => r.json())
      .then((d) => {
        setMinSeverity(d.minSeverity ?? "INFO");
        setNotifyNeedsReview(d.notifyNeedsReview ?? false);
        setAutoGithubIssue(d.autoGithubIssue ?? false);
      });
  }, [owner, name]);

  async function save() {
    setSaving(true);
    await fetch(`/api/repos/${owner}/${name}/notify`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ minSeverity, notifyNeedsReview, autoGithubIssue }),
    });
    setSaving(false); setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm space-y-6">
      {/* Min severity */}
      <div>
        <label className="block text-sm font-semibold text-gray-700 mb-2">
          Minimum severity to trigger notifications
        </label>
        <p className="text-xs text-gray-400 mb-3">
          Webhooks (Slack, Discord, Teams) only fire when the scan severity is at or above this level.
        </p>
        <div className="flex gap-2 flex-wrap">
          {SEVERITIES.map((s) => (
            <button key={s} onClick={() => setMinSeverity(s)}
              className={`rounded-full px-3 py-1 text-xs font-semibold transition-colors ${
                minSeverity === s ? "bg-gray-900 text-white" : "border border-gray-200 text-gray-600 hover:bg-gray-50"
              }`}>
              {s}
            </button>
          ))}
        </div>
        <p className="mt-2 text-xs text-gray-400">
          Current: notify when severity ≥ <strong>{minSeverity}</strong>
        </p>
      </div>

      {/* Notify on NEEDS_REVIEW */}
      <div className="flex items-start gap-3">
        <input type="checkbox" id="nr" checked={notifyNeedsReview}
          onChange={(e) => setNotifyNeedsReview(e.target.checked)}
          className="mt-0.5 h-4 w-4 rounded border-gray-300 accent-gray-900"
        />
        <div>
          <label htmlFor="nr" className="text-sm font-medium text-gray-700 cursor-pointer">
            Also notify on NEEDS_REVIEW
          </label>
          <p className="text-xs text-gray-400 mt-0.5">
            By default, webhooks only fire on TRUE_POSITIVE. Enable this to also alert on uncertain findings.
          </p>
        </div>
      </div>

      {/* Auto GitHub Issue */}
      <div className="flex items-start gap-3">
        <input type="checkbox" id="gi" checked={autoGithubIssue}
          onChange={(e) => setAutoGithubIssue(e.target.checked)}
          className="mt-0.5 h-4 w-4 rounded border-gray-300 accent-gray-900"
        />
        <div>
          <label htmlFor="gi" className="text-sm font-medium text-gray-700 cursor-pointer">
            Auto-create GitHub Issue on TRUE_POSITIVE
          </label>
          <p className="text-xs text-gray-400 mt-0.5">
            Requires this repo to be installed via the GitHub App (uses installation token).
            Opens a &apos;security&apos;-labelled issue with the verdict details.
          </p>
        </div>
      </div>

      <button onClick={save} disabled={saving}
        className="rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white hover:bg-gray-700 disabled:opacity-50">
        {saved ? "Saved ✓" : saving ? "Saving…" : "Save settings"}
      </button>
    </div>
  );
}
