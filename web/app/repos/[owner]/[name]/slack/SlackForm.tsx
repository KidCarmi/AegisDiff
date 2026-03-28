"use client";

import { useEffect, useState } from "react";

export function SlackForm({ owner, name }: { owner: string; name: string }) {
  const [url, setUrl] = useState("");
  const [masked, setMasked] = useState<string | null>(null);
  const [configured, setConfigured] = useState(false);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    fetch(`/api/repos/${owner}/${name}/slack`)
      .then((r) => r.json())
      .then((d) => {
        setConfigured(d.configured);
        setMasked(d.masked);
      });
  }, [owner, name]);

  async function save() {
    if (!url.startsWith("https://hooks.slack.com/")) {
      setStatus("Must be a Slack Incoming Webhook URL (https://hooks.slack.com/…)");
      return;
    }
    setSaving(true);
    const r = await fetch(`/api/repos/${owner}/${name}/slack`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ slackWebhookUrl: url }),
    });
    setSaving(false);
    if (r.ok) {
      setConfigured(true);
      setMasked(url.replace(/\/[^/]+$/, "/****"));
      setUrl("");
      setStatus("Webhook saved. You'll receive a Slack message on every TRUE_POSITIVE.");
    } else {
      setStatus("Failed to save — check the URL and try again.");
    }
  }

  async function remove() {
    await fetch(`/api/repos/${owner}/${name}/slack`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ slackWebhookUrl: null }),
    });
    setConfigured(false);
    setMasked(null);
    setStatus("Webhook removed.");
  }

  return (
    <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-6 shadow-sm space-y-4">
      {configured && masked && (
        <div className="rounded-md bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 px-4 py-3 flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-green-800 dark:text-green-300">Webhook configured</p>
            <p className="text-xs text-green-700 dark:text-green-400 font-mono mt-0.5">{masked}</p>
          </div>
          <button onClick={remove} className="text-xs text-red-500 hover:underline">
            Remove
          </button>
        </div>
      )}

      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          {configured ? "Replace webhook URL" : "Slack Webhook URL"}
        </label>
        <input
          type="url"
          placeholder="https://hooks.slack.com/services/T.../B.../..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
          Create one at api.slack.com → Your apps → Incoming Webhooks.
        </p>
      </div>

      <button
        onClick={save}
        disabled={saving || !url}
        className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
      >
        {saving ? "Saving…" : "Save webhook"}
      </button>

      {status && (
        <p className="text-sm text-gray-600 dark:text-gray-400">{status}</p>
      )}
    </div>
  );
}
