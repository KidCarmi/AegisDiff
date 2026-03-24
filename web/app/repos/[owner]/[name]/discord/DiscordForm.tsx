"use client";
import { useEffect, useState } from "react";

export function DiscordForm({ owner, name }: { owner: string; name: string }) {
  const [url, setUrl] = useState("");
  const [masked, setMasked] = useState<string | null>(null);
  const [configured, setConfigured] = useState(false);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    fetch(`/api/repos/${owner}/${name}/discord`)
      .then((r) => r.json())
      .then((d) => { setConfigured(d.configured); setMasked(d.masked); });
  }, [owner, name]);

  async function save() {
    if (!url.startsWith("https://discord.com/api/webhooks/") && !url.startsWith("https://discordapp.com/api/webhooks/")) {
      setStatus("Must be a Discord Incoming Webhook URL (https://discord.com/api/webhooks/…)");
      return;
    }
    setSaving(true);
    const r = await fetch(`/api/repos/${owner}/${name}/discord`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ discordWebhookUrl: url }),
    });
    setSaving(false);
    if (r.ok) {
      setConfigured(true);
      setMasked(url.replace(/\/[^/]+$/, "/****"));
      setUrl("");
      setStatus("Webhook saved. You'll receive a Discord message on every TRUE_POSITIVE.");
    } else {
      setStatus("Failed to save — check the URL and try again.");
    }
  }

  async function remove() {
    await fetch(`/api/repos/${owner}/${name}/discord`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ discordWebhookUrl: null }),
    });
    setConfigured(false); setMasked(null);
    setStatus("Webhook removed.");
  }

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm space-y-4">
      {configured && masked && (
        <div className="rounded-md bg-green-50 border border-green-200 px-4 py-3 flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-green-800">Webhook configured</p>
            <p className="text-xs text-green-700 font-mono mt-0.5">{masked}</p>
          </div>
          <button onClick={remove} className="text-xs text-red-500 hover:underline">Remove</button>
        </div>
      )}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          {configured ? "Replace webhook URL" : "Discord Webhook URL"}
        </label>
        <input type="url"
          placeholder="https://discord.com/api/webhooks/123456/token"
          value={url} onChange={(e) => setUrl(e.target.value)}
          className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <p className="mt-1 text-xs text-gray-400">
          Discord server → Edit Channel → Integrations → Webhooks → New Webhook.
        </p>
      </div>
      <button onClick={save} disabled={saving || !url}
        className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50">
        {saving ? "Saving…" : "Save webhook"}
      </button>
      {status && <p className="text-sm text-gray-600">{status}</p>}
    </div>
  );
}
