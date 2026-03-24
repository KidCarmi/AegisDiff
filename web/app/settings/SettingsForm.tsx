"use client";

import { useState } from "react";

export function SettingsForm({ retentionDays }: { retentionDays: number }) {
  const [days, setDays] = useState(retentionDays);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  async function save() {
    setSaving(true);
    await fetch("/api/settings", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scanRetentionDays: days }),
    });
    setSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  return (
    <div className="flex items-center gap-3">
      <input
        type="number"
        min={1}
        max={365}
        value={days}
        onChange={(e) => setDays(Number(e.target.value))}
        className="w-20 rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
      />
      <span className="text-sm text-gray-500">days</span>
      <button
        onClick={save}
        disabled={saving}
        className="rounded-md bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
      >
        {saved ? "Saved ✓" : saving ? "Saving…" : "Save"}
      </button>
    </div>
  );
}
