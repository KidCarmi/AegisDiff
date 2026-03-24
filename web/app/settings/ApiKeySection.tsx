"use client";
import { useState } from "react";

export function ApiKeySection() {
  const [key, setKey] = useState<string | null>(null);
  const [info, setInfo] = useState<{ key: string | null; createdAt?: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  async function load() {
    const r = await fetch("/api/v1/key");
    const d = await r.json();
    setInfo(d);
  }

  async function generate() {
    setLoading(true);
    const r = await fetch("/api/v1/key", { method: "POST" });
    const d = await r.json();
    setKey(d.key);
    setInfo(null);
    setLoading(false);
  }

  async function revoke() {
    await fetch("/api/v1/key", { method: "DELETE" });
    setKey(null); setInfo({ key: null });
  }

  async function copy() {
    if (!key) return;
    await navigator.clipboard.writeText(key);
    setCopied(true); setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-3">
      {key ? (
        <div className="space-y-2">
          <p className="text-xs text-amber-600 font-medium">
            ⚠️ Copy this key now — it won&apos;t be shown again.
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 rounded-lg bg-gray-900 text-green-400 px-3 py-2 text-xs font-mono break-all">
              {key}
            </code>
            <button onClick={copy}
              className="shrink-0 rounded-md border border-gray-200 px-3 py-2 text-xs font-medium text-gray-600 hover:bg-gray-50">
              {copied ? "✓" : "Copy"}
            </button>
          </div>
        </div>
      ) : info ? (
        info.key ? (
          <div className="rounded-md bg-gray-50 border border-gray-200 px-3 py-2 flex items-center justify-between">
            <div>
              <p className="text-xs font-medium text-gray-700">API key active</p>
              <p className="text-xs text-gray-400 font-mono mt-0.5">{info.key}</p>
            </div>
            <button onClick={revoke} className="text-xs text-red-500 hover:underline">Revoke</button>
          </div>
        ) : (
          <p className="text-sm text-gray-400">No API key configured.</p>
        )
      ) : (
        <button onClick={load} className="text-sm text-blue-600 hover:underline">
          Check existing key
        </button>
      )}

      <div className="flex gap-2">
        <button onClick={generate} disabled={loading}
          className="rounded-md bg-gray-900 px-4 py-1.5 text-sm font-medium text-white hover:bg-gray-700 disabled:opacity-50">
          {loading ? "Generating…" : key ? "Rotate key" : "Generate API key"}
        </button>
      </div>

      <div className="rounded-lg bg-gray-50 border border-gray-100 p-3 text-xs text-gray-500 space-y-1">
        <p className="font-semibold text-gray-600">Usage</p>
        <pre className="font-mono overflow-x-auto whitespace-pre-wrap break-all">
          {`curl https://aegis-diff.vercel.app/api/v1/scans \\
  -H "Authorization: Bearer ak_your_key"`}
        </pre>
        <p className="mt-1">Supports: <code>?repo=</code> <code>?verdict=</code> <code>?severity=</code> <code>?limit=</code> <code>?since=</code></p>
      </div>
    </div>
  );
}
