"use client";

import { useState } from "react";

interface Props {
  owner: string;
  name: string;
  appInstalled: boolean;
  ingestUrl: string;
}

export function RepoSetup({ owner, name, appInstalled, ingestUrl }: Props) {
  const [open, setOpen] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  async function fetchToken() {
    if (token) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/repos/${owner}/${name}/token`);
      if (!res.ok) {
        const data = await res.json();
        setError(data.error ?? "Failed to load token");
      } else {
        const data = await res.json();
        setToken(data.token);
      }
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  }

  function handleOpen() {
    const next = !open;
    setOpen(next);
    if (next && appInstalled && !token) fetchToken();
  }

  async function copy(value: string, key: string) {
    await navigator.clipboard.writeText(value);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  }

  return (
    <div className="mt-2 border-t border-gray-100 pt-2">
      <button
        onClick={handleOpen}
        className="text-xs text-gray-400 hover:text-gray-700 flex items-center gap-1"
      >
        <span>{open ? "▾" : "▸"}</span>
        CI secrets setup
      </button>

      {open && (
        <div className="mt-3 rounded-md bg-gray-50 p-4 text-xs space-y-3">
          <p className="text-gray-600">
            Add these two secrets to{" "}
            <a
              href={`https://github.com/${owner}/${name}/settings/secrets/actions`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 hover:underline"
            >
              {owner}/{name} → Settings → Secrets
            </a>{" "}
            so the CI self-scan can post results to your dashboard.
          </p>

          {/* AEGISDIFF_INGEST_URL */}
          <div>
            <p className="font-mono font-semibold text-gray-700 mb-1">AEGISDIFF_INGEST_URL</p>
            <div className="flex items-center gap-2">
              <code className="flex-1 rounded bg-white border border-gray-200 px-2 py-1 font-mono text-gray-800 break-all">
                {ingestUrl}
              </code>
              <button
                onClick={() => copy(ingestUrl, "url")}
                className="shrink-0 rounded border border-gray-200 bg-white px-2 py-1 hover:bg-gray-100"
              >
                {copied === "url" ? "✓" : "Copy"}
              </button>
            </div>
          </div>

          {/* AEGISDIFF_REPO_TOKEN */}
          <div>
            <p className="font-mono font-semibold text-gray-700 mb-1">AEGISDIFF_REPO_TOKEN</p>
            {!appInstalled ? (
              <p className="text-gray-500 italic">
                Manual-connect token was shown once at registration time. To get a new one,
                remove and re-add the repo via{" "}
                <a href="/repos/connect" className="text-blue-600 hover:underline">
                  Manual Connect
                </a>
                .
              </p>
            ) : loading ? (
              <p className="text-gray-400 italic">Loading…</p>
            ) : error ? (
              <p className="text-red-500">{error}</p>
            ) : token ? (
              <div className="flex items-center gap-2">
                <code className="flex-1 rounded bg-white border border-gray-200 px-2 py-1 font-mono text-gray-800 break-all">
                  {token}
                </code>
                <button
                  onClick={() => copy(token, "token")}
                  className="shrink-0 rounded border border-gray-200 bg-white px-2 py-1 hover:bg-gray-100"
                >
                  {copied === "token" ? "✓" : "Copy"}
                </button>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
