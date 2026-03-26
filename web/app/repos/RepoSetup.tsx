"use client";

import { useState } from "react";

interface Props {
  owner: string;
  name: string;
  ingestUrl: string;
  appInstalled: boolean;
}

type State = "idle" | "loading" | "done" | "error" | "permission_error";

export function RepoSetup({ owner, name, ingestUrl, appInstalled }: Props) {
  const [state, setState] = useState<State>("idle");
  const [message, setMessage] = useState("");
  const [showManual, setShowManual] = useState(!appInstalled);
  const [copied, setCopied] = useState(false);

  async function setupWorkflow() {
    setState("loading");
    try {
      const res = await fetch(`/api/repos/${owner}/${name}/setup-workflow`, { method: "POST" });
      const text = await res.text();
      let data: any = {};
      try { data = JSON.parse(text); } catch { /* non-JSON */ }
      if (!res.ok) {
        if (data.needs_permission_fix) {
          setState("permission_error");
          setShowManual(true);
          return;
        }
        throw new Error(data.error ?? `Server error ${res.status}`);
      }
      setState("done");
      setMessage(data.updated ? "Workflow updated!" : "Workflow added!");
    } catch (e: any) {
      setState("error");
      setMessage(e.message ?? "Failed");
    }
  }

  async function copy() {
    await navigator.clipboard.writeText(ingestUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  if (state === "done") {
    return (
      <div className="mt-2 border-t border-gray-100 dark:border-gray-800 pt-2">
        <p className="text-xs text-green-600 dark:text-green-400 flex items-center gap-1.5">
          <span>✓</span>
          <span>
            {message}{" "}
            <a
              href={`https://github.com/${owner}/${name}/blob/main/.github/workflows/aegisdiff.yml`}
              target="_blank"
              rel="noopener noreferrer"
              className="underline"
            >
              View on GitHub ↗
            </a>
          </span>
        </p>
      </div>
    );
  }

  return (
    <div className="mt-2 border-t border-gray-100 dark:border-gray-800 pt-2">
      {appInstalled ? (
        // GitHub App path — one click
        <div className="flex items-center gap-3 flex-wrap">
          <button
            onClick={setupWorkflow}
            disabled={state === "loading"}
            className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 dark:bg-gray-100 px-3 py-1.5 text-xs font-semibold text-white dark:text-gray-900 hover:bg-gray-700 dark:hover:bg-gray-200 disabled:opacity-50 transition-colors"
          >
            {state === "loading" ? (
              <>
                <svg className="h-3 w-3 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                </svg>
                Adding workflow…
              </>
            ) : (
              "⚡ Add workflow to repo"
            )}
          </button>
          {state === "error" && (
            <span className="text-xs text-red-500">{message}</span>
          )}
          {state === "permission_error" && (
            <span className="text-xs text-amber-600 dark:text-amber-400">
              App needs <strong>Contents: read &amp; write</strong> permission.{" "}
              <a
                href={`https://github.com/settings/apps`}
                target="_blank"
                rel="noopener noreferrer"
                className="underline"
              >
                Fix in GitHub App settings ↗
              </a>
              {" "}then re-accept the install. Use manual setup below in the meantime.
            </span>
          )}
          <button
            onClick={() => setShowManual((v) => !v)}
            className="text-xs text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-400"
          >
            {showManual ? "Hide manual instructions" : "Manual setup instead →"}
          </button>
        </div>
      ) : (
        // Manual path
        <button
          onClick={() => setShowManual((v) => !v)}
          className="text-xs text-gray-400 dark:text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 flex items-center gap-1"
        >
          <span>{showManual ? "▾" : "▸"}</span>
          CI setup
        </button>
      )}

      {showManual && (
        <div className="mt-3 rounded-md bg-gray-50 dark:bg-gray-800 p-4 text-xs space-y-3">
          <p className="text-gray-600 dark:text-gray-300">
            Add one secret to{" "}
            <a
              href={`https://github.com/${owner}/${name}/settings/secrets/actions`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 hover:underline"
            >
              {owner}/{name} → Settings → Secrets
            </a>
            . Auth is automatic via GitHub Actions OIDC.
          </p>
          <div>
            <p className="font-mono font-semibold text-gray-700 dark:text-gray-200 mb-1">
              AEGISDIFF_INGEST_URL
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 rounded bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 px-2 py-1 font-mono text-gray-800 dark:text-gray-200 break-all">
                {ingestUrl}
              </code>
              <button
                onClick={copy}
                className="shrink-0 rounded border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 px-2 py-1 hover:bg-gray-100 dark:hover:bg-gray-800 text-gray-600 dark:text-gray-300"
              >
                {copied ? "✓" : "Copy"}
              </button>
            </div>
          </div>
          <p className="text-gray-400 dark:text-gray-500">
            Then copy the{" "}
            <a
              href="https://github.com/KidCarmi/AegisDiff/blob/main/.github/workflows/aegisdiff.yml"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 hover:underline"
            >
              aegisdiff.yml workflow
            </a>{" "}
            into <code className="bg-gray-100 dark:bg-gray-700 px-1 rounded">.github/workflows/</code> in your repo.
          </p>
        </div>
      )}
    </div>
  );
}
