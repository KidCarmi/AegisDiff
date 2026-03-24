"use client";

import { useState } from "react";

interface Props {
  owner: string;
  name: string;
  ingestUrl: string;
}

export function RepoSetup({ owner, name, ingestUrl }: Props) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(ingestUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="mt-2 border-t border-gray-100 pt-2">
      <button
        onClick={() => setOpen((v) => !v)}
        className="text-xs text-gray-400 hover:text-gray-700 flex items-center gap-1"
      >
        <span>{open ? "▾" : "▸"}</span>
        CI setup
      </button>

      {open && (
        <div className="mt-3 rounded-md bg-gray-50 p-4 text-xs space-y-3">
          <p className="text-gray-600">
            Add one secret to{" "}
            <a
              href={`https://github.com/${owner}/${name}/settings/secrets/actions`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 hover:underline"
            >
              {owner}/{name} → Settings → Secrets
            </a>
            . Authentication is handled automatically via GitHub Actions OIDC — no token required.
          </p>

          <div>
            <p className="font-mono font-semibold text-gray-700 mb-1">AEGISDIFF_INGEST_URL</p>
            <div className="flex items-center gap-2">
              <code className="flex-1 rounded bg-white border border-gray-200 px-2 py-1 font-mono text-gray-800 break-all">
                {ingestUrl}
              </code>
              <button
                onClick={copy}
                className="shrink-0 rounded border border-gray-200 bg-white px-2 py-1 hover:bg-gray-100"
              >
                {copied ? "✓" : "Copy"}
              </button>
            </div>
          </div>

          <p className="text-gray-400">
            Then copy the{" "}
            <a
              href="https://github.com/KidCarmi/AegisDiff/blob/main/.github/workflows/aegisdiff.yml"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 hover:underline"
            >
              aegisdiff.yml workflow
            </a>{" "}
            into <code>.github/workflows/</code> in your repo. That&apos;s it.
          </p>
        </div>
      )}
    </div>
  );
}
