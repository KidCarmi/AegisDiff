"use client";

import { useState } from "react";

interface Props {
  username: string;
  ingestUrl: string;
  appSlug: string;
}

type Method = "app" | "manual" | null;

const GITHUB_SVG = (
  <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 24 24">
    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
  </svg>
);

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
  return (
    <button
      onClick={copy}
      className="shrink-0 rounded-md border border-gray-200 bg-white px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 transition-colors"
    >
      {copied ? "✓ Copied" : "Copy"}
    </button>
  );
}

function SecretRow({ name, value }: { name: string; value: string }) {
  return (
    <div className="space-y-1">
      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">{name}</p>
      <div className="flex items-center gap-2">
        <code className="flex-1 rounded-lg bg-gray-900 text-green-400 px-3 py-2 text-xs font-mono break-all">
          {value}
        </code>
        <CopyButton value={value} />
      </div>
    </div>
  );
}

function StepDots({ total, current }: { total: number; current: number }) {
  return (
    <div className="flex items-center gap-2 mb-8">
      {Array.from({ length: total }).map((_, i) => (
        <div
          key={i}
          className={`rounded-full transition-all ${
            i + 1 === current
              ? "w-6 h-2 bg-gray-900"
              : i + 1 < current
              ? "w-2 h-2 bg-gray-400"
              : "w-2 h-2 bg-gray-200"
          }`}
        />
      ))}
    </div>
  );
}

// ─── Step 1: Welcome ──────────────────────────────────────────────────────────
function StepWelcome({ username, onNext }: { username: string; onNext: () => void }) {
  return (
    <div>
      <StepDots total={3} current={1} />
      <div className="mb-2 text-4xl">🛡️</div>
      <h1 className="text-2xl font-bold text-gray-900 mb-2">
        Welcome{username ? `, @${username}` : ""}!
      </h1>
      <p className="text-gray-500 mb-8 leading-relaxed max-w-md">
        AegisDiff automatically analyzes every pull request for security vulnerabilities.
        A cynical AI AppSec engineer reviews each diff — trying to disprove issues, not
        just flag them. Let&apos;s get you set up.
      </p>

      <div className="grid sm:grid-cols-3 gap-3 mb-8">
        {[
          { icon: "⚡", label: "90 seconds", desc: "from PR open to analysis" },
          { icon: "🔒", label: "Zero code egress", desc: "your code stays on GitHub" },
          { icon: "💰", label: "$0/month", desc: "runs on free tiers" },
        ].map((item) => (
          <div key={item.label} className="rounded-xl border border-gray-100 bg-gray-50 p-4 text-center">
            <div className="text-2xl mb-1">{item.icon}</div>
            <div className="text-sm font-semibold text-gray-800">{item.label}</div>
            <div className="text-xs text-gray-400 mt-0.5">{item.desc}</div>
          </div>
        ))}
      </div>

      <button
        onClick={onNext}
        className="rounded-xl bg-gray-900 px-6 py-3 text-sm font-semibold text-white hover:bg-gray-700 active:scale-[0.98] transition-all"
      >
        Get started →
      </button>
    </div>
  );
}

// ─── Step 2: Choose method ────────────────────────────────────────────────────
function StepChoose({
  appSlug,
  onChoose,
}: {
  appSlug: string;
  onChoose: (method: Method) => void;
}) {
  return (
    <div>
      <StepDots total={3} current={2} />
      <h2 className="text-xl font-bold text-gray-900 mb-1">Connect a repository</h2>
      <p className="text-gray-500 text-sm mb-6">Choose how you want to integrate AegisDiff.</p>

      <div className="space-y-3 mb-6">
        {/* GitHub App card */}
        <button
          onClick={() => onChoose("app")}
          className="w-full text-left rounded-xl border-2 border-blue-500 bg-blue-50 p-5 hover:bg-blue-100 transition-colors group"
        >
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-bold text-blue-900">GitHub App</span>
                <span className="rounded-full bg-blue-600 px-2 py-0.5 text-xs font-semibold text-white">
                  Recommended
                </span>
              </div>
              <p className="text-xs text-blue-700 leading-relaxed">
                One-click install. No YAML files, no API keys, no secrets.
                AegisDiff uses its own API keys — you pay nothing.
              </p>
              <div className="mt-3 flex gap-2 flex-wrap">
                {["No config", "Our API keys", "Instant"].map((tag) => (
                  <span key={tag} className="rounded-md bg-blue-100 px-2 py-0.5 text-xs text-blue-700">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
            <span className="ml-4 text-blue-500 group-hover:translate-x-0.5 transition-transform">→</span>
          </div>
        </button>

        {/* Manual card */}
        <button
          onClick={() => onChoose("manual")}
          className="w-full text-left rounded-xl border border-gray-200 bg-white p-5 hover:bg-gray-50 transition-colors group"
        >
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-bold text-gray-800">Manual workflow</span>
                <span className="rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-500">
                  Advanced
                </span>
              </div>
              <p className="text-xs text-gray-500 leading-relaxed">
                Copy a workflow file into your repo. Bring your own Gemini or Groq API keys.
                Full control over every step.
              </p>
              <div className="mt-3 flex gap-2 flex-wrap">
                {["Your API keys", "Full control", "Open source"].map((tag) => (
                  <span key={tag} className="rounded-md bg-gray-100 px-2 py-0.5 text-xs text-gray-600">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
            <span className="ml-4 text-gray-400 group-hover:translate-x-0.5 transition-transform">→</span>
          </div>
        </button>
      </div>

      <a href="/dashboard" className="text-xs text-gray-400 hover:text-gray-600">
        Skip for now →
      </a>
    </div>
  );
}

// ─── Step 3a: GitHub App ──────────────────────────────────────────────────────
function StepAppInstall({
  appSlug,
  onDone,
}: {
  appSlug: string;
  onDone: () => void;
}) {
  const [clicked, setClicked] = useState(false);

  return (
    <div>
      <StepDots total={3} current={3} />
      <h2 className="text-xl font-bold text-gray-900 mb-1">Install the GitHub App</h2>
      <p className="text-gray-500 text-sm mb-6">
        Select the repos you want to scan. AegisDiff handles everything from there.
      </p>

      <div className="rounded-xl border border-gray-200 bg-white p-5 mb-6 space-y-3">
        {[
          { done: true, text: "Signed in with GitHub" },
          { done: clicked, text: "Install AegisDiff on your repos" },
          { done: false, text: "Open a pull request — results in ~90s" },
        ].map((step, i) => (
          <div key={i} className="flex items-center gap-3">
            <div
              className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
                step.done
                  ? "bg-green-100 text-green-700"
                  : "bg-gray-100 text-gray-400"
              }`}
            >
              {step.done ? "✓" : i + 1}
            </div>
            <span className={`text-sm ${step.done ? "text-gray-400 line-through" : "text-gray-700"}`}>
              {step.text}
            </span>
          </div>
        ))}
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <a
          href={`https://github.com/apps/${appSlug}/installations/new`}
          target="_blank"
          rel="noopener noreferrer"
          onClick={() => setClicked(true)}
          className="inline-flex items-center justify-center gap-2 rounded-xl bg-gray-900 px-5 py-3 text-sm font-semibold text-white hover:bg-gray-700 transition-colors"
        >
          {GITHUB_SVG}
          Install on GitHub
        </a>
        {clicked && (
          <button
            onClick={onDone}
            className="rounded-xl border border-gray-200 bg-white px-5 py-3 text-sm font-semibold text-gray-700 hover:bg-gray-50 transition-colors"
          >
            I&apos;ve installed it →
          </button>
        )}
      </div>
    </div>
  );
}

// ─── Step 3b: Manual setup ────────────────────────────────────────────────────
function StepManualSetup({ ingestUrl, onDone }: { ingestUrl: string; onDone: () => void }) {
  return (
    <div>
      <StepDots total={3} current={3} />
      <h2 className="text-xl font-bold text-gray-900 mb-1">Manual setup</h2>
      <p className="text-gray-500 text-sm mb-6">
        Three steps — takes about 2 minutes.
      </p>

      <div className="space-y-5 mb-8">
        {/* Step 1 */}
        <div className="rounded-xl border border-gray-200 bg-white p-5">
          <div className="flex items-center gap-2 mb-3">
            <span className="w-5 h-5 rounded-full bg-gray-900 text-white text-xs font-bold flex items-center justify-center">1</span>
            <span className="text-sm font-semibold text-gray-800">Add your LLM API key</span>
          </div>
          <p className="text-xs text-gray-500 mb-3">
            Get a free key from{" "}
            <a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
              Google AI Studio
            </a>{" "}
            (Gemini) or{" "}
            <a href="https://console.groq.com/keys" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
              Groq Console
            </a>
            . Add it as a secret in your repo.
          </p>
          <div className="flex gap-2 flex-wrap">
            <code className="rounded-md bg-gray-100 px-2 py-1 text-xs font-mono">GEMINI_API_KEY</code>
            <span className="text-xs text-gray-400 self-center">or</span>
            <code className="rounded-md bg-gray-100 px-2 py-1 text-xs font-mono">GROQ_API_KEY</code>
          </div>
        </div>

        {/* Step 2 */}
        <div className="rounded-xl border border-gray-200 bg-white p-5">
          <div className="flex items-center gap-2 mb-3">
            <span className="w-5 h-5 rounded-full bg-gray-900 text-white text-xs font-bold flex items-center justify-center">2</span>
            <span className="text-sm font-semibold text-gray-800">Add the ingest URL secret</span>
          </div>
          <p className="text-xs text-gray-500 mb-3">
            This tells the workflow where to send scan results. Auth is automatic via GitHub OIDC.
          </p>
          <SecretRow name="AEGISDIFF_INGEST_URL" value={ingestUrl} />
        </div>

        {/* Step 3 */}
        <div className="rounded-xl border border-gray-200 bg-white p-5">
          <div className="flex items-center gap-2 mb-3">
            <span className="w-5 h-5 rounded-full bg-gray-900 text-white text-xs font-bold flex items-center justify-center">3</span>
            <span className="text-sm font-semibold text-gray-800">Copy the workflow file</span>
          </div>
          <p className="text-xs text-gray-500 mb-3">
            Add this file to your repo at{" "}
            <code className="bg-gray-100 px-1 rounded text-gray-700">.github/workflows/aegisdiff.yml</code>
          </p>
          <a
            href="https://github.com/KidCarmi/AegisDiff/blob/main/.github/workflows/aegisdiff.yml"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 px-3 py-2 text-xs font-medium text-gray-700 hover:bg-gray-50 transition-colors"
          >
            {GITHUB_SVG}
            View aegisdiff.yml on GitHub
          </a>
        </div>
      </div>

      <button
        onClick={onDone}
        className="rounded-xl bg-gray-900 px-6 py-3 text-sm font-semibold text-white hover:bg-gray-700 transition-colors"
      >
        Done, go to dashboard →
      </button>
    </div>
  );
}

// ─── Step 4: All done ─────────────────────────────────────────────────────────
function StepDone({ method }: { method: Method }) {
  return (
    <div>
      <div className="mb-4 text-5xl">🎉</div>
      <h2 className="text-2xl font-bold text-gray-900 mb-2">You&apos;re all set!</h2>
      <p className="text-gray-500 text-sm mb-8 max-w-md leading-relaxed">
        {method === "app"
          ? "The GitHub App is installed. Open any pull request on a connected repo — AegisDiff will post a security analysis as a comment within ~90 seconds."
          : "The workflow is set up. Open any pull request and AegisDiff will automatically analyze it for security vulnerabilities."}
      </p>

      <div className="rounded-xl border border-green-200 bg-green-50 p-5 mb-8">
        <p className="text-sm font-semibold text-green-800 mb-3">What happens next</p>
        <div className="space-y-2">
          {[
            "Open a pull request in a connected repo",
            "AegisDiff analyzes the diff (~90 seconds)",
            "A verdict comment is posted on your PR",
            "Results appear here in your dashboard",
          ].map((step, i) => (
            <div key={i} className="flex items-center gap-3 text-sm text-green-700">
              <span className="text-green-500 font-bold">{i + 1}.</span>
              {step}
            </div>
          ))}
        </div>
      </div>

      <div className="flex gap-3">
        <a
          href="/dashboard"
          className="rounded-xl bg-gray-900 px-6 py-3 text-sm font-semibold text-white hover:bg-gray-700 transition-colors"
        >
          Go to dashboard →
        </a>
        <a
          href="/repos"
          className="rounded-xl border border-gray-200 bg-white px-6 py-3 text-sm font-semibold text-gray-700 hover:bg-gray-50 transition-colors"
        >
          Manage repos
        </a>
      </div>
    </div>
  );
}

// ─── Main wizard ──────────────────────────────────────────────────────────────
export function OnboardingWizard({ username, ingestUrl, appSlug }: Props) {
  const [step, setStep] = useState<"welcome" | "choose" | "setup" | "done">("welcome");
  const [method, setMethod] = useState<Method>(null);

  function handleChoose(m: Method) {
    setMethod(m);
    setStep("setup");
  }

  return (
    <div className="min-h-[calc(100vh-64px)] flex items-start justify-center pt-12 px-4">
      <div className="w-full max-w-lg">
        {step === "welcome" && (
          <StepWelcome username={username} onNext={() => setStep("choose")} />
        )}
        {step === "choose" && (
          <StepChoose appSlug={appSlug} onChoose={handleChoose} />
        )}
        {step === "setup" && method === "app" && (
          <StepAppInstall appSlug={appSlug} onDone={() => setStep("done")} />
        )}
        {step === "setup" && method === "manual" && (
          <StepManualSetup ingestUrl={ingestUrl} onDone={() => setStep("done")} />
        )}
        {step === "done" && <StepDone method={method} />}
      </div>
    </div>
  );
}
