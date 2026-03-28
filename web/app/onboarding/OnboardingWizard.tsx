"use client";

import { useState } from "react";

interface Props {
  username: string;
  appSlug: string;
}

const GITHUB_SVG = (
  <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 24 24">
    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
  </svg>
);

function StepDots({ total, current }: { total: number; current: number }) {
  return (
    <div className="flex items-center gap-2 mb-8">
      {Array.from({ length: total }).map((_, i) => (
        <div
          key={i}
          className={`rounded-full transition-all ${
            i + 1 === current
              ? "w-6 h-2 bg-gray-900 dark:bg-gray-100"
              : i + 1 < current
              ? "w-2 h-2 bg-gray-400 dark:bg-gray-500"
              : "w-2 h-2 bg-gray-200 dark:bg-gray-700"
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
      <StepDots total={2} current={1} />
      <div className="mb-2 text-4xl">🛡️</div>
      <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-50 mb-2">
        Welcome{username ? `, @${username}` : ""}!
      </h1>
      <p className="text-gray-500 dark:text-gray-400 mb-8 leading-relaxed max-w-md">
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
          <div key={item.label} className="rounded-xl border border-gray-100 dark:border-gray-800 bg-gray-50 dark:bg-gray-900 p-4 text-center">
            <div className="text-2xl mb-1">{item.icon}</div>
            <div className="text-sm font-semibold text-gray-800 dark:text-gray-100">{item.label}</div>
            <div className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">{item.desc}</div>
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

// ─── Step 2: GitHub App Install ───────────────────────────────────────────────
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
      <StepDots total={2} current={2} />
      <h2 className="text-xl font-bold text-gray-900 dark:text-gray-50 mb-1">Install the GitHub App</h2>
      <p className="text-gray-500 dark:text-gray-400 text-sm mb-6">
        Select the repos you want to scan. AegisDiff handles everything from there —
        no YAML files, no API keys, no secrets.
      </p>

      <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-5 mb-6 space-y-3">
        {[
          { done: true, text: "Signed in with GitHub" },
          { done: clicked, text: "Install AegisDiff on your repos" },
          { done: false, text: "Open a pull request — results in ~90s" },
        ].map((step, i) => (
          <div key={i} className="flex items-center gap-3">
            <div
              className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
                step.done
                  ? "bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300"
                  : "bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-500"
              }`}
            >
              {step.done ? "✓" : i + 1}
            </div>
            <span className={`text-sm ${step.done ? "text-gray-400 dark:text-gray-500 line-through" : "text-gray-700 dark:text-gray-200"}`}>
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
            className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 px-5 py-3 text-sm font-semibold text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
          >
            I&apos;ve installed it →
          </button>
        )}
      </div>

      <div className="mt-4">
        <a href="/dashboard" className="text-xs text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-400">
          Skip for now →
        </a>
      </div>
    </div>
  );
}

// ─── Step 3: All done ─────────────────────────────────────────────────────────
function StepDone() {
  return (
    <div>
      <div className="mb-4 text-5xl">🎉</div>
      <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-50 mb-2">You&apos;re all set!</h2>
      <p className="text-gray-500 dark:text-gray-400 text-sm mb-8 max-w-md leading-relaxed">
        The GitHub App is installed. Open any pull request on a connected repo — AegisDiff
        will post a security analysis as a comment within ~90 seconds.
      </p>

      <div className="rounded-xl border border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-950 p-5 mb-8">
        <p className="text-sm font-semibold text-green-800 dark:text-green-200 mb-3">What happens next</p>
        <div className="space-y-2">
          {[
            "Open a pull request in a connected repo",
            "AegisDiff analyzes the diff (~90 seconds)",
            "A verdict comment is posted on your PR",
            "Results appear here in your dashboard",
          ].map((step, i) => (
            <div key={i} className="flex items-center gap-3 text-sm text-green-700 dark:text-green-300">
              <span className="text-green-500 font-bold">{i + 1}.</span>
              {step}
            </div>
          ))}
        </div>
      </div>

      <div className="flex gap-3">
        <a
          href="/dashboard"
          onClick={() => {
            document.cookie = "aegisdiff_onboarded=1; path=/; max-age=31536000; SameSite=Lax";
          }}
          className="rounded-xl bg-gray-900 px-6 py-3 text-sm font-semibold text-white hover:bg-gray-700 transition-colors"
        >
          Go to dashboard →
        </a>
        <a
          href="/repos"
          className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 px-6 py-3 text-sm font-semibold text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
        >
          Manage repos
        </a>
      </div>
    </div>
  );
}

// ─── Main wizard ──────────────────────────────────────────────────────────────
export function OnboardingWizard({ username, appSlug }: Props) {
  const [step, setStep] = useState<"welcome" | "install" | "done">("welcome");

  return (
    <div className="min-h-[calc(100vh-64px)] flex items-start justify-center pt-12 px-4">
      <div className="w-full max-w-lg">
        {step === "welcome" && (
          <StepWelcome username={username} onNext={() => setStep("install")} />
        )}
        {step === "install" && (
          <StepAppInstall appSlug={appSlug} onDone={() => setStep("done")} />
        )}
        {step === "done" && <StepDone />}
      </div>
    </div>
  );
}
