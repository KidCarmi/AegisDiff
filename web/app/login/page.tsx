"use client";
import { signIn } from "next-auth/react";

const FEATURES = [
  {
    icon: "⚡",
    title: "Zero config",
    desc: "One-click GitHub App install. No YAML files, no secrets to manage.",
  },
  {
    icon: "🔒",
    title: "Zero code egress",
    desc: "Your source code never leaves GitHub. Only scan metadata is stored.",
  },
  {
    icon: "🤖",
    title: "AI-powered triage",
    desc: "A cynical AppSec engineer that tries to disprove vulnerabilities first.",
  },
  {
    icon: "💰",
    title: "Free forever",
    desc: "Runs on GitHub Actions + Vercel + Neon free tiers. No credit card.",
  },
];

export default function LoginPage() {
  return (
    <div className="flex min-h-screen">
      {/* Left panel — dark, feature list */}
      <div className="hidden lg:flex flex-col justify-center px-16 w-[46%] bg-gray-900">
        <div className="max-w-xs">
          <div className="mb-10">
            <div className="text-3xl font-bold text-white mb-1">🛡️ AegisDiff</div>
            <p className="text-gray-400 text-sm leading-relaxed">
              Autonomous AppSec triage for every pull request. Catches real
              vulnerabilities, filters out the noise.
            </p>
          </div>
          <div className="space-y-6">
            {FEATURES.map((f) => (
              <div key={f.title} className="flex gap-4 items-start">
                <span className="text-2xl leading-none mt-0.5">{f.icon}</span>
                <div>
                  <p className="font-semibold text-white text-sm">{f.title}</p>
                  <p className="text-gray-400 text-xs mt-0.5 leading-relaxed">{f.desc}</p>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-10 pt-8 border-t border-gray-700">
            <p className="text-xs text-gray-500">
              Open source · Built on the Ghost Stack · $0/month
            </p>
          </div>
        </div>
      </div>

      {/* Right panel — sign in */}
      <div className="flex flex-1 items-center justify-center p-8 bg-gray-50">
        <div className="w-full max-w-sm">
          {/* Mobile logo */}
          <div className="text-center mb-8 lg:hidden">
            <div className="text-3xl font-bold text-gray-900 mb-1">🛡️ AegisDiff</div>
            <p className="text-sm text-gray-500">Autonomous AppSec triage for pull requests</p>
          </div>

          <div className="rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
            <h2 className="text-xl font-bold text-gray-900 mb-1">Welcome</h2>
            <p className="text-sm text-gray-500 mb-6">
              Sign in with GitHub to start scanning pull requests.
            </p>

            <button
              onClick={() => signIn("github", { callbackUrl: "/dashboard" })}
              className="w-full inline-flex items-center justify-center gap-3 rounded-xl bg-gray-900 px-4 py-3 text-sm font-semibold text-white hover:bg-gray-700 active:scale-[0.98] transition-all"
            >
              <svg className="h-5 w-5 shrink-0" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
              </svg>
              Continue with GitHub
            </button>

            <p className="mt-5 text-center text-xs text-gray-400">
              Requires read access to your repositories.
            </p>
          </div>

          {/* Mobile feature highlights */}
          <div className="mt-8 grid grid-cols-2 gap-3 lg:hidden">
            {FEATURES.map((f) => (
              <div key={f.title} className="rounded-xl border border-gray-200 bg-white p-3 text-center">
                <div className="text-xl mb-1">{f.icon}</div>
                <div className="text-xs font-semibold text-gray-700">{f.title}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
