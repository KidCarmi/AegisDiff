import { SignInButton } from "./SignInButton";

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

            <SignInButton />

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
