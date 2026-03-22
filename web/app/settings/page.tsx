import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import { authOptions } from "../../lib/auth";

export default async function SettingsPage() {
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");

  return (
    <div className="max-w-2xl">
      <h1 className="mb-6 text-2xl font-bold text-gray-900">Settings</h1>

      <section className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-gray-800 mb-4">Account</h2>
        <div className="space-y-2 text-sm">
          <div className="flex items-center gap-3">
            <span className="text-gray-500 w-24">GitHub user</span>
            <span className="font-mono text-gray-900">{session.user?.name}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-gray-500 w-24">Email</span>
            <span className="text-gray-900">{session.user?.email ?? "—"}</span>
          </div>
        </div>
      </section>

      <section className="mt-6 rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-gray-800 mb-2">API Keys</h2>
        <p className="text-sm text-gray-500 mb-4">
          AegisDiff uses <strong>your own LLM API keys</strong>, stored as GitHub Secrets
          in each connected repository. We never store or access your keys.
        </p>
        <div className="rounded-md bg-gray-50 border border-gray-200 p-4 text-sm font-mono space-y-1">
          <div><span className="text-blue-600">GEMINI_API_KEY</span> — Google AI Studio (primary)</div>
          <div><span className="text-blue-600">GROQ_API_KEY</span> — Groq Llama-3 (fallback)</div>
          <div><span className="text-blue-600">AEGISDIFF_REPO_TOKEN</span> — Generated per repo</div>
          <div><span className="text-blue-600">AEGISDIFF_INGEST_URL</span> — Your dashboard URL + /api/ingest</div>
        </div>
        <p className="mt-3 text-xs text-gray-400">
          These secrets are stored in GitHub's encrypted secrets vault — not in AegisDiff's database.
        </p>
      </section>

      <section className="mt-6 rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-gray-800 mb-2">Privacy</h2>
        <p className="text-sm text-gray-500">
          AegisDiff operates on a <strong>zero code egress</strong> model. Your source code
          never leaves GitHub's infrastructure. The analysis engine runs directly inside
          your GitHub Actions runner. Only scan metadata (verdict, severity, confidence) is
          sent to this dashboard — never code, diffs, or evidence quotes.
        </p>
      </section>
    </div>
  );
}
