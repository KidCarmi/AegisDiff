/**
 * POST /api/repos/[owner]/[name]/setup-workflow
 *
 * Commits .github/workflows/aegisdiff.yml directly to the user's repo
 * via the GitHub App installation token. No manual steps required.
 *
 * The ingest URL is hardcoded (it's not a secret — auth is via OIDC).
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../../../lib/auth";
import { requireRepoRole } from "../../../../../../lib/rbac";
import { sql } from "../../../../../../lib/db";
import { getInstallationToken, ghFetch } from "../../../../../../lib/github-app";

const WORKFLOW_PATH = ".github/workflows/aegisdiff.yml";

function buildWorkflowContent(ingestUrl: string): string {
  return `name: AegisDiff — AppSec Triage

on:
  pull_request:
    types: [opened, synchronize, reopened]
    paths:
      - "**.py"
      - "**.js"
      - "**.ts"
      - "**.tsx"
      - "**.jsx"
      - "**.go"
      - "**.java"
      - "**.rb"
      - "**.php"
  workflow_dispatch: {}

permissions:
  contents: read
  pull-requests: write
  issues: write
  id-token: write

jobs:
  appsec-triage:
    name: Security Triage
    runs-on: ubuntu-latest
    timeout-minutes: 10

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: "pip"

      - name: Install AegisDiff
        run: |
          pip install --quiet httpx>=0.27 tree-sitter-languages>=1.10
          pip install --quiet -e git+https://github.com/KidCarmi/AegisDiff.git#egg=aegisdiff

      - name: Generate diff
        id: diff
        run: |
          if [ "\${{ github.event_name }}" = "pull_request" ]; then
            BASE_SHA="\${{ github.event.pull_request.base.sha }}"
            HEAD_SHA="\${{ github.event.pull_request.head.sha }}"
          else
            BASE_SHA="\${{ github.event.before }}"
            HEAD_SHA="\${{ github.event.after || github.sha }}"
          fi
          timeout 60 git diff "\${BASE_SHA}...\${HEAD_SHA}" \\
            -- "*.py" "*.js" "*.ts" "*.tsx" "*.jsx" "*.go" "*.java" "*.rb" "*.php" \\
            > /tmp/aegisdiff_pr.diff 2>/dev/null || true
          if [ ! -s /tmp/aegisdiff_pr.diff ]; then
            echo "skip=true" >> "$GITHUB_OUTPUT"
          else
            echo "skip=false" >> "$GITHUB_OUTPUT"
          fi

      - name: Run AegisDiff triage
        if: steps.diff.outputs.skip == 'false'
        env:
          AEGISDIFF_INGEST_URL: "${ingestUrl}"
          GITHUB_TOKEN:         \${{ secrets.GITHUB_TOKEN }}
          PR_NUMBER:            \${{ github.event.pull_request.number || '' }}
          COMMIT_SHA:           \${{ github.sha }}
          REPO:                 \${{ github.repository }}
          DIFF_PATH:            /tmp/aegisdiff_pr.diff
        run: python -m aegisdiff.entrypoint
`;
}

export async function POST(
  req: NextRequest,
  { params }: { params: { owner: string; name: string } }
) {
  try {
    const session = await getServerSession(authOptions);
    try { await requireRepoRole(session, params.owner, params.name, "repo:admin"); }
    catch (r) { return r as Response; }

    const { owner, name } = params;

    // Get the installation ID for this repo
    const rows = await sql`
      SELECT installation_id FROM repos
      WHERE owner = ${owner} AND name = ${name} AND installation_id IS NOT NULL
      LIMIT 1
    `;
    if (!rows.length || !(rows[0] as any).installation_id) {
      return NextResponse.json(
        { error: "Repo not connected via GitHub App. Use the manual setup instructions." },
        { status: 400 }
      );
    }
    const installationId = (rows[0] as any).installation_id as number;
    const token = await getInstallationToken(installationId);

    const ingestUrl = `${process.env.NEXTAUTH_URL ?? "https://aegis-diff.vercel.app"}/api/ingest`;
    const content = buildWorkflowContent(ingestUrl);
    const contentB64 = Buffer.from(content).toString("base64");

    // Check if file already exists (need sha to update)
    let existingSha: string | undefined;
    try {
      const existing = await ghFetch(
        `https://api.github.com/repos/${owner}/${name}/contents/${WORKFLOW_PATH}`,
        token
      );
      existingSha = (existing as any).sha;
    } catch {
      // File doesn't exist yet — that's fine
    }

    await ghFetch(
      `https://api.github.com/repos/${owner}/${name}/contents/${WORKFLOW_PATH}`,
      token,
      "PUT",
      {
        message: existingSha
          ? "Update AegisDiff security scanning workflow"
          : "Add AegisDiff security scanning workflow",
        content: contentB64,
        ...(existingSha ? { sha: existingSha } : {}),
      }
    );

    return NextResponse.json({ ok: true, updated: !!existingSha });
  } catch (err: any) {
    console.error("[setup-workflow] Error:", err);
    const msg: string = err?.message ?? "Setup failed";
    // "Resource not accessible by integration" means the GitHub App is missing
    // contents:write permission. Return a structured error so the UI can show
    // a targeted fix link instead of a raw API dump.
    if (msg.includes("Resource not accessible by integration") || msg.includes("403")) {
      return NextResponse.json(
        {
          error: "GitHub App needs Contents (read & write) permission. Update the App permissions and re-accept the install.",
          needs_permission_fix: true,
        },
        { status: 403 }
      );
    }
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
