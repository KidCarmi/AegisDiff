/**
 * Email sending via Resend API (https://resend.com)
 * Uses the HTTP API directly — no SDK package needed.
 *
 * Required env var: RESEND_API_KEY
 * Optional env var: EMAIL_FROM (default: "AegisDiff <noreply@aegis-diff.app>")
 *
 * All functions are fire-and-forget safe — they catch and log errors internally
 * so a failed email never breaks the calling flow.
 */

const RESEND_API = "https://api.resend.com/emails";
// Default to Resend's shared sender — works with no domain setup.
// Set EMAIL_FROM in Vercel env once you have a custom domain.
const FROM = process.env.EMAIL_FROM ?? "AegisDiff <onboarding@resend.dev>";
const BASE_URL = (process.env.NEXTAUTH_URL ?? "https://aegis-diff.vercel.app").replace(/\/$/, "");

async function sendEmail(to: string, subject: string, html: string): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return; // Email not configured — silently skip

  try {
    const res = await fetch(RESEND_API, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ from: FROM, to, subject, html }),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      console.error(`[email] Resend error ${res.status}:`, body);
    }
  } catch (err) {
    console.error("[email] Failed to send:", err);
  }
}

/** Sent once when a new user signs in for the first time. */
export async function sendWelcomeEmail(to: string, username: string): Promise<void> {
  if (!to) return;
  const subject = "Welcome to AegisDiff 🛡️";
  const html = `
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#1f2937">
      <div style="background:#38bdf8;padding:24px 32px;border-radius:12px 12px 0 0">
        <h1 style="margin:0;font-size:22px;color:#fff;font-weight:700">🛡️ AegisDiff</h1>
      </div>
      <div style="background:#f9fafb;padding:32px;border-radius:0 0 12px 12px;border:1px solid #e5e7eb;border-top:none">
        <h2 style="margin:0 0 12px;font-size:18px">Hey ${username}, welcome aboard!</h2>
        <p style="margin:0 0 16px;color:#4b5563;line-height:1.6">
          AegisDiff is now scanning your pull requests for security vulnerabilities —
          automatically, with zero configuration required.
        </p>
        <h3 style="margin:0 0 8px;font-size:14px;color:#374151">What happens next:</h3>
        <ol style="margin:0 0 24px;padding-left:20px;color:#4b5563;line-height:1.8">
          <li>Connect your repos (if you haven't already)</li>
          <li>Open a pull request</li>
          <li>AegisDiff posts a security review in ~90 seconds</li>
          <li>Results appear in your dashboard</li>
        </ol>
        <a href="${BASE_URL}/dashboard"
           style="display:inline-block;background:#38bdf8;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px">
          Go to Dashboard →
        </a>
        <hr style="margin:32px 0;border:none;border-top:1px solid #e5e7eb" />
        <p style="margin:0;font-size:12px;color:#9ca3af">
          AegisDiff — Zero code egress. Source code never leaves GitHub.<br/>
          <a href="${BASE_URL}/privacy" style="color:#9ca3af">Privacy Policy</a> ·
          <a href="${BASE_URL}/terms" style="color:#9ca3af">Terms of Service</a> ·
          <a href="${BASE_URL}/settings" style="color:#9ca3af">Unsubscribe</a>
        </p>
      </div>
    </div>
  `;
  await sendEmail(to, subject, html);
}

/** Sent when a TRUE_POSITIVE scan is found and no webhook is configured. */
export async function sendScanAlertEmail(
  to: string,
  username: string,
  repoOwner: string,
  repoName: string,
  opts: {
    title: string | null;
    severity: string | null;
    cweId: string | null;
    prNumber: number | null;
    prUrl: string | null;
    confidence: number | null;
  }
): Promise<void> {
  if (!to) return;
  const repoSlug = `${repoOwner}/${repoName}`;
  const prLink = opts.prUrl
    ? `<a href="${opts.prUrl}" style="color:#38bdf8">PR #${opts.prNumber}</a>`
    : opts.prNumber ? `PR #${opts.prNumber}` : "a recent commit";
  const confidence = opts.confidence != null ? `${Math.round(opts.confidence * 100)}%` : "—";
  const dashUrl = `${BASE_URL}/repos/${repoOwner}/${repoName}`;

  const subject = `🚨 Security issue detected in ${repoSlug}`;
  const html = `
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#1f2937">
      <div style="background:#ef4444;padding:24px 32px;border-radius:12px 12px 0 0">
        <h1 style="margin:0;font-size:18px;color:#fff;font-weight:700">🚨 AegisDiff Security Alert</h1>
      </div>
      <div style="background:#f9fafb;padding:32px;border-radius:0 0 12px 12px;border:1px solid #e5e7eb;border-top:none">
        <p style="margin:0 0 16px;color:#4b5563">
          A <strong>TRUE POSITIVE</strong> security finding was detected in ${prLink} on
          <strong>${repoSlug}</strong>.
        </p>
        <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:24px">
          ${[
            ["Finding", opts.title ?? "Security vulnerability"],
            ["Severity", opts.severity ?? "N/A"],
            ["CWE", opts.cweId ?? "N/A"],
            ["Confidence", confidence],
          ].map(([k, v]) => `
            <tr>
              <td style="padding:8px 12px;background:#f3f4f6;font-weight:600;width:110px;border:1px solid #e5e7eb">${k}</td>
              <td style="padding:8px 12px;border:1px solid #e5e7eb">${v}</td>
            </tr>
          `).join("")}
        </table>
        <a href="${dashUrl}"
           style="display:inline-block;background:#38bdf8;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px">
          View in Dashboard →
        </a>
        <hr style="margin:32px 0;border:none;border-top:1px solid #e5e7eb" />
        <p style="margin:0;font-size:12px;color:#9ca3af">
          To stop receiving these emails, configure a Slack or Discord webhook in
          <a href="${BASE_URL}/settings" style="color:#9ca3af">Settings</a>
          and remove your email address from your GitHub account, or
          <a href="${BASE_URL}/settings" style="color:#9ca3af">delete your account</a>.
        </p>
      </div>
    </div>
  `;
  await sendEmail(to, subject, html);
}
