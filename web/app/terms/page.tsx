import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Terms of Service — AegisDiff",
};

const EFFECTIVE_DATE = "March 27, 2026";

export default function TermsPage() {
  return (
    <div className="max-w-3xl mx-auto py-8 space-y-8 text-gray-800 dark:text-gray-200">
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-50">Terms of Service</h1>
        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">Effective date: {EFFECTIVE_DATE}</p>
      </div>

      <Section title="1. Acceptance">
        <p>
          By signing in to AegisDiff ("the Service") you agree to these Terms of Service ("Terms").
          If you do not agree, do not use the Service. These Terms form a binding agreement between
          you and the operator of AegisDiff ("we", "us", "our").
        </p>
      </Section>

      <Section title="2. Description of Service">
        <p>
          AegisDiff is an application security triage platform that analyzes GitHub pull request
          diffs for security vulnerabilities and surfaces findings in a dashboard. The Service
          operates on a <strong>zero code egress</strong> model — your source code is never
          transmitted to or stored on AegisDiff servers. Only scan metadata (verdict, severity,
          CWE ID, confidence score, and commit SHA) is stored.
        </p>
      </Section>

      <Section title="3. Account and Access">
        <ul className="list-disc pl-5 space-y-1">
          <li>You must have a valid GitHub account to use the Service.</li>
          <li>You are responsible for all activity under your account.</li>
          <li>You must not share credentials or allow unauthorized access to your account.</li>
          <li>We reserve the right to suspend or terminate accounts that violate these Terms.</li>
        </ul>
      </Section>

      <Section title="4. Acceptable Use">
        <p>You agree not to:</p>
        <ul className="list-disc pl-5 space-y-1 mt-2">
          <li>Use the Service to scan repositories you do not own or have authorization to scan.</li>
          <li>Attempt to reverse-engineer, scrape, or extract data beyond normal use.</li>
          <li>Abuse rate limits or attempt to bypass them programmatically.</li>
          <li>Use the Service in any way that violates applicable laws or regulations.</li>
          <li>Submit scan data that contains personal data of third parties without consent.</li>
        </ul>
      </Section>

      <Section title="5. Data and Privacy">
        <p>
          Your use of the Service is also governed by our{" "}
          <a href="/privacy" className="text-brand-blue hover:underline">Privacy Policy</a>,
          which is incorporated into these Terms. Key points:
        </p>
        <ul className="list-disc pl-5 space-y-1 mt-2">
          <li>Source code is never stored — only scan metadata.</li>
          <li>Scan records are automatically deleted after your configured retention period (default 90 days).</li>
          <li>You can delete your account and all associated data at any time from Settings.</li>
        </ul>
      </Section>

      <Section title="6. Free Tier and Rate Limits">
        <p>
          The Service is currently provided free of charge subject to a default limit of 100 scans
          per repository per day. We reserve the right to adjust limits at any time with reasonable
          notice. We may introduce paid tiers in the future; existing free-tier functionality will
          remain available at reasonable limits.
        </p>
      </Section>

      <Section title="7. Intellectual Property">
        <p>
          The AegisDiff platform, including its code, design, and trademarks, remains the property
          of the operator. Your scan metadata remains yours — we do not claim ownership over it.
          The open-source components of the engine are licensed under their respective licenses
          (see the{" "}
          <a
            href="https://github.com/KidCarmi/AegisDiff"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-blue hover:underline"
          >
            GitHub repository
          </a>).
        </p>
      </Section>

      <Section title="8. Disclaimer of Warranties">
        <p>
          THE SERVICE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. WE DO NOT WARRANT THAT
          THE SERVICE WILL BE ERROR-FREE, UNINTERRUPTED, OR THAT IT WILL DETECT ALL SECURITY
          VULNERABILITIES. SECURITY SCANNING IS PROBABILISTIC — YOU SHOULD NOT RELY SOLELY ON
          AEGISDIFF FOR SECURITY ASSURANCE.
        </p>
      </Section>

      <Section title="9. Limitation of Liability">
        <p>
          TO THE MAXIMUM EXTENT PERMITTED BY LAW, WE SHALL NOT BE LIABLE FOR ANY INDIRECT,
          INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES ARISING FROM YOUR USE OF THE SERVICE,
          INCLUDING ANY SECURITY BREACH THAT AEGISDIFF FAILED TO DETECT. OUR TOTAL LIABILITY
          SHALL NOT EXCEED THE AMOUNT YOU PAID US IN THE TWELVE MONTHS PRECEDING THE CLAIM
          (WHICH, FOR FREE TIER USERS, IS ZERO).
        </p>
      </Section>

      <Section title="10. Changes to Terms">
        <p>
          We may update these Terms from time to time. We will notify you of material changes by
          posting a notice in the dashboard or by email if you have one on file. Continued use
          after changes constitutes acceptance.
        </p>
      </Section>

      <Section title="11. Governing Law">
        <p>
          These Terms are governed by the laws of the State of Israel, without regard to
          conflict of law principles. Any disputes shall be resolved in the courts of Tel Aviv,
          Israel.
        </p>
      </Section>

      <Section title="12. Contact">
        <p>
          Questions about these Terms? Open an issue on our{" "}
          <a
            href="https://github.com/KidCarmi/AegisDiff/issues"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-blue hover:underline"
          >
            GitHub repository
          </a>.
        </p>
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-2">
      <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-50">{title}</h2>
      <div className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed space-y-2">
        {children}
      </div>
    </section>
  );
}
