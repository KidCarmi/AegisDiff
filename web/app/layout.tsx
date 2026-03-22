import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AegisDiff — AppSec Triage",
  description: "Zero-cost autonomous security triage for your pull requests",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-gray-50 font-sans antialiased">
        <nav className="border-b border-gray-200 bg-white px-6 py-3">
          <div className="mx-auto max-w-5xl flex items-center justify-between">
            <a href="/dashboard" className="text-xl font-bold text-gray-900">
              🛡️ AegisDiff
            </a>
            <div className="flex items-center gap-4 text-sm">
              <a href="/dashboard" className="text-gray-600 hover:text-gray-900">
                Dashboard
              </a>
              <a href="/repos" className="text-gray-600 hover:text-gray-900">
                Repos
              </a>
              <a href="/settings" className="text-gray-600 hover:text-gray-900">
                Settings
              </a>
              <a
                href="/api/auth/signout"
                className="rounded-md bg-gray-100 px-3 py-1.5 text-gray-700 hover:bg-gray-200"
              >
                Sign out
              </a>
            </div>
          </div>
        </nav>
        <main className="mx-auto max-w-5xl px-6 py-8">{children}</main>
      </body>
    </html>
  );
}
