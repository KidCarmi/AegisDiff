import type { Metadata } from "next";
import "./globals.css";
import { NavBar } from "../components/NavBar";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../lib/auth";
import { isPlatformAdminSession } from "../lib/rbac";

export const metadata: Metadata = {
  title: "AegisDiff — AppSec Triage",
  description: "Zero-cost autonomous security triage for your pull requests",
  icons: {
    icon: [
      { url: "/favicon.png", type: "image/png" },
    ],
    apple: "/icon-192.png",
  },
  openGraph: {
    title: "AegisDiff — AppSec Triage",
    description: "Zero-cost autonomous security triage for your pull requests",
    images: [{ url: "/og-image.png", width: 1200, height: 630 }],
  },
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await getServerSession(authOptions);
  const isAdmin = !!session && isPlatformAdminSession(session);

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{__html: `(function(){try{var t=localStorage.getItem('aegisdiff-theme');if(t==='dark'||(t===null&&window.matchMedia('(prefers-color-scheme: dark)').matches)){document.documentElement.classList.add('dark')}}catch(e){}})();`}} />
      </head>
      <body className="min-h-screen bg-gray-50 dark:bg-gray-950 font-sans antialiased">
        <NavBar isAdmin={isAdmin} />
        <main className="mx-auto max-w-5xl px-6 py-8">{children}</main>
        <footer className="mt-16 border-t border-gray-200 dark:border-gray-800 py-6">
          <div className="mx-auto max-w-5xl px-6 flex flex-wrap items-center justify-between gap-3">
            <span className="text-xs text-gray-400 dark:text-gray-500">
              © {new Date().getFullYear()} AegisDiff — Zero code egress
            </span>
            <div className="flex items-center gap-4 text-xs text-gray-400 dark:text-gray-500">
              <a href="/pricing" className="hover:text-brand-blue hover:underline transition-colors">Pricing</a>
              <a href="/privacy" className="hover:text-brand-blue hover:underline transition-colors">Privacy</a>
              <a href="/terms" className="hover:text-brand-blue hover:underline transition-colors">Terms</a>
              <a href="https://github.com/KidCarmi/AegisDiff" target="_blank" rel="noopener noreferrer" className="hover:text-brand-blue hover:underline transition-colors">GitHub</a>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
