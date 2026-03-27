import type { Metadata } from "next";
import "./globals.css";
import { NavBar } from "../components/NavBar";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../lib/auth";
import { isPlatformAdminSession } from "../lib/rbac";

export const metadata: Metadata = {
  title: "AegisDiff — AppSec Triage",
  description: "Zero-cost autonomous security triage for your pull requests",
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
      </body>
    </html>
  );
}
