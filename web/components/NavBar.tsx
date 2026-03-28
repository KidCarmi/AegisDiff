"use client";

import { usePathname } from "next/navigation";
import { signOut } from "next-auth/react";
import { useEffect, useState } from "react";
import Image from "next/image";
import icon from "../public/icon-192.png";

const NAV_LINKS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/repos", label: "Repos" },
  { href: "/pricing", label: "Pricing" },
  { href: "/settings", label: "Settings" },
];

const ADMIN_LINK = { href: "/admin", label: "Admin" };

const STALE_MS = 5 * 60 * 1000;
const LS_KEY = "aegisdiff_dashboard_ts";

function ThemeToggle() {
  const [dark, setDark] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    setDark(document.documentElement.classList.contains("dark"));

    function onStorage(e: StorageEvent) {
      if (e.key !== "aegisdiff-theme") return;
      const next = e.newValue === "dark";
      setDark(next);
      document.documentElement.classList.toggle("dark", next);
    }
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  function toggle() {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    localStorage.setItem("aegisdiff-theme", next ? "dark" : "light");
  }

  // Render a same-size placeholder until mounted to avoid hydration mismatch.
  // Server always renders dark=false; client may differ based on localStorage.
  if (!mounted) {
    return <span className="ml-1 inline-block h-7 w-7" aria-hidden />;
  }

  return (
    <button
      onClick={toggle}
      className="ml-1 rounded-md p-1.5 text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
      aria-label="Toggle dark mode"
    >
      {dark ? (
        <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707M17.657 17.657l-.707-.707M6.343 6.343l-.707-.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
        </svg>
      ) : (
        <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
        </svg>
      )}
    </button>
  );
}

function SignOutButton() {
  const [signingOut, setSigningOut] = useState(false);
  return (
    <button
      onClick={() => { setSigningOut(true); signOut({ callbackUrl: "/login" }); }}
      disabled={signingOut}
      className="ml-2 rounded-md border border-gray-200 dark:border-gray-700 px-3 py-1.5 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-50 transition-colors"
    >
      {signingOut ? "Signing out…" : "Sign out"}
    </button>
  );
}

export function NavBar({ isAdmin = false }: { isAdmin?: boolean }) {
  const path = usePathname();
  if (path === "/login") return null;
  const [maybeNewScans, setMaybeNewScans] = useState(false);

  useEffect(() => {
    if (path === "/dashboard") {
      localStorage.setItem(LS_KEY, String(Date.now()));
      setMaybeNewScans(false);
    } else {
      const last = parseInt(localStorage.getItem(LS_KEY) ?? "0", 10);
      setMaybeNewScans(last > 0 && Date.now() - last > STALE_MS);
    }
  }, [path]);

  function isActive(href: string) {
    if (href === "/dashboard") return path === "/dashboard";
    return path.startsWith(href);
  }

  return (
    <nav className="sticky top-0 z-50 border-b border-gray-200 dark:border-gray-800 bg-white/95 dark:bg-gray-950/95 backdrop-blur-sm px-6 py-3">
      <div className="mx-auto max-w-5xl flex items-center justify-between">
        {/* Logo */}
        <a
          href="/dashboard"
          className="flex items-center gap-2 font-bold hover:opacity-80 transition-opacity"
        >
          <Image src={icon} alt="" width={28} height={28} className="rounded-md ring-1 ring-brand-blue/40" priority />
          <span className="text-xl text-brand-blue">AegisDiff</span>
        </a>

        {/* Nav links */}
        <div className="flex items-center gap-1 text-sm">
          {NAV_LINKS.map(({ href, label }) => (
            <a
              key={href}
              href={href}
              className={`relative rounded-md px-3 py-1.5 font-medium transition-colors ${
                isActive(href)
                  ? "bg-brand-blue text-white"
                  : "text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800"
              }`}
            >
              {label}
              {href === "/dashboard" && maybeNewScans && (
                <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-brand-blue animate-pulse" />
              )}
            </a>
          ))}

          {isAdmin && (
            <a
              href={ADMIN_LINK.href}
              className={`relative rounded-md px-3 py-1.5 font-medium transition-colors ${
                isActive(ADMIN_LINK.href)
                  ? "bg-brand-blue text-white"
                  : "text-brand-blue hover:bg-brand-blue/10 dark:hover:bg-brand-blue/10"
              }`}
            >
              {ADMIN_LINK.label}
            </a>
          )}

          <ThemeToggle />

          <SignOutButton />
        </div>
      </div>
    </nav>
  );
}
