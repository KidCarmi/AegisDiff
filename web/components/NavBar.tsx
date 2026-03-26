"use client";

import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

const NAV_LINKS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/repos", label: "Repos" },
  { href: "/settings", label: "Settings" },
];

/** QW4 — pulsing dot on Dashboard link when user hasn't checked in >5 min */
const STALE_MS = 5 * 60 * 1000;
const LS_KEY = "aegisdiff_dashboard_ts";

function ThemeToggle() {
  const [dark, setDark] = useState(false);

  useEffect(() => {
    setDark(document.documentElement.classList.contains("dark"));
  }, []);

  function toggle() {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    localStorage.setItem("aegisdiff-theme", next ? "dark" : "light");
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

export function NavBar() {
  const path = usePathname();
  const [maybeNewScans, setMaybeNewScans] = useState(false);

  useEffect(() => {
    if (path === "/dashboard") {
      // Visiting dashboard — record timestamp, clear badge
      localStorage.setItem(LS_KEY, String(Date.now()));
      setMaybeNewScans(false);
    } else {
      // On another page — show badge if dashboard hasn't been checked recently
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
        <a
          href="/dashboard"
          className="flex items-center gap-2 text-xl font-bold text-gray-900 dark:text-gray-50 hover:opacity-80 transition-opacity"
        >
          🛡️ <span>AegisDiff</span>
        </a>
        <div className="flex items-center gap-1 text-sm">
          {NAV_LINKS.map(({ href, label }) => (
            <a
              key={href}
              href={href}
              className={`relative rounded-md px-3 py-1.5 font-medium transition-colors ${
                isActive(href)
                  ? "bg-gray-900 dark:bg-gray-100 text-white dark:text-gray-900"
                  : "text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800"
              }`}
            >
              {label}
              {/* QW4 — "maybe new scans" indicator */}
              {href === "/dashboard" && maybeNewScans && (
                <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-blue-500 animate-pulse" />
              )}
            </a>
          ))}
          <ThemeToggle />
          <a
            href="/api/auth/signout"
            className="ml-2 rounded-md border border-gray-200 dark:border-gray-700 px-3 py-1.5 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
          >
            Sign out
          </a>
        </div>
      </div>
    </nav>
  );
}
