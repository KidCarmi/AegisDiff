"use client";

import { usePathname } from "next/navigation";

const NAV_LINKS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/repos", label: "Repos" },
  { href: "/settings", label: "Settings" },
];

export function NavBar() {
  const path = usePathname();

  function isActive(href: string) {
    if (href === "/dashboard") return path === "/dashboard";
    return path.startsWith(href);
  }

  return (
    <nav className="sticky top-0 z-50 border-b border-gray-200 bg-white/95 backdrop-blur-sm px-6 py-3">
      <div className="mx-auto max-w-5xl flex items-center justify-between">
        <a
          href="/dashboard"
          className="flex items-center gap-2 text-xl font-bold text-gray-900 hover:opacity-80 transition-opacity"
        >
          🛡️ <span>AegisDiff</span>
        </a>
        <div className="flex items-center gap-1 text-sm">
          {NAV_LINKS.map(({ href, label }) => (
            <a
              key={href}
              href={href}
              className={`rounded-md px-3 py-1.5 font-medium transition-colors ${
                isActive(href)
                  ? "bg-gray-900 text-white"
                  : "text-gray-600 hover:text-gray-900 hover:bg-gray-100"
              }`}
            >
              {label}
            </a>
          ))}
          <a
            href="/api/auth/signout"
            className="ml-3 rounded-md border border-gray-200 px-3 py-1.5 text-gray-600 hover:bg-gray-50 transition-colors"
          >
            Sign out
          </a>
        </div>
      </div>
    </nav>
  );
}
