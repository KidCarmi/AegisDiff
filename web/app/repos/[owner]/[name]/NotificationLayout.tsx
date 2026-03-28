"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

interface Props {
  owner: string;
  name: string;
  children: React.ReactNode;
}

const TABS = [
  { label: "Slack",     href: (o: string, n: string) => `/repos/${o}/${n}/slack` },
  { label: "Discord",   href: (o: string, n: string) => `/repos/${o}/${n}/discord` },
  { label: "Teams",     href: (o: string, n: string) => `/repos/${o}/${n}/teams` },
  { label: "Thresholds", href: (o: string, n: string) => `/repos/${o}/${n}/notify` },
];

export function NotificationLayout({ owner, name, children }: Props) {
  const pathname = usePathname();

  return (
    <div className="max-w-2xl">
      {/* Back link */}
      <div className="mb-5">
        <Link
          href={`/repos/${owner}/${name}/settings`}
          className="text-sm text-blue-600 hover:underline dark:text-blue-400"
        >
          ← Settings
        </Link>
      </div>

      {/* Header */}
      <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-50 mb-0.5">
        Notifications
      </h1>
      <p className="text-sm text-gray-500 dark:text-gray-400 font-mono mb-5">
        {owner}/{name}
      </p>

      {/* Channel tabs */}
      <div className="flex gap-1 border-b border-gray-200 dark:border-gray-700 mb-6">
        {TABS.map((tab) => {
          const href = tab.href(owner, name);
          const active = pathname === href;
          return (
            <Link
              key={tab.label}
              href={href}
              className={[
                "px-4 py-2 text-sm font-medium rounded-t-md border-b-2 -mb-px transition-colors",
                active
                  ? "border-blue-600 text-blue-600 dark:border-blue-400 dark:text-blue-400"
                  : "border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200",
              ].join(" ")}
            >
              {tab.label}
            </Link>
          );
        })}
      </div>

      {/* Page content */}
      {children}
    </div>
  );
}
