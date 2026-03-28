"use client";

interface Props {
  owner: string;
  name: string;
  appInstalled: boolean;
  appSlug: string;
}

export function RepoSetup({ owner, name, appInstalled, appSlug }: Props) {
  if (appInstalled) {
    return (
      <div className="mt-2 border-t border-gray-100 dark:border-gray-800 pt-2">
        <p className="text-xs text-green-600 dark:text-green-400 flex items-center gap-1.5">
          <span>✓</span>
          <span>Scanning PRs automatically via GitHub App</span>
        </p>
      </div>
    );
  }

  return (
    <div className="mt-2 border-t border-gray-100 dark:border-gray-800 pt-2">
      <a
        href={`https://github.com/apps/${appSlug}/installations/new`}
        target="_blank"
        rel="noopener noreferrer"
        className="text-xs text-blue-600 hover:underline"
      >
        Install GitHub App to enable scanning on {owner}/{name} ↗
      </a>
    </div>
  );
}
