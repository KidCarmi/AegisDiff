import { getServerSession } from "next-auth/next";
import { redirect, notFound } from "next/navigation";
import { authOptions, verifyRepoAccess } from "../../../../../lib/auth";
import { RepoSettingsTabs } from "./RepoSettingsTabs";

interface Props {
  params: Promise<{ owner: string; name: string }>;
}

export default async function RepoSettingsPage({ params }: Props) {
  const { owner, name } = await params;
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");

  const accessToken = (session.user as any).accessToken as string;
  const ok = await verifyRepoAccess(accessToken, owner, name);
  if (!ok) notFound();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <a
          href={`/repos/${owner}/${name}`}
          className="text-sm text-blue-600 hover:underline dark:text-blue-400"
        >
          ← {owner}/{name}
        </a>
        <h1 className="mt-1 text-2xl font-bold text-gray-900 dark:text-gray-50">
          Settings
        </h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5 font-mono">
          {owner}/{name}
        </p>
      </div>

      <RepoSettingsTabs owner={owner} name={name} />
    </div>
  );
}
