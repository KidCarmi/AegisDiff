import { getServerSession } from "next-auth/next";
import { redirect, notFound } from "next/navigation";
import { authOptions, verifyRepoAccess } from "../../../../../lib/auth";
import { SlackForm } from "./SlackForm";

interface Props {
  params: { owner: string; name: string };
}

export default async function SlackSettingsPage({ params }: Props) {
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");

  const accessToken = (session.user as any).accessToken as string;
  const ok = await verifyRepoAccess(accessToken, params.owner, params.name);
  if (!ok) notFound();

  return (
    <div className="max-w-xl">
      <div className="mb-6">
        <a href="/settings" className="text-sm text-blue-600 hover:underline">
          ← Settings
        </a>
      </div>
      <h1 className="text-xl font-bold text-gray-900 mb-1">Slack Notifications</h1>
      <p className="text-sm text-gray-500 mb-6 font-mono">
        {params.owner}/{params.name}
      </p>
      <SlackForm owner={params.owner} name={params.name} />
    </div>
  );
}
