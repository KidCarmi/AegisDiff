import { getServerSession } from "next-auth/next";
import { redirect, notFound } from "next/navigation";
import { authOptions, verifyRepoAccess } from "../../../../../lib/auth";
import { NotifyForm } from "./NotifyForm";

interface Props { params: { owner: string; name: string } }

export default async function NotifySettingsPage({ params }: Props) {
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");
  const ok = await verifyRepoAccess((session.user as any).accessToken, params.owner, params.name);
  if (!ok) notFound();

  return (
    <div className="max-w-xl">
      <a href={`/repos/${params.owner}/${params.name}`} className="text-sm text-blue-600 hover:underline">
        ← {params.owner}/{params.name}
      </a>
      <h1 className="text-xl font-bold text-gray-900 mt-4 mb-1">Notification Settings</h1>
      <p className="text-sm text-gray-500 mb-6 font-mono">{params.owner}/{params.name}</p>
      <NotifyForm owner={params.owner} name={params.name} />
    </div>
  );
}
