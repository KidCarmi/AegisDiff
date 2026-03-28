import { getServerSession } from "next-auth/next";
import { redirect, notFound } from "next/navigation";
import { authOptions, verifyRepoAccess } from "../../../../../lib/auth";
import { NotificationLayout } from "../NotificationLayout";
import { NotifyForm } from "./NotifyForm";

interface Props { params: { owner: string; name: string } }

export default async function NotifySettingsPage({ params }: Props) {
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");
  const ok = await verifyRepoAccess((session.user as any).accessToken, params.owner, params.name);
  if (!ok) notFound();

  return (
    <NotificationLayout owner={params.owner} name={params.name}>
      <NotifyForm owner={params.owner} name={params.name} />
    </NotificationLayout>
  );
}
