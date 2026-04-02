import { getServerSession } from "next-auth/next";
import { redirect, notFound } from "next/navigation";
import { authOptions, verifyRepoAccess } from "../../../../../lib/auth";
import { NotificationLayout } from "../NotificationLayout";
import { NotifyForm } from "./NotifyForm";

interface Props { params: Promise<{ owner: string; name: string }> }

export default async function NotifySettingsPage({ params }: Props) {
  const { owner, name } = await params;
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");
  const ok = await verifyRepoAccess((session.user as any).accessToken, owner, name);
  if (!ok) notFound();

  return (
    <NotificationLayout owner={owner} name={name}>
      <NotifyForm owner={owner} name={name} />
    </NotificationLayout>
  );
}
