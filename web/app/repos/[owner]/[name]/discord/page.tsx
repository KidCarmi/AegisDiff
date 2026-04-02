import { getServerSession } from "next-auth/next";
import { redirect, notFound } from "next/navigation";
import { authOptions, verifyRepoAccess } from "../../../../../lib/auth";
import { NotificationLayout } from "../NotificationLayout";
import { DiscordForm } from "./DiscordForm";

interface Props { params: Promise<{ owner: string; name: string }> }

export default async function DiscordSettingsPage({ params }: Props) {
  const { owner, name } = await params;
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");
  const ok = await verifyRepoAccess((session.user as any).accessToken, owner, name);
  if (!ok) notFound();

  return (
    <NotificationLayout owner={owner} name={name}>
      <DiscordForm owner={owner} name={name} />
    </NotificationLayout>
  );
}
