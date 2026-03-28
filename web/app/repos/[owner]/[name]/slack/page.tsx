import { getServerSession } from "next-auth/next";
import { redirect, notFound } from "next/navigation";
import { authOptions, verifyRepoAccess } from "../../../../../lib/auth";
import { NotificationLayout } from "../NotificationLayout";
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
    <NotificationLayout owner={params.owner} name={params.name}>
      <SlackForm owner={params.owner} name={params.name} />
    </NotificationLayout>
  );
}
