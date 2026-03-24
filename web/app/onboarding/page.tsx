import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import { authOptions } from "../../lib/auth";
import { OnboardingWizard } from "./OnboardingWizard";

export default async function OnboardingPage() {
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");

  const username =
    (session.user as any).username as string ?? session.user?.name ?? "";
  const ingestUrl = `${process.env.NEXTAUTH_URL ?? ""}/api/ingest`;
  const appSlug = process.env.NEXT_PUBLIC_GITHUB_APP_SLUG ?? "aegisdiff";

  return (
    <OnboardingWizard
      username={username}
      ingestUrl={ingestUrl}
      appSlug={appSlug}
    />
  );
}
