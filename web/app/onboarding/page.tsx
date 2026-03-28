import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import { cookies } from "next/headers";
import { authOptions } from "../../lib/auth";
import { OnboardingWizard } from "./OnboardingWizard";

export default async function OnboardingPage() {
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");

  // Already completed onboarding → go straight to dashboard
  if (cookies().get("aegisdiff_onboarded")) redirect("/dashboard");

  const username =
    (session.user as any).username as string ?? session.user?.name ?? "";
  const appSlug = process.env.NEXT_PUBLIC_GITHUB_APP_SLUG ?? "aegisdiff";

  return (
    <OnboardingWizard
      username={username}
      appSlug={appSlug}
    />
  );
}
