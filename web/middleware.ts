/**
 * Next.js Edge Middleware — session protection + admin route guard.
 *
 * Runs on the edge (no Node.js APIs). Uses next-auth getToken() to read
 * the JWT without a full DB round-trip.
 *
 * Rules:
 *   /login, /api/auth/**  → always public
 *   /api/llm-token        → public (OIDC-authenticated by the route itself)
 *   /api/ingest           → public (OIDC-authenticated by the route itself)
 *   /api/webhooks/**      → public (HMAC-SHA256-authenticated by the route itself)
 *   /api/badge/**         → public (SVG badges, no auth)
 *   /api/cron/**          → public (CRON_SECRET-authenticated by the route itself)
 *   /api/v1/**            → public (Bearer ak_ key authenticated by the route)
 *   /admin/**             → requires platform:admin (githubId in PLATFORM_ADMIN_GITHUB_IDS)
 *   /api/admin/**         → requires platform:admin
 *   everything else       → requires valid session (redirect to /login)
 */
import { NextRequest, NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";

// Routes that are fully public — no session check
const PUBLIC_PREFIXES = [
  "/login",
  "/api/auth",
  "/api/ingest",
  "/api/llm-token",
  "/api/v1",
  "/api/webhooks",   // GitHub App webhooks — HMAC-authenticated by the route itself
  "/api/badge",      // public SVG badges
  "/api/cron",       // Vercel cron — authenticated by CRON_SECRET in the route
  "/_next",
  "/favicon",
];

function isPlatformAdmin(githubId: number): boolean {
  const ids = (process.env.PLATFORM_ADMIN_GITHUB_IDS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map(Number);
  return ids.includes(githubId);
}

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Always allow public routes
  if (PUBLIC_PREFIXES.some((p) => pathname.startsWith(p))) {
    return NextResponse.next();
  }

  // Read JWT (works on edge — no DB call)
  const token = await getToken({
    req,
    secret: process.env.NEXTAUTH_SECRET,
  });

  // No session → redirect to login (for pages) or 401 (for API)
  if (!token) {
    if (pathname.startsWith("/api/")) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    const loginUrl = new URL("/login", req.url);
    loginUrl.searchParams.set("callbackUrl", req.url);
    return NextResponse.redirect(loginUrl);
  }

  // Admin routes — require platform:admin role
  if (pathname.startsWith("/admin") || pathname.startsWith("/api/admin")) {
    const githubId = token.githubId as number | undefined;
    if (!githubId || !isPlatformAdmin(githubId)) {
      if (pathname.startsWith("/api/")) {
        return NextResponse.json(
          { error: "Platform admin access required" },
          { status: 403 }
        );
      }
      // Redirect non-admins to dashboard with a message
      return NextResponse.redirect(new URL("/dashboard?error=forbidden", req.url));
    }
  }

  return NextResponse.next();
}

export const config = {
  // Run on all routes except static files and Next.js internals
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
