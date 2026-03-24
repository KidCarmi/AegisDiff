import type { Metadata } from "next";
import "./globals.css";
import { NavBar } from "../components/NavBar";

export const metadata: Metadata = {
  title: "AegisDiff — AppSec Triage",
  description: "Zero-cost autonomous security triage for your pull requests",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-gray-50 font-sans antialiased">
        <NavBar />
        <main className="mx-auto max-w-5xl px-6 py-8">{children}</main>
      </body>
    </html>
  );
}
