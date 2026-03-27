"use client";

import { useState } from "react";
import { signOut } from "next-auth/react";

export function DeleteAccountButton() {
  const [step, setStep] = useState<"idle" | "confirm" | "deleting">("idle");
  const [error, setError] = useState<string | null>(null);

  async function handleDelete() {
    setStep("deleting");
    setError(null);
    try {
      const res = await fetch("/api/user/delete", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirm: "delete my account" }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error ?? "Failed to delete account");
      }
      // Sign out and redirect to landing/home
      await signOut({ callbackUrl: "/" });
    } catch (err: any) {
      setError(err.message);
      setStep("confirm");
    }
  }

  if (step === "idle") {
    return (
      <button
        onClick={() => setStep("confirm")}
        className="rounded-lg border border-red-300 dark:border-red-800 px-4 py-2 text-sm font-medium text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950 transition-colors"
      >
        Delete my account
      </button>
    );
  }

  return (
    <div className="rounded-lg border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-950/40 p-4 space-y-3">
      <p className="text-sm font-semibold text-red-700 dark:text-red-400">
        This will permanently delete:
      </p>
      <ul className="text-sm text-red-600 dark:text-red-300 list-disc pl-5 space-y-0.5">
        <li>Your account and profile</li>
        <li>All connected repos and their scan history</li>
        <li>All feedback, ignore rules, and API keys</li>
      </ul>
      <p className="text-sm text-red-700 dark:text-red-400 font-medium">
        This action is irreversible.
      </p>
      {error && (
        <p className="text-xs text-red-600 dark:text-red-400 bg-red-100 dark:bg-red-900/40 rounded px-3 py-2">
          {error}
        </p>
      )}
      <div className="flex gap-2">
        <button
          onClick={handleDelete}
          disabled={step === "deleting"}
          className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50 transition-colors"
        >
          {step === "deleting" ? "Deleting…" : "Yes, delete everything"}
        </button>
        <button
          onClick={() => { setStep("idle"); setError(null); }}
          disabled={step === "deleting"}
          className="rounded-lg border border-gray-300 dark:border-gray-600 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-50 transition-colors"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
