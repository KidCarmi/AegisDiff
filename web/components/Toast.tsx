"use client";

import { useEffect, useState } from "react";

interface ToastProps {
  message: string;
  type?: "success" | "error" | "info";
  duration?: number;
  onDismiss?: () => void;
}

export function Toast({ message, type = "success", duration = 3500, onDismiss }: ToastProps) {
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    const t = setTimeout(() => {
      setVisible(false);
      onDismiss?.();
    }, duration);
    return () => clearTimeout(t);
  }, [duration, onDismiss]);

  if (!visible) return null;

  const styles = {
    success: "bg-green-700 border-green-600",
    error: "bg-red-700 border-red-600",
    info: "bg-gray-800 border-gray-700",
  }[type];

  const icon = { success: "✓", error: "✕", info: "ℹ" }[type];

  return (
    <div
      className={`fixed bottom-5 right-5 z-50 flex items-center gap-2.5 rounded-xl border px-4 py-3 text-sm font-medium text-white shadow-lg animate-fade-in ${styles}`}
    >
      <span className="font-bold">{icon}</span>
      <span>{message}</span>
      <button
        onClick={() => { setVisible(false); onDismiss?.(); }}
        className="ml-1 opacity-60 hover:opacity-100 transition-opacity"
        aria-label="Dismiss"
      >
        ×
      </button>
    </div>
  );
}
