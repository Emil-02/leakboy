import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "leakboy – find the leaks in your vibe-coded app",
  description:
    "Paste a URL, get a 0–100 security score: open Supabase RLS, open Firebase rules, secrets in JS bundles and source maps, exposed .env and .git. Passive and read-only.",
  openGraph: {
    title: "leakboy 🤠 – find the leaks in your vibe-coded app",
    description: "Open Supabase RLS, Firebase rules, leaked API keys, public source maps. One URL, one score.",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
