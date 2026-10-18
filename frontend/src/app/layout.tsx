import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentinelSOC — Agentic Threat Investigation",
  description:
    "Agentic AI cybersecurity assistant: ingests security logs, correlates "
    + "signals into incidents, explains the evidence and recommends response.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-bg text-ink">{children}</body>
    </html>
  );
}
