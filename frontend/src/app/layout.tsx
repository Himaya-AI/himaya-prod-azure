import type { Metadata } from "next";
import "./globals.css";
import { Toaster } from "@/components/ui/Toast";
import { ThemeProvider } from "@/contexts/ThemeContext";

export const metadata: Metadata = {
  title: "Himaya - AI-Driven Workspace Security",
  description:
    "AI-driven workspace security for the modern enterprise. Email threat protection, DLP, SaaS security posture, and data governance — powered by Himaya.",
  keywords: [
    "workspace security",
    "AI security",
    "email security",
    "DLP",
    "SaaS security",
    "data governance",
    "threat protection",
    "Himaya",
  ],
  metadataBase: new URL("https://app.himaya.ai"),
  openGraph: {
    title: "Himaya - AI-Driven Workspace Security",
    description:
      "AI-driven workspace security for the modern enterprise. Email threat protection, DLP, SaaS security posture, and data governance.",
    url: "https://app.himaya.ai",
    siteName: "Himaya",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Himaya - AI-Driven Workspace Security",
    description:
      "AI-driven workspace security for the modern enterprise. Email threat protection, DLP, SaaS security posture, and data governance.",
  },
  icons: {
    icon: "/favicon.ico",
    apple: "/favicon.png",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" dir="ltr">
      <head>
        {/* Apply per-user theme before first paint — no flash, no FOUC */}
        <script dangerouslySetInnerHTML={{ __html: `
          try {
            var u = localStorage.getItem('sentinel_user');
            var uid = u ? JSON.parse(u).id : null;
            var key = uid ? 'helios-theme-' + uid : 'helios-theme';
            var t = localStorage.getItem(key) || localStorage.getItem('helios-theme') || 'dark';
            document.documentElement.setAttribute('data-theme', t);
          } catch(e) {
            document.documentElement.setAttribute('data-theme', 'dark');
          }
        `}} />
      </head>
      <body className="bg-[#0c0c0e] text-[#e8eaf0] antialiased">
        <ThemeProvider>
          {children}
        </ThemeProvider>
        <Toaster />
      </body>
    </html>
  );
}
