import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || "https://app.himaya.ai",
  },
  async headers() {
    return [
      {
        // Outlook add-in taskpane — must allow connect-src to our own API
        // and frame-ancestors for Microsoft Office hosts (OWA, new Outlook, desktop)
        source: "/addons/outlook/:path*",
        headers: [
          { key: "Cache-Control", value: "no-store, must-revalidate" },
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self' https://app.himaya.ai",
              "script-src 'self' 'unsafe-inline' https://appsforoffice.microsoft.com https://ajax.aspnetcdn.com",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' https://app.himaya.ai data:",
              "connect-src 'self' https://app.himaya.ai https://appsforoffice.microsoft.com",
              "frame-ancestors https://outlook.office.com https://outlook.office365.com https://*.office.com https://*.office365.com https://*.microsoft.com https://localhost:*",
            ].join("; "),
          },
          { key: "X-Frame-Options", value: "ALLOWALL" },
        ],
      },
      {
        // Never cache HTML pages — forces browser to always fetch fresh HTML
        // so new JS/CSS chunk hashes are always picked up after deploys
        source: "/((?!_next/static|_next/image|favicon).*)",
        headers: [
          { key: "Cache-Control", value: "no-store, must-revalidate" },
          { key: "Pragma", value: "no-cache" },
        ],
      },
      {
        // Static assets (JS/CSS) are content-hashed — cache them aggressively
        source: "/_next/static/:path*",
        headers: [
          { key: "Cache-Control", value: "public, max-age=31536000, immutable" },
        ],
      },
    ];
  },
};

export default nextConfig;
