import type { NextConfig } from "next";

// Default build (Vercel, `next start`): standard Next.js output.
// Static build (S3, GitHub Pages, any file host): set STATIC_EXPORT=1 to write plain files to out/.
const isStatic = process.env.STATIC_EXPORT === "1";

const nextConfig: NextConfig = {
  ...(isStatic ? { output: "export", trailingSlash: true } : {}),
};

export default nextConfig;
