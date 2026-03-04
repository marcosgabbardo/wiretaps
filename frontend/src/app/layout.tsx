import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "./sidebar";

export const metadata: Metadata = {
  title: "wiretaps",
  description: "Agent observability platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-bg text-neutral-200 antialiased">
        <Sidebar />
        {/* Desktop: offset pela sidebar | Mobile: offset pelo top bar */}
        <main className="md:ml-56 mt-12 md:mt-0 min-h-screen p-4 md:p-8">{children}</main>
      </body>
    </html>
  );
}
