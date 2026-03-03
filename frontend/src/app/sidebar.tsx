"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const nav = [
  { href: "/sessions", icon: "📡", label: "Sessions" },
  { href: "/stats", icon: "📊", label: "Stats" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 h-full w-56 bg-card border-r border-border flex flex-col z-10">
      <div className="p-5 border-b border-border">
        <Link
          href="/sessions"
          className="text-xl font-bold text-white tracking-tight"
        >
          wiretaps{" "}
          <span className="text-lg">🔌</span>
        </Link>
      </div>

      <nav className="flex-1 p-3 space-y-1">
        {nav.map((item) => {
          const active = pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors ${
                active
                  ? "bg-accent/10 text-accent"
                  : "text-neutral-400 hover:text-white hover:bg-white/5"
              }`}
            >
              <span>{item.icon}</span>
              <span className="text-sm font-medium">{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="p-4 border-t border-border text-xs text-neutral-500">
        v2.0.0
      </div>
    </aside>
  );
}
