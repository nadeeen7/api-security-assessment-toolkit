import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";

export default function Layout() {
  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <Sidebar />
      <main className="min-w-0 flex-1 flex flex-col">
        {/* Thin authorized-testing banner */}
        <div className="flex items-center justify-center gap-2 border-b border-line bg-panel/80 px-4 py-2 text-center">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" className="text-accent-strong flex-shrink-0">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <span className="text-xs text-info">
            Authorized testing only — only assess systems you own or have explicit written permission to test
          </span>
        </div>
        <div className="mx-auto w-full max-w-6xl px-4 py-3 md:px-6 md:py-4 flex-1">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
