import { useState, useEffect } from "react";
import { NavLink, useNavigate, useLocation } from "react-router-dom";
import { api } from "../api/client";

function clearAssessmentDraft() {
  try {
    window.sessionStorage.removeItem("assessment-draft:v1");
  } catch {
    // ignore
  }
}

const NAV_ITEMS = [
  {
    to: "/",
    label: "New Assessment",
    end: true,
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 5v14M5 12h14" />
      </svg>
    ),
  },
  {
    to: "/history",
    label: "History",
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 8v4l3 3m6-3a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" />
      </svg>
    ),
  },
];

function NavItem({ item, onClick }) {
  return (
    <NavLink
      to={item.to}
      end={item.end}
      onClick={onClick}
      className={({ isActive }) =>
        [
          "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150",
          "border-l-2",
          isActive
            ? "border-accent-strong bg-surface text-accent"
            : "border-transparent text-slate-400 hover:bg-surface/60 hover:text-slate-200",
        ].join(" ")
      }
    >
      <span className={`shrink-0`}>{item.icon}</span>
      <span>{item.label}</span>
    </NavLink>
  );
}

export default function Sidebar() {
  const [health, setHealth] = useState(null);
  const [offline, setOffline] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    let active = true;
    api
      .health()
      .then((value) => {
        if (active) {
          setHealth(value);
          setOffline(false);
        }
      })
      .catch(() => {
        if (active) setOffline(true);
      });
    return () => {
      active = false;
    };
  }, []);

  const closeMobile = () => setMobileOpen(false);

  const handleNewAssessment = () => {
    clearAssessmentDraft();
    closeMobile();
  };

  return (
    <>
      {/* Mobile topbar */}
      <div className="flex md:hidden items-center justify-between bg-panel border-b border-line px-4 py-3">
        <div className="flex items-center gap-2.5">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent-dim border border-accent/20 text-sm" aria-hidden="true">
            🛡
          </span>
          <div className="leading-tight">
            <p className="text-sm font-semibold text-white">API Security</p>
            <p className="text-xs text-info">Assessment Toolkit</p>
          </div>
        </div>
        <button
          aria-label={mobileOpen ? "Close navigation" : "Open navigation"}
          className="btn btn-ghost px-2.5 py-2"
          onClick={() => setMobileOpen((v) => !v)}
        >
          {mobileOpen ? (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          ) : (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
              <path d="M3 12h18M3 6h18M3 18h18" />
            </svg>
          )}
        </button>
      </div>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 md:hidden"
          onClick={closeMobile}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <aside
        className={[
          "shrink-0 flex flex-col bg-panel border-line z-40",
          "fixed top-0 left-0 h-full w-64 border-r transition-transform duration-200 md:static md:translate-x-0 md:h-screen",
          mobileOpen ? "translate-x-0" : "-translate-x-full",
        ].join(" ")}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-5 border-b border-line">
          <span
            className="grid h-9 w-9 place-items-center rounded-xl bg-accent-dim border border-accent/25 text-lg"
            aria-hidden="true"
          >
            🛡
          </span>
          <div className="leading-tight min-w-0">
            <p className="text-sm font-bold text-white tracking-tight">API Security</p>
            <p className="text-xs text-info">Assessment Toolkit</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto" aria-label="Primary navigation">
          {NAV_ITEMS.map((item) => (
            <NavItem
              key={item.to}
              item={item}
              onClick={item.to === "/" ? handleNewAssessment : closeMobile}
            />
          ))}
        </nav>

        {/* Status footer */}
        <div className="px-4 py-4 border-t border-line mt-auto">
          <div className="flex items-center gap-2 mb-2">
            <span
              className={[
                "h-2 w-2 rounded-full flex-shrink-0",
                offline ? "bg-critical" : health ? "bg-ok status-dot-running" : "bg-info",
              ].join(" ")}
              aria-hidden="true"
            />
            <span className="text-xs text-slate-400 truncate">
              {offline
                ? "API unreachable"
                : health
                ? `Engine ready · Python ${health.python}`
                : "Connecting to engine…"}
            </span>
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            Max 200 req/assessment · min 0.2s spacing
          </p>
        </div>
      </aside>
    </>
  );
}
