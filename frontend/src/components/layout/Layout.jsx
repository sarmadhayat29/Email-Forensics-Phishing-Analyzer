import React, { useCallback, useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import {
  UploadCloud, Shield, LayoutDashboard, Clock, Info, LogOut,
  Menu, X, PanelLeftClose, PanelLeft,
} from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';

const COLLAPSED_KEY = 'soc-sidebar-collapsed';
const LG_QUERY = '(min-width: 1024px)';

const NAV_ITEMS = [
  { to: '/dashboard', label: 'Workspace Dashboard', icon: LayoutDashboard },
  { to: '/upload', label: 'Upload & Analyze', icon: UploadCloud },
  { to: '/history', label: 'Analysis History', icon: Clock },
  { to: '/about', label: 'About', icon: Info },
];

function useIsDesktop() {
  const [isDesktop, setIsDesktop] = useState(() =>
    typeof window !== 'undefined' ? window.matchMedia(LG_QUERY).matches : true
  );

  useEffect(() => {
    const mq = window.matchMedia(LG_QUERY);
    const onChange = () => setIsDesktop(mq.matches);
    onChange();
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  return isDesktop;
}

function pageTitleFromPath(pathname) {
  const segment = pathname.split('/').filter(Boolean)[0] || 'dashboard';
  if (segment === 'analysis') return 'Investigation';
  return segment.replace(/-/g, ' ');
}

export default function Layout() {
  const { user, logoutUser } = useAuth();
  const location = useLocation();
  const isDesktop = useIsDesktop();

  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(COLLAPSED_KEY) === '1';
    } catch {
      return false;
    }
  });
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    try {
      localStorage.setItem(COLLAPSED_KEY, collapsed ? '1' : '0');
    } catch {
      /* ignore quota / private mode */
    }
  }, [collapsed]);

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (isDesktop) setMobileOpen(false);
  }, [isDesktop]);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') setMobileOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    if (!mobileOpen || isDesktop) return undefined;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = prev;
    };
  }, [mobileOpen, isDesktop]);

  const toggleSidebar = useCallback(() => {
    if (isDesktop) setCollapsed((c) => !c);
    else setMobileOpen((o) => !o);
  }, [isDesktop]);

  const closeMobile = useCallback(() => setMobileOpen(false), []);

  const navClass = ({ isActive }) =>
    [
      'w-full min-h-11 rounded-xl text-xs font-bold flex items-center transition',
      collapsed && isDesktop ? 'justify-center px-2 py-2.5 gap-0' : 'gap-3 px-3.5 py-2.5',
      isActive
        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
        : 'text-slate-400 hover:bg-soc-card hover:text-slate-200 border border-transparent',
    ].join(' ');

  const renderNav = (opts = {}) => {
    const { onNavigate, showLabels = true } = opts;
    return (
      <nav className="p-3 sm:p-4 space-y-1.5 overflow-y-auto flex-1 min-h-0" aria-label="Main">
        {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            title={label}
            aria-label={label}
            onClick={onNavigate}
            className={navClass}
          >
            <Icon className="w-4 h-4 shrink-0" aria-hidden />
            {showLabels && <span className="truncate">{label}</span>}
          </NavLink>
        ))}
      </nav>
    );
  };

  const brandBlock = (compact) => (
    <div
      className={[
        'border-b border-emerald-950 flex items-center shrink-0',
        compact ? 'p-3 justify-center' : 'p-4 sm:p-6 gap-3',
      ].join(' ')}
    >
      <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-400 shrink-0">
        <Shield className="w-6 h-6" aria-hidden />
      </div>
      {!compact && (
        <div className="min-w-0">
          <h1 className="font-extrabold text-base leading-none text-slate-100 truncate">
            SOC Workspace
          </h1>
          <span className="text-[10px] font-mono text-cyan-400">Forensics Engine v2.0</span>
        </div>
      )}
    </div>
  );

  const userFooter = (compact, { onNavigate } = {}) => (
    <div className="p-3 sm:p-4 border-t border-emerald-950 shrink-0">
      {!compact && (
        <div className="px-3 pb-3 mb-2 border-b border-emerald-950/50 min-w-0">
          <p className="text-[10px] font-mono text-slate-500 uppercase">Logged in as</p>
          {user?.full_name ? (
            <p className="text-xs font-bold text-slate-200 truncate" title={user.full_name}>
              {user.full_name}
            </p>
          ) : null}
          <p className="text-xs font-bold text-slate-300 truncate" title={user?.email}>
            {user?.email}
          </p>
        </div>
      )}
      <button
        type="button"
        onClick={() => {
          onNavigate?.();
          logoutUser();
        }}
        title="Secure Logout"
        aria-label="Secure Logout"
        className={[
          'w-full min-h-11 rounded-xl text-xs font-bold flex items-center text-red-400 hover:bg-red-950/30 transition',
          compact ? 'justify-center px-2' : 'gap-3 px-3.5',
        ].join(' ')}
      >
        <LogOut className="w-4 h-4 shrink-0" aria-hidden />
        {!compact && <span>Secure Logout</span>}
      </button>
    </div>
  );

  const desktopCollapsed = isDesktop && collapsed;

  return (
    <div className="flex h-[100dvh] max-h-[100dvh] bg-soc-bg text-slate-100 font-sans overflow-hidden">
      {/* Desktop sidebar */}
      <aside
        className={[
          'hidden lg:flex bg-soc-panel border-r border-emerald-950 flex-col justify-between shrink-0',
          'transition-[width] duration-300 ease-in-out overflow-hidden',
          desktopCollapsed ? 'w-[4.5rem]' : 'w-64',
        ].join(' ')}
        aria-label="Sidebar"
      >
        {brandBlock(desktopCollapsed)}
        {renderNav({ showLabels: !desktopCollapsed })}
        {userFooter(desktopCollapsed)}
      </aside>

      {/* Mobile drawer overlay */}
      <div
        className={[
          'lg:hidden fixed inset-0 z-40 transition-opacity duration-300',
          mobileOpen ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none',
        ].join(' ')}
        aria-hidden={!mobileOpen}
      >
        <button
          type="button"
          className="absolute inset-0 bg-black/60 backdrop-blur-[2px]"
          aria-label="Close menu"
          onClick={closeMobile}
        />
        <aside
          className={[
            'absolute inset-y-0 left-0 w-[min(18rem,88vw)] max-w-full bg-soc-panel border-r border-emerald-950',
            'flex flex-col shadow-2xl transition-transform duration-300 ease-in-out',
            mobileOpen ? 'translate-x-0' : '-translate-x-full',
          ].join(' ')}
          role="dialog"
          aria-modal="true"
          aria-label="Navigation menu"
        >
          <div className="p-4 border-b border-emerald-950 flex items-center justify-between gap-3 shrink-0">
            <div className="flex items-center gap-3 min-w-0">
              <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-400 shrink-0">
                <Shield className="w-5 h-5" aria-hidden />
              </div>
              <div className="min-w-0">
                <h1 className="font-extrabold text-sm text-slate-100 truncate">SOC Workspace</h1>
                <span className="text-[10px] font-mono text-cyan-400">Forensics Engine v2.0</span>
              </div>
            </div>
            <button
              type="button"
              onClick={closeMobile}
              className="min-h-11 min-w-11 inline-flex items-center justify-center rounded-xl text-slate-400 hover:text-slate-100 hover:bg-soc-card transition focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
              aria-label="Close sidebar"
            >
              <X className="w-5 h-5" aria-hidden />
            </button>
          </div>
          {renderNav({ onNavigate: closeMobile, showLabels: true })}
          {userFooter(false, { onNavigate: closeMobile })}
        </aside>
      </div>

      {/* Main column */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <header className="h-14 sm:h-16 border-b border-emerald-950 bg-soc-panel px-3 sm:px-6 lg:px-8 flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-2 sm:gap-3 min-w-0">
            <button
              type="button"
              onClick={toggleSidebar}
              className="min-h-11 min-w-11 inline-flex items-center justify-center rounded-xl text-slate-300 hover:text-emerald-400 hover:bg-emerald-500/10 border border-transparent hover:border-emerald-500/20 transition focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
              aria-label={
                isDesktop
                  ? (collapsed ? 'Expand sidebar' : 'Collapse sidebar')
                  : (mobileOpen ? 'Close menu' : 'Open menu')
              }
              aria-expanded={isDesktop ? !collapsed : mobileOpen}
            >
              {isDesktop ? (
                collapsed ? <PanelLeft className="w-5 h-5" aria-hidden /> : <PanelLeftClose className="w-5 h-5" aria-hidden />
              ) : (
                <Menu className="w-5 h-5" aria-hidden />
              )}
            </button>
            <h2 className="font-bold text-sm sm:text-base text-slate-100 capitalize truncate">
              {pageTitleFromPath(location.pathname)}
            </h2>
          </div>
          {!isDesktop && (
            <div className="flex items-center gap-2 shrink-0 lg:hidden">
              <div className="p-1.5 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-400">
                <Shield className="w-4 h-4" aria-hidden />
              </div>
            </div>
          )}
        </header>

        <div className="flex-1 overflow-y-auto overflow-x-hidden p-3 sm:p-6 lg:p-8 relative">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
