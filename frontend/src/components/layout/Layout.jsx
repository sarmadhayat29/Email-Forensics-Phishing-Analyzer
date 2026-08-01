import React from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { UploadCloud, Shield, LayoutDashboard, Clock, Info, LogOut } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';

export default function Layout() {
  const { user, logoutUser } = useAuth();
  const location = useLocation();

  const getPageTitle = () => {
    const path = location.pathname.split('/')[1];
    return path ? path.replace('-', ' ') : 'dashboard';
  };

  const navLinkClass = ({ isActive }) => 
    `w-full px-3.5 py-2.5 rounded-xl text-xs font-bold flex items-center gap-3 transition ${
      isActive 
        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' 
        : 'text-slate-400 hover:bg-soc-card hover:text-slate-200'
    }`;

  return (
    <div className="flex h-screen bg-soc-bg text-slate-100 font-sans overflow-hidden">
      {/* PERSISTENT SIDEBAR NAVIGATION */}
      <aside className="w-64 bg-soc-panel border-r border-emerald-950 flex flex-col justify-between shrink-0">
        <div>
          <div className="p-6 border-b border-emerald-950 flex items-center gap-3">
            <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="font-extrabold text-base leading-none text-slate-100">SOC Workspace</h1>
              <span className="text-[10px] font-mono text-cyan-400">Forensics Engine v2.0</span>
            </div>
          </div>

          <nav className="p-4 space-y-1.5">
            <NavLink to="/dashboard" className={navLinkClass}>
              <LayoutDashboard className="w-4 h-4" /> Workspace Dashboard
            </NavLink>
            <NavLink to="/upload" className={navLinkClass}>
              <UploadCloud className="w-4 h-4" /> Upload &amp; Analyze
            </NavLink>
            <NavLink to="/history" className={navLinkClass}>
              <Clock className="w-4 h-4" /> Analysis History
            </NavLink>
            <NavLink to="/about" className={navLinkClass}>
              <Info className="w-4 h-4" /> About
            </NavLink>
          </nav>
        </div>
        
        <div className="p-4 border-t border-emerald-950">
          <div className="px-3 pb-3 mb-2 border-b border-emerald-950/50">
            <p className="text-[10px] font-mono text-slate-500 uppercase">Logged in as</p>
            {user?.full_name ? (
              <p className="text-xs font-bold text-slate-200 truncate" title={user.full_name}>
                {user.full_name}
              </p>
            ) : null}
            <p className="text-xs font-bold text-slate-300 truncate" title={user?.email}>{user?.email}</p>
          </div>
          <button onClick={logoutUser} className="w-full px-3.5 py-2.5 rounded-xl text-xs font-bold flex items-center gap-3 text-red-400 hover:bg-red-950/30 transition">
            <LogOut className="w-4 h-4" /> Secure Logout
          </button>
        </div>
      </aside>

      {/* MAIN WORKSPACE CONTENT */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        
        <header className="h-16 border-b border-emerald-950 bg-soc-panel px-8 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <h2 className="font-bold text-base text-slate-100 capitalize">{getPageTitle()}</h2>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-8 relative">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
