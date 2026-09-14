import React, { useEffect, useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  ShieldAlert,
  Activity,
  Network,
  Briefcase,
  BarChart2,
  FileText,
  Radio,
  WifiOff,
  Sun,
  Moon,
} from 'lucide-react';
import { wsManager, type WebSocketStatus } from '../../api/ws';
import { api } from '../../api/client';

import { LiveAlertPopup } from './LiveAlertPopup';

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [wsStatus, setWsStatus] = useState<WebSocketStatus>(wsManager.getStatus());
  const [backendOk, setBackendOk] = useState<boolean>(false);
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const saved = typeof window !== 'undefined' ? localStorage.getItem('sh4d0w-theme') : null;
    return saved === 'light' ? 'light' : 'dark';
  });
  const location = useLocation();

  useEffect(() => {
    document.documentElement.classList.remove('dark', 'light');
    document.documentElement.classList.add(theme);
    document.body.classList.remove('dark', 'light');
    document.body.classList.add(theme);
    localStorage.setItem('sh4d0w-theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  useEffect(() => {
    const unsub = wsManager.subscribeStatus((st) => setWsStatus(st));

    // Check backend health
    api.getHealth()
      .then(() => setBackendOk(true))
      .catch(() => setBackendOk(false));

    const interval = setInterval(() => {
      api.getHealth()
        .then(() => setBackendOk(true))
        .catch(() => setBackendOk(false));
    }, 15000);

    return () => {
      unsub();
      clearInterval(interval);
    };
  }, []);

  const navItems = [
    { section: 'COMMAND CENTER' },
    { to: '/', label: 'Overview', icon: Activity },
    { section: 'INVESTIGATION' },
    { to: '/alerts', label: 'Alerts', icon: ShieldAlert },
    { to: '/cases', label: 'Cases', icon: Briefcase },
    { section: 'THREAT INTELLIGENCE' },
    { to: '/topology', label: 'Attack Topology', icon: Network },
    { to: '/analytics', label: 'Detection Analytics', icon: BarChart2 },
    { section: 'REPORTING' },
    { to: '/reports', label: 'Threat Reports', icon: FileText },
  ];

  const getPageTitle = (pathname: string) => {
    if (pathname === '/') return { title: 'Command Center', subtitle: 'Real-time behavioral threat monitoring' };
    if (pathname.startsWith('/alerts/')) return { title: 'Alert Investigation', subtitle: 'Deep forensic evidence & detector rationale' };
    if (pathname === '/alerts') return { title: 'Security Alerts', subtitle: 'Deduplicated threat alerts evaluated from risk scores' };
    if (pathname.startsWith('/cases/')) return { title: 'Case Investigation', subtitle: 'Correlated incident timeline & evidence' };
    if (pathname === '/cases') return { title: 'Incident Cases', subtitle: 'Multi-stage behavioral SOC incident cases' };
    if (pathname === '/topology') return { title: 'Attack Topology', subtitle: 'Entity relationship view (IP → Account → Device → Destination → Port)' };
    if (pathname === '/analytics') return { title: 'Detection Analytics', subtitle: 'Multi-detector activity & behavioral distribution' };
    if (pathname === '/reports') return { title: 'Threat Reports', subtitle: 'Investigation summaries & intelligence exports' };
    return { title: 'Sh4d0w_St4lk3r', subtitle: 'Behavioral Threat Intelligence Platform' };
  };

  const { title, subtitle } = getPageTitle(location.pathname);

  return (
    <div className="flex h-screen w-screen bg-[#070b12] text-slate-100 overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-[#0a0f18] border-r border-[#1c2638] flex flex-col justify-between select-none">
        <div>
          {/* Logo */}
          <div className="p-5 border-b border-[#1c2638]">
            <div className="flex items-center space-x-2.5">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center font-mono font-bold text-black text-sm shadow-[0_0_15px_rgba(0,210,255,0.4)]">
                S4
              </div>
              <div>
                <div className="font-mono text-sm font-bold tracking-wider text-white">
                  SH4D0W<span className="text-cyan-400">_ST4LK3R</span>
                </div>
                <div className="text-[10px] text-slate-400 tracking-tight">
                  Behavioral Threat Platform
                </div>
              </div>
            </div>
          </div>

          {/* Nav */}
          <nav className="p-3 space-y-1 overflow-y-auto max-h-[calc(100vh-170px)]">
            {navItems.map((item, idx) => {
              if (item.section) {
                return (
                  <div
                    key={idx}
                    className="text-[10px] font-mono tracking-wider text-slate-500 font-semibold px-3 pt-4 pb-1"
                  >
                    {item.section}
                  </div>
                );
              }

              const Icon = item.icon!;
              return (
                <NavLink
                  key={item.to}
                  to={item.to!}
                  className={({ isActive }) =>
                    `flex items-center space-x-3 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                      isActive
                        ? 'bg-cyan-950/40 text-cyan-400 border border-cyan-800/40 shadow-[0_0_10px_rgba(0,210,255,0.1)]'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-[#101724]'
                    }`
                  }
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>

        {/* System Status Footer */}
        <div className="p-3.5 border-t border-[#1c2638] bg-[#070b12]/80 text-[11px] font-mono space-y-1.5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center space-x-1.5">
              <span
                className={`w-2 h-2 rounded-full ${
                  backendOk ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]' : 'bg-rose-500'
                }`}
              />
              <span>Backend Core</span>
            </span>
            <span className={backendOk ? 'text-emerald-400' : 'text-rose-400'}>
              {backendOk ? 'ONLINE' : 'UNREACHABLE'}
            </span>
          </div>

          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center space-x-1.5">
              <span
                className={`w-2 h-2 rounded-full ${
                  wsStatus === 'CONNECTED'
                    ? 'bg-cyan-400 shadow-[0_0_6px_rgba(0,210,255,0.8)]'
                    : wsStatus === 'CONNECTING'
                    ? 'bg-amber-400 animate-pulse'
                    : 'bg-slate-600'
                }`}
              />
              <span>Real-Time WS</span>
            </span>
            <span
              className={
                wsStatus === 'CONNECTED'
                  ? 'text-cyan-400'
                  : wsStatus === 'CONNECTING'
                  ? 'text-amber-400'
                  : 'text-slate-500'
              }
            >
              {wsStatus}
            </span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Header */}
        <header className="h-16 border-b border-[#1c2638] bg-[#090e17] px-6 flex items-center justify-between">
          <div>
            <h1 className="text-base font-semibold text-white tracking-wide">{title}</h1>
            <p className="text-xs text-slate-400">{subtitle}</p>
          </div>

          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-[#0d131d] border border-[#1c2638] text-xs font-mono">
              {wsStatus === 'CONNECTED' ? (
                <>
                  <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                  <span className="text-cyan-400">STREAMING ACTIVE</span>
                </>
              ) : (
                <>
                  <WifiOff className="w-3.5 h-3.5 text-slate-500" />
                  <span className="text-slate-500">RECONNECTING...</span>
                </>
              )}
            </div>

            <button
              type="button"
              onClick={toggleTheme}
              aria-label={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              className="p-1.5 rounded-lg bg-[#0d131d] border border-[#1c2638] text-slate-300 hover:text-cyan-400 hover:border-cyan-800 transition-all cursor-pointer flex items-center justify-center focus:outline-none focus:ring-1 focus:ring-cyan-500"
            >
              {theme === 'dark' ? (
                <Sun className="w-4 h-4 text-amber-400 hover:text-amber-300 transition-colors" />
              ) : (
                <Moon className="w-4 h-4 text-slate-700 hover:text-cyan-600 transition-colors" />
              )}
            </button>

            <div className="text-[11px] font-mono text-slate-500 border-l border-[#1c2638] pl-4">
              v1.0.0-SOC
            </div>
          </div>
        </header>

        <LiveAlertPopup />
        {/* Page Container */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#070b12]">
          {children}
        </main>
      </div>
    </div>
  );
};
