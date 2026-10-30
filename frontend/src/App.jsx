import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Routes, Route, Link, useLocation, Navigate, useNavigate } from 'react-router-dom';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  FileText, 
  BarChart3, 
  Cpu, 
  Settings as SettingsIcon,
  Clock,
  Mail,
  ChevronLeft,
  ChevronRight,
  RotateCcw,
  BookOpen
} from 'lucide-react';
import axios from 'axios';

import Overview from './pages/Overview';
import Alerts from './pages/Alerts';
import Analytics from './pages/Analytics';
import Models from './pages/Models';
import Settings from './pages/Settings';
import OnboardingPage from './pages/OnboardingPage';
import LoginModal from './components/LoginModal';
import SplashScreen, { CyberCubeLogo } from './components/SplashScreen';
import Tour from './components/Tour';
import { isSetupComplete } from './utils/setupState';

const BACKEND_HOST = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000').replace(/^https?:\/\//, '');
const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

// Tour "already seen" flag is stored per user so each new account gets the walkthrough once.
const getTourKey = () => `soc_tour_seen:${sessionStorage.getItem('soc_user_email') || 'anonymous'}`;

// Lazily resolves a [data-tour="..."] element so the Tour can follow it.
const tourRef = (name) => ({
  get current() {
    return document.querySelector(`[data-tour="${name}"]`);
  },
});

// Steps for the guided tour (Tour.jsx requires this array via the `steps` prop).
const TOUR_STEPS = [
  { id: 'status',    title: 'System Status',     text: 'Shows that the live monitor is running and connected.',      ref: tourRef('system-status') },
  { id: 'clock',     title: 'Clock',             text: 'Current local time and date for incident timestamps.',       ref: tourRef('clock') },
  { id: 'overview',  title: 'Overview',          text: 'Your live SOC dashboard with threat summary and map.',       ref: tourRef('nav-overview') },
  { id: 'alerts',    title: 'Alerts',            text: 'Investigate and filter classified network threats.',         ref: tourRef('nav-alerts') },
  { id: 'logs',      title: 'Logs',              text: 'Full audit log of benign and anomalous flows.',              ref: tourRef('nav-logs') },
  { id: 'analytics', title: 'Analytics',         text: 'Historical intrusion trends over time.',                     ref: tourRef('nav-analytics') },
  { id: 'models',    title: 'Models (AI)',       text: 'Classifier metrics, confusion matrix and benchmarks.',       ref: tourRef('nav-models') },
  { id: 'settings',  title: 'Settings',          text: 'IPS auto-containment, thresholds and API URL.',              ref: tourRef('nav-settings') },
  { id: 'reset',     title: 'Reset Statistics',  text: 'Restarts the live data stream and refreshes the pages.',     ref: tourRef('reset-stats') },
  { id: 'guide',     title: 'Setup Guide',       text: 'Replay this tour any time from here.',                       ref: tourRef('setup-guide') },
];

// Inline SVGs for brand icons to bypass Lucide's removal of trademarked logos
const GithubIcon = ({ className }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.2c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4" />
    <path d="M9 18c-4.51 2-5-2-7-2" />
  </svg>
);

const LinkedinIcon = ({ className }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z" />
    <rect width="4" height="12" x="2" y="9" />
    <circle cx="4" cy="4" r="2" />
  </svg>
);

function App() {
  const location = useLocation();
  const navigate = useNavigate();
  
  // Auth & Route States
  const [isAuthenticated, setIsAuthenticated] = useState(!!sessionStorage.getItem('soc_session_token'));
  const [time, setTime] = useState(new Date());
  const [toast, setToast] = useState(null); // { text, tone: 'alert' | 'info' }
  const [streamKey, setStreamKey] = useState(0); // bumping this reconnects the WebSocket
  
  // Splash Screen, Sidebar, Tour and Reset states
  const [isAppLoading, setIsAppLoading] = useState(true);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [isTourOpen, setIsTourOpen] = useState(false);
  const [isResetting, setIsResetting] = useState(false);

  const toastTimer = useRef(null);
  const resetTimer = useRef(null);

  // Evaluated on every render (cheap localStorage read), so a refresh can never bypass setup.
  const setupDone = isSetupComplete();

  const showToast = useCallback((text, tone = 'alert', durationMs = 6000) => {
    clearTimeout(toastTimer.current);
    setToast({ text, tone });
    toastTimer.current = setTimeout(() => setToast(null), durationMs);
  }, []);

  // Clean up timers on unmount
  useEffect(() => () => {
    clearTimeout(toastTimer.current);
    clearTimeout(resetTimer.current);
  }, []);

  // Splash Screen Timer
  useEffect(() => {
    const timer = setTimeout(() => {
      setIsAppLoading(false);
    }, 2200);
    return () => clearTimeout(timer);
  }, []);

  // Save active tab to session memory (skip for onboarding)
  useEffect(() => {
    if (location.pathname !== '/index.html' && location.pathname !== '/onboarding') {
      sessionStorage.setItem('soc_last_route', location.pathname + location.search);
    }
  }, [location.pathname, location.search]);

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Launch the tour once, right after setup is finished, on the main console.
  useEffect(() => {
    if (!isAuthenticated || !setupDone || isAppLoading) return;
    if (location.pathname === '/onboarding') return;

    let seen = false;
    try { seen = !!localStorage.getItem(getTourKey()); } catch (e) { /* storage unavailable */ }
    if (seen) return;

    const timer = setTimeout(() => setIsTourOpen(true), 700);
    return () => clearTimeout(timer);
  }, [isAuthenticated, setupDone, isAppLoading, location.pathname]);

  const closeTour = useCallback(() => {
    setIsTourOpen(false);
    try { localStorage.setItem(getTourKey(), '1'); } catch (e) { /* storage unavailable */ }
  }, []);

  // When a tour step targets a sidebar item, make sure the sidebar is expanded.
  const handleTourStepChange = useCallback(() => {
    setIsSidebarOpen(true);
  }, []);

  // WebSocket Live Push Telemetry (re-runs when the user restarts the stream)
  useEffect(() => {
    if (!isAuthenticated) return;

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    
    // Inject the isolated tenant key into the WebSocket connection
    const tenantKey = sessionStorage.getItem('soc_tenant_key') || 'default';
    const wsUrl = `${wsProtocol}//${BACKEND_HOST}/ws/threats?api_key=${encodeURIComponent(tenantKey)}`;

    let socket;
    try {
      socket = new WebSocket(wsUrl);
      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'pcap_analysis_completed') {
            showToast(`PCAP Ingestion: ${data.threats_count} threats detected in ${data.filename}`);
            window.dispatchEvent(new CustomEvent('soc-threat-created'));
          } else if (data.type === 'new_threat') {
            showToast(`Live Threat Detected: [${data.threat?.attack_type}] from ${data.threat?.source_ip}`);
            window.dispatchEvent(new CustomEvent('soc-threat-created'));
          }
        } catch (e) {
          console.error("WS Parse error:", e);
        }
      };
    } catch (err) {
      console.warn("WebSocket initialization fallback");
    }
    return () => { if (socket) socket.close(); };
  }, [isAuthenticated, streamKey, showToast]);

  // "Reset Statistics": Uses the new secure backend endpoint instead of just clearing the local state
  const handleResetStatistics = useCallback(async () => {
    if (isResetting) return;
    
    const confirmDelete = window.confirm(
      "Are you sure you want to reset the statistics? This will permanently delete all logs and threats for your account."
    );
    if (!confirmDelete) return;

    setIsResetting(true);
    showToast('Clearing backend threat logs...', 'info', 4000);

    try {
      const token = sessionStorage.getItem('soc_session_token');
      const tenantKey = sessionStorage.getItem('soc_tenant_key');
      const headers = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;
      if (tenantKey) headers['X-Tenant-Key'] = tenantKey;

      // Hit the backend endpoint to delete the data
      await axios.post(`${API_URL}/statistics/reset`, {}, { headers });
      
      // Tell all the other components on the page to fetch the newly empty data
      setStreamKey((k) => k + 1);
      window.dispatchEvent(new CustomEvent('soc-stats-reset'));
      window.dispatchEvent(new CustomEvent('soc-threat-created'));
      window.dispatchEvent(new CustomEvent('soc-settings-updated'));
      
      showToast('Statistics reset successfully.', 'info', 3500);
    } catch (error) {
      console.error("Failed to reset stats:", error);
      showToast('Failed to reset statistics on the server.', 'alert', 3500);
    } finally {
      setIsResetting(false);
    }
  }, [isResetting, showToast]);

  const navItems = [
    { name: 'Overview', path: '/', icon: LayoutDashboard, tour: 'nav-overview' },
    { name: 'Alerts', path: '/alerts', icon: ShieldAlert, tour: 'nav-alerts' },
    { name: 'Logs', path: '/logs', icon: FileText, tour: 'nav-logs' },
    { name: 'Analytics', path: '/analytics', icon: BarChart3, tour: 'nav-analytics' },
    { name: 'Models (AI)', path: '/models', icon: Cpu, tour: 'nav-models' },
    { name: 'Settings', path: '/settings', icon: SettingsIcon, tour: 'nav-settings' },
  ];

  const formatClock = (date) => {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  };

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
    // Anyone who has not finished setup always lands in onboarding, new account or not.
    if (!isSetupComplete()) {
      navigate('/onboarding', { replace: true });
    } else {
      navigate(sessionStorage.getItem('soc_last_route') || '/', { replace: true });
    }
  };

  // ---------------------------------------------------------------------
  // Render gates (all hooks are above this line)
  // ---------------------------------------------------------------------
  if (isAppLoading) {
    return <SplashScreen />;
  }

  // Signed-out: show only the login modal. No pages mount, so nothing is fetched for the "default" tenant.
  if (!isAuthenticated) {
    return (
      <div className="flex h-screen bg-slate-950 text-slate-100 font-sans">
        <LoginModal isOpen={true} onLoginSuccess={handleLoginSuccess} />
      </div>
    );
  }

  // Onboarding route: only reachable while setup is incomplete.
  if (location.pathname === '/onboarding') {
    if (setupDone) {
      return <Navigate to={sessionStorage.getItem('soc_last_route') || '/'} replace />;
    }
    return (
      <Routes>
        <Route path="/onboarding" element={<OnboardingPage />} />
      </Routes>
    );
  }

  // Strict gate: signed in but setup not finished means every other URL (including after a reload) is sent to onboarding.
  if (!setupDone) {
    return <Navigate to="/onboarding" replace />;
  }

  const controlButtonClass = `flex items-center rounded-lg border border-slate-800 bg-slate-950/40 text-xs font-semibold text-slate-300 transition-colors hover:border-slate-700 hover:text-emerald-400 disabled:cursor-not-allowed disabled:opacity-60 ${
    isSidebarOpen ? 'w-full px-3 py-2 gap-3' : 'p-2.5 justify-center'
  }`;

  return (
    <div className="flex h-screen bg-slate-950 overflow-hidden text-slate-100 font-sans relative">

      {/* Guided tour (FIX: only mounted while open, and always given its steps) */}
      {isTourOpen && (
        <Tour steps={TOUR_STEPS} onClose={closeTour} onStepChange={handleTourStepChange} />
      )}

      {/* Collapsible Sidebar */}
      <aside className={`relative bg-slate-900 border-r border-slate-800 flex flex-col justify-between shrink-0 transition-all duration-300 ease-in-out z-20 ${isSidebarOpen ? 'w-64' : 'w-20'}`}>
        
        <button 
          type="button"
          onClick={() => setIsSidebarOpen(!isSidebarOpen)}
          aria-label={isSidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
          className="absolute -right-3 top-14 bg-slate-800 border border-slate-700 rounded-full p-1 text-slate-400 hover:text-emerald-400 hover:bg-slate-900 shadow-lg transition-colors z-30"
        >
          {isSidebarOpen ? <ChevronLeft className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </button>

        <div>
          <div className={`h-16 flex items-center ${isSidebarOpen ? 'px-6 gap-3' : 'justify-center'} border-b border-slate-800 bg-slate-950/40 overflow-hidden whitespace-nowrap transition-all duration-300`}>
            <div className="w-8 h-8 shrink-0 rounded-lg bg-emerald-600 flex items-center justify-center text-slate-100 shadow shadow-emerald-500/20">
              <CyberCubeLogo className="w-5 h-5 text-slate-100" />
            </div>
            <div className={`transition-opacity duration-300 ${isSidebarOpen ? '' : 'opacity-0 hidden'}`}>
              <h1 className="text-sm font-bold tracking-wider text-slate-100 uppercase">CyberCube</h1>
              <p className="text-[10px] font-bold text-emerald-500 uppercase tracking-widest leading-none mt-0.5">SOC Monitor</p>
            </div>
          </div>
          
          <nav className="mt-6 px-3 space-y-1.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.name}
                  to={item.path}
                  data-tour={item.tour}
                  title={!isSidebarOpen ? item.name : ""}
                  className={`flex items-center rounded-lg text-xs font-semibold tracking-wide transition-all group relative overflow-hidden ${
                    isSidebarOpen ? 'px-4 py-2.5 gap-3.5' : 'p-2.5 justify-center'
                  } ${
                    isActive 
                      ? 'bg-slate-800/80 text-emerald-400 border border-slate-700/50 shadow shadow-slate-950/50' 
                      : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200 border border-transparent'
                  }`}
                >
                  <Icon className={`w-4 h-4 shrink-0 transition-transform duration-200 group-hover:scale-105 ${isActive ? 'text-emerald-400' : 'text-slate-400 group-hover:text-slate-300'}`} />
                  <span className={`whitespace-nowrap transition-opacity duration-200 ${isSidebarOpen ? '' : 'hidden'}`}>
                    {item.name}
                  </span>
                  {isActive && (
                    <span className="absolute left-0 top-1/4 bottom-1/4 w-1 rounded-r-md bg-emerald-500"></span>
                  )}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Footer */}
        <div className={`p-4 border-t border-slate-800/80 bg-slate-950/20 flex flex-col gap-3 ${isSidebarOpen ? '' : 'items-center'}`}>

          {/* Controls */}
          <div className={`flex flex-col gap-2 ${isSidebarOpen ? 'w-full' : 'items-center'}`}>
            <div className={`text-[9px] uppercase font-bold text-slate-500 tracking-wider ${isSidebarOpen ? '' : 'hidden'}`}>
              Controls
            </div>

            <button
              type="button"
              data-tour="reset-stats"
              onClick={handleResetStatistics}
              disabled={isResetting}
              title={!isSidebarOpen ? 'Reset Statistics' : 'Restart the live data stream'}
              className={controlButtonClass}
            >
              <RotateCcw className={`w-4 h-4 shrink-0 ${isResetting ? 'animate-spin text-emerald-400' : ''}`} />
              <span className={`whitespace-nowrap ${isSidebarOpen ? '' : 'hidden'}`}>
                {isResetting ? 'Restarting...' : 'Reset Statistics'}
              </span>
            </button>

            <button
              type="button"
              data-tour="setup-guide"
              onClick={() => setIsTourOpen(true)}
              title={!isSidebarOpen ? 'Show Setup Guide' : 'Replay the guided tour'}
              className={controlButtonClass}
            >
              <BookOpen className="w-4 h-4 shrink-0" />
              <span className={`whitespace-nowrap ${isSidebarOpen ? '' : 'hidden'}`}>Show Setup Guide</span>
            </button>
          </div>

          <div className={`text-[9px] uppercase font-bold text-slate-500 tracking-wider transition-opacity ${isSidebarOpen ? '' : 'hidden'}`}>
            Network
          </div>
          
          <a href="mailto:naiknartana@gmail.com" title={!isSidebarOpen ? "Email" : ""} className="flex items-center gap-3 text-slate-400 hover:text-emerald-400 transition-colors group">
            <Mail className="w-5 h-5 shrink-0 group-hover:scale-110 transition-transform" />
            <span className={`text-xs font-semibold whitespace-nowrap ${isSidebarOpen ? '' : 'hidden'}`}>Email Developer</span>
          </a>

          <a href="https://github.com/NartanNaik" target="_blank" rel="noreferrer" title={!isSidebarOpen ? "GitHub" : ""} className="flex items-center gap-3 text-slate-400 hover:text-emerald-400 transition-colors group">
            <GithubIcon className="w-5 h-5 shrink-0 group-hover:scale-110 transition-transform" />
            <span className={`text-xs font-semibold whitespace-nowrap ${isSidebarOpen ? '' : 'hidden'}`}>Developer GitHub</span>
          </a>
          
          <a href="https://linkedin.com/in/nartan-naik-90499a359" target="_blank" rel="noreferrer" title={!isSidebarOpen ? "LinkedIn" : ""} className="flex items-center gap-3 text-slate-400 hover:text-emerald-400 transition-colors group">
            <LinkedinIcon className="w-5 h-5 shrink-0 group-hover:scale-110 transition-transform" />
            <span className={`text-xs font-semibold whitespace-nowrap ${isSidebarOpen ? '' : 'hidden'}`}>Connect on LinkedIn</span>
          </a>
        </div>
      </aside>

      {/* Main Panel */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <header className="h-16 bg-slate-900 border-b border-slate-800 flex items-center justify-between px-6 shrink-0 relative z-10">
          <div className="flex items-center gap-3" data-tour="system-status">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">
              SYSTEM MONITOR ACTIVE
            </span>
          </div>

          {toast && (
            <div
              role="status"
              className={`absolute left-1/2 -translate-x-1/2 px-4 py-1.5 rounded-full text-xs font-semibold shadow-lg flex items-center gap-2 ${
                toast.tone === 'info'
                  ? 'bg-emerald-950/90 border border-emerald-500/40 text-emerald-200 shadow-emerald-950/50'
                  : 'bg-rose-950/90 border border-rose-500/40 text-rose-200 shadow-rose-950/50 animate-bounce'
              }`}
            >
              <span className={`w-2 h-2 rounded-full animate-ping ${toast.tone === 'info' ? 'bg-emerald-500' : 'bg-rose-500'}`}></span>
              <span>{toast.text}</span>
            </div>
          )}
          
          <div className="flex items-center gap-4 text-xs font-semibold text-slate-400 bg-slate-950/40 border border-slate-800 px-4 py-2 rounded-lg" data-tour="clock">
            <Clock className="w-4 h-4 text-slate-500" />
            <span className="font-mono tracking-wider">{formatClock(time)}</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">{time.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' })}</span>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-6 bg-slate-950">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/alerts" element={<Alerts showOnlyAttacks={true} />} />
            <Route path="/logs" element={<Alerts showOnlyAttacks={false} />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/models" element={<Models />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/index.html" element={<Navigate to={sessionStorage.getItem('soc_last_route') || '/'} replace />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default App;