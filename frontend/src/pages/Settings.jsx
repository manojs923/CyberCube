import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Settings as SettingsIcon, 
  Sliders, 
  Shield, 
  Save, 
  ShieldAlert, 
  Trash2, 
  Link as LinkIcon, 
  CheckCircle2, 
  Send, 
  ShieldCheck, 
  KeyRound, 
  RefreshCw 
} from 'lucide-react';

const Settings = () => {
  // Existing Local Storage Settings
  const [threshold, setThreshold] = useState(() => {
    return parseInt(localStorage.getItem('soc_threshold') || '85', 10);
  });
  const [interval, setIntervalVal] = useState(() => {
    return parseInt(localStorage.getItem('soc_polling_interval') || '10', 10);
  });
  const [apiUrl, setApiUrl] = useState(() => {
    return localStorage.getItem('soc_api_url') || (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000');
  });
  const [webhookUrl, setWebhookUrl] = useState(() => {
    return localStorage.getItem('soc_webhook_url') || '';
  });
  const [saved, setSaved] = useState(false);

  // IPS Auto-Containment Settings
  const [ipsActive, setIpsActive] = useState(false);
  const [ipsLoading, setIpsLoading] = useState(true);
  
  // State for hard reset functionality
  const [resetting, setResetting] = useState(false);
  const [resetMessage, setResetMessage] = useState(null);

  // Webhook Test state
  const [testingWebhook, setTestingWebhook] = useState(false);
  const [webhookFeedback, setWebhookFeedback] = useState(null);

  // Forensic Audit Verification state
  const [verifyingAudit, setVerifyingAudit] = useState(false);
  const [auditData, setAuditData] = useState(null);

  // Helper function to build headers for API calls
  const getAuthHeaders = () => {
    const token = sessionStorage.getItem('soc_session_token');
    const tenantKey = sessionStorage.getItem('soc_tenant_key');
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    if (tenantKey) headers['X-Tenant-Key'] = tenantKey;
    return headers;
  };

  // Fetch initial IPS state from the FastAPI backend when the page loads
  useEffect(() => {
    const headers = getAuthHeaders();
    axios.get(`${apiUrl}/config/ips`, { headers })
      .then(res => {
        setIpsActive(res.data.ips_mode_active);
        setIpsLoading(false);
      })
      .catch(err => {
        console.error("Failed to fetch IPS settings", err);
        setIpsLoading(false);
      });
  }, [apiUrl]);

  // Handle saving the local UI settings (threshold, polling, api, webhook)
  const handleSave = (e) => {
    e.preventDefault();
    localStorage.setItem('soc_threshold', threshold.toString());
    localStorage.setItem('soc_polling_interval', interval.toString());
    localStorage.setItem('soc_api_url', apiUrl.trim());
    localStorage.setItem('soc_webhook_url', webhookUrl.trim());
    
    // Broadcast event across app tabs / windows
    window.dispatchEvent(new Event('soc-settings-updated'));
    
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  // Handle toggling the IPS automation engine on the backend server
  const toggleIpsMode = async () => {
    setIpsLoading(true);
    const newState = !ipsActive;
    try {
      const headers = getAuthHeaders();
      await axios.post(`${apiUrl}/config/ips?active=${newState}`, {}, { headers });
      setIpsActive(newState);
    } catch (error) {
      console.error("Error updating IPS settings", error);
    } finally {
      setIpsLoading(false);
    }
  };

  // Test SIEM Webhook Dispatch
  const handleTestWebhook = async () => {
    if (!webhookUrl.trim()) {
      setWebhookFeedback({ type: 'error', text: 'Please enter a webhook URL first.' });
      setTimeout(() => setWebhookFeedback(null), 3000);
      return;
    }
    setTestingWebhook(true);
    setWebhookFeedback(null);
    try {
      const headers = getAuthHeaders();
      await axios.post(`${apiUrl}/notifications/webhook`, {
        webhook_url: webhookUrl.trim()
      }, { headers });
      setWebhookFeedback({ type: 'success', text: 'Test alert delivered successfully!' });
    } catch (err) {
      setWebhookFeedback({ type: 'error', text: err.response?.data?.detail || 'Failed to dispatch webhook.' });
    } finally {
      setTestingWebhook(false);
      setTimeout(() => setWebhookFeedback(null), 4000);
    }
  };

  // Verify Tamper-Evident Hash Chain
  const handleVerifyAudit = async () => {
    setVerifyingAudit(true);
    setAuditData(null);
    try {
      const headers = getAuthHeaders();
      const res = await axios.get(`${apiUrl}/audit/verify`, { headers });
      setAuditData(res.data);
    } catch (err) {
      console.error("Audit verification error:", err);
      alert("Failed to verify cryptographic audit trail.");
    } finally {
      setVerifyingAudit(false);
    }
  };

  // Handle completely resetting the tenant's statistics and data
  const handleResetData = async () => {
    const confirmDelete = window.confirm(
      "WARNING: This will permanently delete all your generated network logs, PCAP analysis results, and threat statistics. Are you absolutely sure?"
    );
    
    if (!confirmDelete) return;

    setResetting(true);
    setResetMessage(null);

    try {
      const headers = getAuthHeaders();
      const res = await axios.post(`${apiUrl}/statistics/reset`, {}, { headers });
      setResetMessage({ type: 'success', text: res.data.message || 'All statistics have been cleared.' });
      window.dispatchEvent(new Event('soc-settings-updated'));
    } catch (error) {
      console.error("Failed to reset statistics", error);
      setResetMessage({ type: 'error', text: 'Failed to reset statistics. Please check your connection.' });
    } finally {
      setResetting(false);
      setTimeout(() => setResetMessage(null), 4000);
    }
  };

  return (
    <div className="space-y-8 max-w-2xl">
      
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <SettingsIcon className="w-5 h-5 text-slate-400" />
          <span>System Settings</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">Configure threat containment rules, threshold bounds, SIEM webhooks, and forensic integrity.</p>
      </div>

      {/* IPS Auto-Containment Toggle Block */}
      <div className="glass-panel p-6 bg-slate-900 border border-slate-800 rounded-xl relative overflow-hidden">
        <div className="flex justify-between items-start mb-5">
          <div>
            <h3 className="text-lg font-semibold text-slate-200">Defense Operations Mode</h3>
            <p className="text-xs text-slate-400 mt-1">Configure automated firewall response and active threat containment.</p>
          </div>
          <div className={`p-2.5 rounded-lg ${ipsActive ? 'bg-rose-500/20' : 'bg-emerald-500/20'}`}>
            {ipsActive ? <ShieldAlert className="w-6 h-6 text-rose-500" /> : <Shield className="w-6 h-6 text-emerald-500" />}
          </div>
        </div>

        <div className="flex items-center justify-between p-4 bg-slate-950 rounded-lg border border-slate-800 shadow-inner">
          <div>
            <p className="font-semibold text-sm text-slate-200">IPS Auto-Containment</p>
            <p className="text-[10px] text-slate-500 mt-1">Automatically execute firewall blocks for critical/high severity threats without human intervention.</p>
          </div>
          
          <button 
            onClick={toggleIpsMode}
            disabled={ipsLoading}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none shrink-0 ${ipsActive ? 'bg-rose-500' : 'bg-slate-700'} ${ipsLoading ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${ipsActive ? 'translate-x-6' : 'translate-x-1'}`} />
          </button>
        </div>

        {ipsActive && (
          <div className="mt-4 p-3 bg-rose-950/30 border border-rose-900/50 rounded-lg flex items-start gap-2 animate-pulse">
            <span className="w-2 h-2 rounded-full bg-rose-500 mt-1 shrink-0"></span>
            <span className="text-xs text-rose-300 leading-tight">
              <strong>ACTIVE DEFENSE:</strong> Autonomous IPS mode is engaged. Verified malicious flows will be contained instantly upon inference.
            </span>
          </div>
        )}
      </div>

      {/* CRYPTOGRAPHIC AUDIT INTEGRITY CHECKER */}
      <div className="glass-panel p-6 bg-slate-900/50 border border-slate-800 rounded-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sky-400">
            <KeyRound className="w-5 h-5" />
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">Tamper-Evident Forensic Audit Chain</h3>
          </div>
          <button
            type="button"
            onClick={handleVerifyAudit}
            disabled={verifyingAudit}
            className="px-3 py-1.5 rounded-lg bg-sky-600/20 hover:bg-sky-600/30 border border-sky-500/30 text-sky-300 text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer shadow"
          >
            {verifyingAudit ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
            <span>{verifyingAudit ? "Computing Hashes..." : "Verify Cryptographic Audit"}</span>
          </button>
        </div>
        <p className="text-xs text-slate-400">
          Evaluates sequential SHA-256 hash chaining across tenant incident logs to prove zero data alteration or unauthorized deletion for regulatory compliance (SOC 2, ISO 27001).
        </p>

        {auditData && (
          <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-2 text-xs font-mono animate-fade-in">
            <div className="flex items-center justify-between text-emerald-400 font-bold">
              <span className="flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                <span>INTEGRITY VERIFIED: ZERO TAMPER DETECTED</span>
              </span>
              <span className="text-[10px] text-slate-500">{auditData.total_records_verified} Verified Blocks</span>
            </div>
            <div className="text-[11px] text-slate-400 space-y-1 pt-1 border-t border-slate-800/80">
              <div className="truncate"><span className="text-slate-500">Chain Head:</span> {auditData.chain_head}</div>
              <div><span className="text-slate-500">Algorithm:</span> {auditData.algorithm}</div>
              <div><span className="text-slate-500">Verified Timestamp:</span> {auditData.verified_at}</div>
            </div>
          </div>
        )}
      </div>

      {/* SIEM & WEBHOOK INTEGRATION */}
      <div className="glass-panel p-6 bg-slate-900/40 rounded-xl border border-slate-800/50 space-y-4">
        <div className="flex items-center gap-2 text-slate-200">
          <LinkIcon className="w-5 h-5 text-emerald-400" />
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">SIEM & Webhook Forwarding</h3>
        </div>
        <p className="text-xs text-slate-400">
          Forward critical threat notifications and MITRE ATT&CK tags in real time to Slack, Discord, Microsoft Teams, or custom SIEM collectors.
        </p>

        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <input
              type="text"
              placeholder="https://hooks.slack.com/services/... or Discord Webhook"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-slate-700 font-mono transition-colors"
            />
            <button
              type="button"
              onClick={handleTestWebhook}
              disabled={testingWebhook}
              className="px-3.5 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-200 text-xs font-semibold border border-slate-700 flex items-center gap-1.5 transition-all cursor-pointer shrink-0"
            >
              {testingWebhook ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5 text-emerald-400" />}
              <span>Test Webhook</span>
            </button>
          </div>

          {webhookFeedback && (
            <div className={`text-xs p-2.5 rounded-lg font-medium flex items-center gap-2 ${webhookFeedback.type === 'success' ? 'bg-emerald-950/40 border border-emerald-500/20 text-emerald-300' : 'bg-rose-950/40 border border-rose-500/20 text-rose-300'}`}>
              <span>{webhookFeedback.text}</span>
            </div>
          )}
        </div>
      </div>

      {/* Dashboard UI Settings Block */}
      <div className="glass-panel p-6 bg-slate-900/40 rounded-xl border border-slate-800/50">
        <h3 className="text-sm font-semibold text-slate-200 mb-5 border-b border-slate-800 pb-2">Dashboard Interface Parameters</h3>
        
        <form onSubmit={handleSave} className="space-y-6">
          
          {/* Threshold slider */}
          <div className="space-y-2">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Sliders className="w-4 h-4 text-sky-400" />
              <span>Anomaly Alarm Threshold ({threshold}%)</span>
            </label>
            <input
              type="range"
              min="50"
              max="99"
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
              className="w-full bg-slate-850 h-1.5 rounded-lg appearance-none cursor-pointer accent-emerald-500"
            />
            <span className="text-[10px] text-slate-500 block">Threat alerts with classification confidence below this value will not trigger high severity notifications.</span>
          </div>

          {/* Refresh Interval */}
          <div className="space-y-2">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Shield className="w-4 h-4 text-emerald-400" />
              <span>Log Polling Interval (Seconds)</span>
            </label>
            <input
              type="number"
              min="1"
              max="60"
              value={interval}
              onChange={(e) => setIntervalVal(parseInt(e.target.value || '1', 10))}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-slate-700 transition-colors"
            />
            <span className="text-[10px] text-slate-500 block">Rate at which the dashboard pulls active logs from the server database (default is 10s).</span>
          </div>

          {/* API URL */}
          <div className="space-y-2">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-400">
              <span>Backend API Server URL</span>
            </label>
            <input
              type="text"
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-slate-700 font-mono transition-colors"
            />
            <span className="text-[10px] text-slate-500 block">Target server endpoint where threat logs are hosted.</span>
          </div>

          {/* Save Button */}
          <div className="pt-2 border-t border-slate-800/80">
            <button
              type="submit"
              className="w-full mt-4 bg-emerald-600 hover:bg-emerald-500 text-slate-100 px-4 py-2.5 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-all shadow-md cursor-pointer"
            >
              <Save className="w-4 h-4" />
              <span>{saved ? "Settings Applied!" : "Save Dashboard Modifications"}</span>
            </button>
          </div>
        </form>
      </div>

      {/* DATA MANAGEMENT (HARD RESET) BLOCK */}
      <div className="glass-panel p-6 bg-rose-950/20 border border-rose-900/30 rounded-xl">
        <div className="mb-4 border-b border-rose-900/30 pb-3">
          <h3 className="text-sm font-semibold text-rose-400 flex items-center gap-2">
            <Trash2 className="w-4 h-4" />
            Danger Zone
          </h3>
          <p className="text-[11px] text-slate-400 mt-1">Permanently wipe all network telemetry data and analysis statistics for your account.</p>
        </div>
        
        <div className="flex flex-col gap-3">
          <button
            onClick={handleResetData}
            disabled={resetting}
            className="w-full bg-rose-900/60 hover:bg-rose-800 text-rose-100 px-4 py-3 rounded-lg text-xs font-bold transition-all border border-rose-700/50 shadow-sm flex justify-center items-center gap-2 cursor-pointer"
          >
            {resetting ? (
              <span className="flex items-center gap-2">
                <span className="animate-spin w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full"></span>
                Wiping Data...
              </span>
            ) : (
              "Hard Reset Account Statistics"
            )}
          </button>
          
          {resetMessage && (
            <div className={`text-[11px] p-2 rounded text-center font-medium ${resetMessage.type === 'success' ? 'bg-emerald-900/50 text-emerald-400' : 'bg-rose-900/50 text-rose-400'}`}>
              {resetMessage.text}
            </div>
          )}
        </div>
      </div>

    </div>
  );
};

export default Settings;
