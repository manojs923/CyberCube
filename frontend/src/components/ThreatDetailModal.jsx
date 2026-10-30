import React, { useState, useEffect } from 'react';
import { 
  X, ShieldAlert, CheckCircle, Search, RefreshCw, Cpu, ShieldBan, 
  Globe, Tag, FileDown, Terminal, BarChart3, Copy, Check, RotateCcw, 
  Sliders, Send, AlertTriangle, ArrowRight 
} from 'lucide-react';
import axios from 'axios';

const ThreatDetailModal = ({ threat, onClose, onUpdateStatus }) => {
  const [status, setStatus] = useState(threat.status);
  const [isBlocked, setIsBlocked] = useState(threat.is_blocked || false);
  const [updating, setUpdating] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  
  // AI Explanation state
  const [explanation, setExplanation] = useState(threat.ai_explanation);
  const [explaining, setExplaining] = useState(false);

  // XAI (SHAP) state
  const [xaiData, setXaiData] = useState(null);
  const [loadingXai, setLoadingXai] = useState(false);
  const [showXai, setShowXai] = useState(false);

  // Counterfactual What-If Sandbox state
  const [showWhatIf, setShowWhatIf] = useState(false);
  const [cfData, setCfData] = useState(null);
  const [runningCf, setRunningCf] = useState(false);
  const [cfSliders, setCfSliders] = useState({
    packet_len: threat.features?.fwd_pkt_len_mean || 60,
    syn_count: threat.features?.syn_flag_cnt || 2,
    flow_packets_s: threat.features?.flow_pkts_s || 50
  });

  // SIEM Webhook forward state
  const [forwardingWebhook, setForwardingWebhook] = useState(false);
  const [webhookSuccess, setWebhookSuccess] = useState(false);

  // Firewall / IDS Rules state
  const [rules, setRules] = useState(null);
  const [showRules, setShowRules] = useState(false);
  const [loadingRules, setLoadingRules] = useState(false);
  const [copiedRule, setCopiedRule] = useState(null);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

  // Helper function to build headers
  const getAuthHeaders = () => {
    const token = sessionStorage.getItem('soc_session_token');
    const tenantKey = sessionStorage.getItem('soc_tenant_key');
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    if (tenantKey) headers['X-Tenant-Key'] = tenantKey;
    return headers;
  };

  const handleStatusChange = async (newStatus) => {
    setUpdating(true);
    setStatus(newStatus);
    try {
      const headers = getAuthHeaders();
      const res = await axios.patch(`${API_URL}/threats/${threat.id}`, {
        status: newStatus
      }, { headers });
      onUpdateStatus(threat.id, res.data);
    } catch (err) {
      console.error("Failed to update status:", err);
      setStatus(threat.status);
      alert("Failed to update threat status.");
    } finally {
      setUpdating(false);
    }
  };

  const handleBlockIP = async (enforceOs = false) => {
    setUpdating(true);
    try {
      const headers = getAuthHeaders();
      const res = await axios.post(`${API_URL}/threats/${threat.id}/block?enforce_os=${enforceOs}`, {}, { headers });
      setIsBlocked(true);
      setStatus("resolved");
      onUpdateStatus(threat.id, res.data);
    } catch (err) {
      console.error("Failed to execute IP block:", err);
      alert("Failed to contain attacker IP.");
    } finally {
      setUpdating(false);
    }
  };

  const handleUnblockIP = async () => {
    setUpdating(true);
    try {
      const headers = getAuthHeaders();
      const res = await axios.post(`${API_URL}/threats/${threat.id}/unblock`, {}, { headers });
      setIsBlocked(false);
      setStatus("open");
      onUpdateStatus(threat.id, res.data);
    } catch (err) {
      console.error("Failed to rollback quarantine:", err);
      alert("Failed to unblock IP.");
    } finally {
      setUpdating(false);
    }
  };

  const handleFetchXai = async () => {
    if (xaiData) {
      setShowXai(!showXai);
      return;
    }
    setLoadingXai(true);
    try {
      const headers = getAuthHeaders();
      const res = await axios.get(`${API_URL}/threats/${threat.id}/xai`, { headers });
      setXaiData(res.data);
      setShowXai(true);
    } catch (err) {
      console.error("Failed to load XAI explanation:", err);
      alert("XAI feature attribution is currently unavailable.");
    } finally {
      setLoadingXai(false);
    }
  };

  const handleRunCounterfactual = async (overrideSliders = cfSliders) => {
    setRunningCf(true);
    try {
      const headers = getAuthHeaders();
      const res = await axios.post(`${API_URL}/threats/${threat.id}/counterfactual`, {
        perturbations: {
          fwd_pkt_len_mean: parseFloat(overrideSliders.packet_len),
          syn_flag_cnt: parseFloat(overrideSliders.syn_count),
          flow_pkts_s: parseFloat(overrideSliders.flow_packets_s)
        }
      }, { headers });
      setCfData(res.data);
    } catch (err) {
      console.error("Counterfactual error:", err);
    } finally {
      setRunningCf(false);
    }
  };

  const handleForwardToWebhook = async () => {
    const savedUrl = localStorage.getItem('soc_webhook_url');
    if (!savedUrl) {
      alert("Please configure a SIEM or Webhook URL in Settings first!");
      return;
    }
    setForwardingWebhook(true);
    try {
      const headers = getAuthHeaders();
      await axios.post(`${API_URL}/notifications/webhook`, {
        webhook_url: savedUrl,
        threat_id: threat.id
      }, { headers });
      setWebhookSuccess(true);
      setTimeout(() => setWebhookSuccess(false), 3000);
    } catch (err) {
      alert("Failed to forward alert to configured SIEM webhook.");
    } finally {
      setForwardingWebhook(false);
    }
  };

  const handleFetchRules = async () => {
    if (rules) {
      setShowRules(!showRules);
      return;
    }
    setLoadingRules(true);
    try {
      const headers = getAuthHeaders();
      const res = await axios.get(`${API_URL}/threats/${threat.id}/rules`, { headers });
      setRules(res.data);
      setShowRules(true);
    } catch (err) {
      console.error("Failed to load containment rules:", err);
      alert("Firewall rules generator is currently unavailable.");
    } finally {
      setLoadingRules(false);
    }
  };

  const handleDownloadPdf = async () => {
    setDownloadingPdf(true);
    try {
      const headers = getAuthHeaders();
      const res = await axios.get(`${API_URL}/threats/${threat.id}/report/pdf`, {
        responseType: 'blob',
        headers
      });
      const blob = new Blob([res.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `soc_incident_report_${threat.id}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      console.error("PDF download failed:", err);
      alert("Failed to download SOC Incident Report.");
    } finally {
      setDownloadingPdf(false);
    }
  };

  const copyToClipboard = (text, ruleKey) => {
    navigator.clipboard.writeText(text);
    setCopiedRule(ruleKey);
    setTimeout(() => setCopiedRule(null), 2000);
  };

  const getSeverityBadge = (sev) => {
    switch (sev.toLowerCase()) {
      case 'critical': return 'bg-rose-500/10 text-cyber-red border-rose-500/20';
      case 'high': return 'bg-orange-500/10 text-cyber-orange border-orange-500/20';
      case 'medium': return 'bg-amber-500/10 text-cyber-yellow border-amber-500/20';
      default: return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-end overflow-hidden bg-slate-950/80 backdrop-blur-sm transition-opacity duration-300">
      <div className="w-full max-w-xl h-full bg-slate-900 border-l border-slate-800 p-6 flex flex-col shadow-2xl relative animate-slide-over">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
          <div className="flex items-center gap-2.5">
            <div className={`w-8 h-8 rounded-lg border flex items-center justify-center ${getSeverityBadge(threat.severity)}`}>
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-slate-100">Threat Investigation</h2>
                {threat.mitre_id && threat.mitre_id !== 'None' && (
                  <span className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-sky-950/40 text-sky-400 border border-sky-500/20">
                    <Tag className="w-3 h-3" />
                    <span>MITRE {threat.mitre_id}</span>
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-500">Incident ID: #{threat.id}</p>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            {/* SIEM Webhook Dispatch */}
            <button
              onClick={handleForwardToWebhook}
              disabled={forwardingWebhook}
              title="Forward to configured SIEM Webhook (Slack / Discord)"
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 text-xs font-semibold transition-all cursor-pointer shadow"
            >
              {webhookSuccess ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Send className="w-3.5 h-3.5 text-emerald-400" />
              )}
              <span>{webhookSuccess ? "Forwarded!" : "SIEM"}</span>
            </button>

            {/* One-Click PDF Export Button */}
            <button
              onClick={handleDownloadPdf}
              disabled={downloadingPdf}
              title="Download Formal SOC Incident Report (PDF)"
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 text-xs font-semibold transition-all cursor-pointer shadow"
            >
              {downloadingPdf ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-sky-400" />
              ) : (
                <FileDown className="w-3.5 h-3.5 text-sky-400" />
              )}
              <span>PDF Report</span>
            </button>

            <button 
              onClick={onClose}
              className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content (Scrollable) */}
        <div className="flex-1 overflow-y-auto space-y-5 pr-1">
          
          {/* Metadata Cards */}
          <div className="grid grid-cols-2 gap-3.5">
            <div className="bg-slate-950/40 border border-slate-800/80 p-3 rounded-lg">
              <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Source Address</span>
              <p className="font-mono text-sm text-slate-200 mt-1 font-semibold">{threat.source_ip}</p>
              {threat.geo_country && (
                <div className="flex items-center gap-1 text-[11px] text-slate-400 mt-1">
                  <Globe className="w-3 h-3 text-sky-400 shrink-0" />
                  <span>{threat.geo_city}, {threat.geo_country}</span>
                </div>
              )}
            </div>
            <div className="bg-slate-950/40 border border-slate-800/80 p-3 rounded-lg">
              <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Destination Asset</span>
              <p className="font-mono text-sm text-slate-200 mt-1 font-semibold">{threat.destination_ip}</p>
              <span className="text-[11px] text-slate-400 block mt-1">
                Port {threat.features?.port || 443} ({threat.features?.protocol || 'TCP'})
              </span>
            </div>
            <div className="bg-slate-950/40 border border-slate-800/80 p-3 rounded-lg">
              <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Detection Confidence</span>
              <p className="text-sm text-slate-200 mt-1 font-semibold">{(threat.confidence * 100).toFixed(2)}%</p>
            </div>
            <div className="bg-slate-950/40 border border-slate-800/80 p-3 rounded-lg">
              <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Severity Classification</span>
              <span className={`inline-block mt-1 px-2 py-0.5 rounded text-xs font-bold uppercase border ${getSeverityBadge(threat.severity)}`}>
                {threat.severity}
              </span>
            </div>
          </div>

          {/* Classification & Active Containment Action */}
          <div className="glass-panel p-4 bg-slate-950/20 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">AI Classification</span>
                <p className="text-base font-bold text-slate-100 mt-0.5">{threat.attack_type}</p>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400">Status:</span>
                <select
                  value={status}
                  disabled={updating}
                  onChange={(e) => handleStatusChange(e.target.value)}
                  className={`bg-slate-900 border border-slate-800 text-xs font-semibold rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-slate-700 cursor-pointer ${
                    status === 'resolved' ? 'text-emerald-400' :
                    status === 'investigating' ? 'text-sky-400' : 'text-rose-400'
                  }`}
                >
                  <option value="open" className="text-rose-400 bg-slate-900 font-semibold">Open Alert</option>
                  <option value="investigating" className="text-sky-400 bg-slate-900 font-semibold">Investigating</option>
                  <option value="resolved" className="text-emerald-400 bg-slate-900 font-semibold">Resolved</option>
                </select>
                {updating && <RefreshCw className="w-3.5 h-3.5 text-slate-400 animate-spin" />}
              </div>
            </div>

            {/* Active Firewall Actions & Rules */}
            <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2">
              <div>
                <span className="text-xs font-semibold text-slate-300 block">Firewall Containment:</span>
                <span className="text-[10px] text-slate-500">Autonomous quarantine or packet drop for adversary IP.</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleFetchRules}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer"
                >
                  <Terminal className="w-3.5 h-3.5 text-sky-400" />
                  <span>{showRules ? "Hide Rules" : "Firewall Rules"}</span>
                </button>

                {isBlocked ? (
                  <div className="flex items-center gap-2">
                    <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-950/30 border border-emerald-500/20 text-emerald-400 text-xs font-bold">
                      <CheckCircle className="w-3.5 h-3.5" />
                      <span>Quarantined</span>
                    </div>
                    <button
                      onClick={handleUnblockIP}
                      disabled={updating}
                      className="bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/30 text-xs font-semibold px-2.5 py-1.5 rounded-lg flex items-center gap-1.5 transition-all cursor-pointer shadow"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      <span>Rollback</span>
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => handleBlockIP(false)}
                    disabled={updating}
                    className="bg-rose-600 hover:bg-rose-500 text-slate-100 text-xs font-semibold px-3 py-1.5 rounded-lg flex items-center gap-1.5 shadow-md transition-all cursor-pointer"
                  >
                    <ShieldBan className="w-3.5 h-3.5" />
                    <span>Block Attacker IP</span>
                  </button>
                )}
              </div>
            </div>

            {/* Firewall Rules Drawer */}
            {showRules && rules && (
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2 text-xs font-mono animate-fade-in">
                <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">Generated Containment Signatures</span>
                
                <div className="space-y-1">
                  <div className="flex justify-between items-center text-[10px] text-slate-500">
                    <span>Windows Netsh:</span>
                    <button onClick={() => copyToClipboard(rules.windows_netsh, 'netsh')} className="hover:text-slate-300 flex items-center gap-1">
                      {copiedRule === 'netsh' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <pre className="p-1.5 bg-slate-900 rounded border border-slate-850 overflow-x-auto text-[11px] text-slate-300 select-all">
                    {rules.windows_netsh}
                  </pre>
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between items-center text-[10px] text-slate-500">
                    <span>Linux IPtables:</span>
                    <button onClick={() => copyToClipboard(rules.linux_iptables, 'iptables')} className="hover:text-slate-300 flex items-center gap-1">
                      {copiedRule === 'iptables' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <pre className="p-1.5 bg-slate-900 rounded border border-slate-850 overflow-x-auto text-[11px] text-slate-300 select-all">
                    {rules.linux_iptables}
                  </pre>
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between items-center text-[10px] text-slate-500">
                    <span>Suricata Signature:</span>
                    <button onClick={() => copyToClipboard(rules.suricata_rule, 'suricata')} className="hover:text-slate-300 flex items-center gap-1">
                      {copiedRule === 'suricata' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <pre className="p-1.5 bg-slate-900 rounded border border-slate-850 overflow-x-auto text-[11px] text-slate-300 select-all">
                    {rules.suricata_rule}
                  </pre>
                </div>
              </div>
            )}
          </div>

          {/* Explainable AI (SHAP) + What-If Counterfactual Sandbox */}
          <div className="glass-panel p-4 space-y-3 bg-slate-950/40 border border-slate-800/80">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sky-400">
                <BarChart3 className="w-4 h-4" />
                <h3 className="text-xs font-bold uppercase tracking-wider">Explainable AI (SHAP Waterfall)</h3>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setShowWhatIf(!showWhatIf)}
                  className="text-xs font-semibold px-2 py-1 rounded bg-slate-800 hover:bg-slate-750 text-slate-300 border border-slate-700 transition-all flex items-center gap-1 cursor-pointer"
                >
                  <Sliders className="w-3 h-3 text-sky-400" />
                  <span>{showWhatIf ? "Hide Sandbox" : "What-If Sandbox"}</span>
                </button>
                <button
                  type="button"
                  onClick={handleFetchXai}
                  disabled={loadingXai}
                  className="text-xs font-semibold px-2.5 py-1 rounded bg-sky-600/20 hover:bg-sky-600/30 text-sky-300 border border-sky-500/30 transition-all flex items-center gap-1 cursor-pointer"
                >
                  {loadingXai && <RefreshCw className="w-3 h-3 animate-spin" />}
                  <span>{showXai ? "Hide Attributions" : "Calculate SHAP"}</span>
                </button>
              </div>
            </div>

            {/* WHAT-IF COUNTERFACTUAL SANDBOX */}
            {showWhatIf && (
              <div className="p-3 bg-slate-900/90 rounded-lg border border-sky-500/20 space-y-3 text-xs animate-fade-in">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-200 uppercase text-[10px] tracking-wider flex items-center gap-1.5">
                    <Sliders className="w-3.5 h-3.5 text-sky-400" />
                    <span>Counterfactual Perturbation Simulator</span>
                  </span>
                  <button
                    onClick={() => handleRunCounterfactual()}
                    disabled={runningCf}
                    className="px-2 py-0.5 rounded bg-sky-600 hover:bg-sky-500 text-white text-[10px] font-bold transition-all cursor-pointer shadow"
                  >
                    {runningCf ? "Simulating..." : "Run Perturbation"}
                  </button>
                </div>
                <p className="text-[11px] text-slate-400">
                  Tweak packet properties to test if model prediction flips towards <b>Benign</b>:
                </p>

                <div className="grid grid-cols-3 gap-2.5">
                  <div className="space-y-1">
                    <label className="text-[10px] text-slate-400 block font-mono">Pkt Len ({cfSliders.packet_len}B)</label>
                    <input
                      type="range"
                      min="20"
                      max="1500"
                      value={cfSliders.packet_len}
                      onChange={(e) => setCfSliders({ ...cfSliders, packet_len: e.target.value })}
                      className="w-full accent-sky-500 cursor-pointer"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-[10px] text-slate-400 block font-mono">SYN Flags ({cfSliders.syn_count})</label>
                    <input
                      type="range"
                      min="0"
                      max="1000"
                      value={cfSliders.syn_count}
                      onChange={(e) => setCfSliders({ ...cfSliders, syn_count: e.target.value })}
                      className="w-full accent-sky-500 cursor-pointer"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-[10px] text-slate-400 block font-mono">Packets/s ({cfSliders.flow_packets_s})</label>
                    <input
                      type="range"
                      min="1"
                      max="3000"
                      value={cfSliders.flow_packets_s}
                      onChange={(e) => setCfSliders({ ...cfSliders, flow_packets_s: e.target.value })}
                      className="w-full accent-sky-500 cursor-pointer"
                    />
                  </div>
                </div>

                {cfData && (
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800 space-y-1.5 font-mono text-[11px]">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Original Verdict:</span>
                      <span className="font-bold text-rose-400">{cfData.baseline.predicted_class} ({(cfData.baseline.confidence * 100).toFixed(1)}%)</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Perturbed Verdict:</span>
                      <span className={`font-bold ${cfData.counterfactual.predicted_class === 'Benign' ? 'text-emerald-400' : 'text-amber-400'}`}>
                        {cfData.counterfactual.predicted_class} ({(cfData.counterfactual.confidence * 100).toFixed(1)}%)
                      </span>
                    </div>
                    <div className="pt-1 border-t border-slate-850 flex items-center justify-between text-[10px]">
                      <span className="text-slate-500">Classification Shift:</span>
                      <span className={`font-bold ${cfData.decision_changed ? 'text-emerald-400' : 'text-slate-400'}`}>
                        {cfData.decision_changed ? "Decision Reversed via Perturbation!" : "Robust (No Decision Flip)"}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            )}

            {showXai && xaiData && (
              <div className="space-y-2.5 pt-1 animate-fade-in">
                <p className="text-[11px] text-slate-400 italic">
                  Mathematical contribution weights driving model decision for class <b>{xaiData.target_class}</b>:
                </p>
                <div className="space-y-1.5">
                  {xaiData.top_features?.map((feat, idx) => {
                    const isPositive = feat.shap_value >= 0;
                    const barWidth = Math.min(100, Math.round(feat.abs_impact * 400));
                    return (
                      <div key={idx} className="flex items-center justify-between text-[11px] font-mono gap-2">
                        <span className="w-36 truncate text-slate-300" title={feat.feature}>
                          {feat.feature} ({feat.value})
                        </span>
                        <div className="flex-1 bg-slate-950 rounded-full h-2 overflow-hidden flex items-center">
                          <div 
                            className={`h-full rounded-full transition-all duration-500 ${
                              isPositive ? 'bg-rose-500' : 'bg-emerald-500'
                            }`}
                            style={{ width: `${barWidth}%` }}
                          />
                        </div>
                        <span className={`w-16 text-right font-bold ${isPositive ? 'text-rose-400' : 'text-emerald-400'}`}>
                          {isPositive ? `+${feat.shap_value}` : feat.shap_value}
                        </span>
                      </div>
                    );
                  })}
                </div>
                <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-slate-800">
                  <span className="flex items-center gap-1 text-rose-400 font-semibold">
                    <span className="w-2 h-2 rounded-full bg-rose-500 inline-block"></span> Pushed towards Attack
                  </span>
                  <span className="flex items-center gap-1 text-emerald-400 font-semibold">
                    <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block"></span> Pushed towards Benign
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Gemini AI Explanation Layer */}
          <div className="glass-panel p-4 border-emerald-500/15 bg-emerald-950/5">
            <div className="flex items-center justify-between gap-2 text-emerald-400 mb-2.5">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4" />
                <h3 className="text-xs font-bold uppercase tracking-wider">AI Assistant Forensic Triage</h3>
              </div>
              {!explanation && !explaining && (
                <button
                  onClick={async () => {
                    setExplaining(true);
                    try {
                      const headers = getAuthHeaders();
                      const res = await axios.post(`${API_URL}/threats/${threat.id}/explain`, {}, { headers });
                      setExplanation(res.data.ai_explanation);
                      onUpdateStatus(threat.id, res.data);
                    } catch (err) {
                      console.error("AI Explanation failed:", err);
                      alert("AI Explanation service is currently unavailable. Using templates.");
                    } finally {
                      setExplaining(false);
                    }
                  }}
                  className="bg-emerald-600 hover:bg-emerald-500 text-slate-100 text-[10px] font-bold uppercase px-2.5 py-1 rounded transition-all flex items-center gap-1 cursor-pointer shadow"
                >
                  <Cpu className="w-3.5 h-3.5" />
                  <span>Explain Alert</span>
                </button>
              )}
            </div>
            
            {explaining ? (
              <div className="flex items-center gap-2 py-2">
                <div className="w-3.5 h-3.5 border-2 border-emerald-800 border-t-emerald-400 rounded-full animate-spin"></div>
                <p className="text-xs text-slate-400 font-medium animate-pulse">Consulting Gemini AI assistant...</p>
              </div>
            ) : (
              <p className="text-xs text-slate-300 leading-relaxed font-medium">
                {explanation ? explanation : "Click 'Explain Alert' to generate a plain-English SOC briefing powered by Gemini 1.5 Flash."}
              </p>
            )}
          </div>

          {/* CIC-IDS2017 Statistical Flow Indicators */}
          {threat.features && (
            <div className="space-y-3">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">CICFlowMeter Telemetry Metrics</h3>
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-slate-950/20 border border-slate-800 p-3 rounded-lg text-center">
                  <span className="text-[10px] text-slate-500 block">Flow Duration</span>
                  <span className="text-sm font-bold text-slate-200 mt-1 block">
                    {threat.features.flow_duration ? `${(threat.features.flow_duration / 1000).toFixed(2)}s` : '0s'}
                  </span>
                </div>
                <div className="bg-slate-950/20 border border-slate-800 p-3 rounded-lg text-center">
                  <span className="text-[10px] text-slate-500 block">Fwd / Bwd Packets</span>
                  <span className="text-sm font-bold text-slate-200 mt-1 block font-mono">
                    {threat.features.tot_fwd_pkts || 0} / {threat.features.tot_bwd_pkts || 0}
                  </span>
                </div>
                <div className="bg-slate-950/20 border border-slate-800 p-3 rounded-lg text-center">
                  <span className="text-[10px] text-slate-500 block">Flow Rate (B/s)</span>
                  <span className="text-sm font-bold text-slate-200 mt-1 block font-mono">
                    {threat.features.flow_byts_s ? `${Math.round(threat.features.flow_byts_s).toLocaleString()} B/s` : '0 B/s'}
                  </span>
                </div>
                <div className="bg-slate-950/20 border border-slate-800 p-3 rounded-lg text-center">
                  <span className="text-[10px] text-slate-500 block">TCP Flags (SYN / RST)</span>
                  <span className="text-sm font-bold text-slate-200 mt-1 block font-mono text-xs">
                    SYN: {threat.features.syn_flag_cnt || 0} | RST: {threat.features.rst_flag_cnt || 0}
                  </span>
                </div>
                <div className="bg-slate-950/20 border border-slate-800 p-3 rounded-lg text-center">
                  <span className="text-[10px] text-slate-500 block">Down/Up Ratio</span>
                  <span className="text-sm font-bold text-slate-200 mt-1 block font-mono">
                    {threat.features.down_up_ratio || 0}
                  </span>
                </div>
                <div className="bg-slate-950/20 border border-slate-800 p-3 rounded-lg text-center">
                  <span className="text-[10px] text-slate-500 block">Mean Packet Size</span>
                  <span className="text-sm font-bold text-slate-200 mt-1 block font-mono">
                    {threat.features.fwd_pkt_len_mean ? `${threat.features.fwd_pkt_len_mean} B` : '0 B'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Raw JSON Features Accordion */}
          <div className="border border-slate-800 rounded-lg overflow-hidden">
            <button
              onClick={() => setShowRaw(!showRaw)}
              className="w-full flex items-center justify-between p-3 bg-slate-950/40 hover:bg-slate-950/60 text-xs font-semibold text-slate-400 transition-colors"
            >
              <span>RAW FLOW TELEMETRY (JSON)</span>
              <Search className="w-3.5 h-3.5" />
            </button>
            {showRaw && (
              <pre className="p-4 bg-slate-950 text-[10px] font-mono text-slate-400 overflow-x-auto max-h-[220px] border-t border-slate-800 select-all">
                {JSON.stringify(threat, null, 2)}
              </pre>
            )}
          </div>

        </div>

      </div>
    </div>
  );
};

export default ThreatDetailModal;
