import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';

const API = 'http://localhost:8000';

// ── helpers ──────────────────────────────────────────────────────────────────
const sev = (s) => {
  const map = { CRITICAL: '#f85149', HIGH: '#f0883e', MEDIUM: '#d29922', LOW: '#3fb950' };
  return map[s] || '#8b949e';
};
const sevBg = (s) => {
  const map = { CRITICAL: 'rgba(248,81,73,.15)', HIGH: 'rgba(240,136,62,.15)', MEDIUM: 'rgba(210,153,34,.15)', LOW: 'rgba(63,185,80,.15)' };
  return map[s] || 'rgba(139,148,158,.1)';
};
const fmt = (iso) => iso ? new Date(iso).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
const fmtFull = (iso) => iso ? new Date(iso).toLocaleString('fr-FR') : '—';
const getFlag = (c) => c ? String.fromCodePoint(...[...c.toUpperCase()].map(x => 0x1f1a5 + x.charCodeAt())) : '';

// ── tiny components ───────────────────────────────────────────────────────────
const Badge = ({ sev: s, label }) => (
  <span style={{
    background: sevBg(s), color: sev(s), border: `1px solid ${sev(s)}44`,
    borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
    letterSpacing: '.04em', textTransform: 'uppercase'
  }}>{label || s}</span>
);

const StatCard = ({ icon, label, value, sub, color = '#388bfd', pulse }) => (
  <div style={{
    background: 'var(--bg-card)', border: '1px solid var(--border)',
    borderRadius: 12, padding: '20px 24px', position: 'relative', overflow: 'hidden',
    transition: 'border-color .2s',
  }}
    onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--border-glow)'}
    onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
  >
    <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${color}, transparent)` }} />
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
      <div>
        <p style={{ color: 'var(--text-secondary)', fontSize: 12, fontWeight: 500, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '.06em' }}>{label}</p>
        <p style={{ fontSize: 32, fontWeight: 800, color, lineHeight: 1 }}>{value ?? '—'}</p>
        {sub && <p style={{ color: 'var(--text-secondary)', fontSize: 12, marginTop: 6 }}>{sub}</p>}
      </div>
      <span style={{ fontSize: 28, opacity: .6 }}>{icon}</span>
    </div>
    {pulse && <span style={{
      position: 'absolute', top: 16, right: 16, width: 8, height: 8,
      borderRadius: '50%', background: color,
      boxShadow: `0 0 0 0 ${color}`,
      animation: 'pulse 2s infinite'
    }} />}
  </div>
);

// ── MITRE heatmap cell ────────────────────────────────────────────────────────
const MitreCell = ({ tactic, count, max }) => {
  const pct = max ? count / max : 0;
  const col = pct > .7 ? '#f85149' : pct > .4 ? '#f0883e' : pct > .1 ? '#d29922' : '#3fb950';
  return (
    <div title={`${tactic}: ${count}`} style={{
      flex: 1, minWidth: 90,
      background: col + Math.round(pct * 200 + 30).toString(16).padStart(2, '0'),
      border: `1px solid ${col}44`, borderRadius: 8, padding: '10px 8px', textAlign: 'center',
      cursor: 'default', transition: 'transform .15s',
    }}
      onMouseEnter={e => e.currentTarget.style.transform = 'scale(1.04)'}
      onMouseLeave={e => e.currentTarget.style.transform = 'scale(1)'}
    >
      <p style={{ fontSize: 18, fontWeight: 800, color: col }}>{count}</p>
      <p style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 3, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{tactic || 'Unknown'}</p>
    </div>
  );
};

// ── custom tooltip ────────────────────────────────────────────────────────────
const ChartTip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: '#0d1929', border: '1px solid #388bfd44', borderRadius: 8, padding: '10px 14px' }}>
      <p style={{ color: '#8b949e', fontSize: 11, marginBottom: 4 }}>{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color, fontWeight: 600, fontSize: 13 }}>{p.name}: {p.value}</p>
      ))}
    </div>
  );
};

// ── MAIN APP ──────────────────────────────────────────────────────────────────
export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [dashboard, setDashboard] = useState(null);
  const [diagnostic, setDiagnostic] = useState(null);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [liveMode, setLiveMode] = useState(true);
  const [selected, setSelected] = useState(null);
  const [alertCount, setAlertCount] = useState(0);
  const [newAlerts, setNewAlerts] = useState([]);
  const [timelineOffset, setTimelineOffset] = useState(0); // minutes backwards
  const prevCount = useRef(0);
  
  // Settings State
  const [activeTab, setActiveTab] = useState('dashboard');
  const [trustedIps, setTrustedIps] = useState([]);
  const [newIp, setNewIp] = useState('');
  const [newIpDesc, setNewIpDesc] = useState('');

  const fetchTrustedIps = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/siem/trusted-ips`);
      setTrustedIps(await res.json());
    } catch (err) {}
  }, []);

  const fetchAll = useCallback(async () => {
    try {
      const [a, d, diag, s] = await Promise.allSettled([
        fetch(`${API}/api/siem/alerts?limit=100`).then(r => r.json()),
        fetch(`${API}/api/siem/dashboard`).then(r => r.json()),
        fetch(`${API}/api/diagnostic`).then(r => r.json()),
        fetch(`${API}/api/stats?days=1`).then(r => r.json()),
      ]);

      // Only update state if the response is valid (has expected fields)
      if (a.status === 'fulfilled' && Array.isArray(a.value?.alerts)) {
        const alertList = a.value.alerts;
        // Never replace a non-empty list with an empty one — keep last known good data
        setAlerts(prev => alertList.length > 0 ? alertList : prev);

        // detect new alerts
        if (prevCount.current > 0 && alertList.length > prevCount.current) {
          const fresh = alertList.slice(0, alertList.length - prevCount.current);
          setNewAlerts(fresh);
          setTimeout(() => setNewAlerts([]), 5000);
        }
        if (alertList.length > 0) {
          prevCount.current = alertList.length;
          setAlertCount(alertList.length);
        }
      }

      if (d.status === 'fulfilled' && !d.value?.error) setDashboard(d.value);
      if (diag.status === 'fulfilled' && !diag.value?.error) setDiagnostic(diag.value);
      if (s.status === 'fulfilled' && !s.value?.error) setStats(s.value);

      setLastRefresh(new Date());
      setLoading(false);
    } catch (err) {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    fetchTrustedIps();
    let iv;
    if (liveMode) iv = setInterval(fetchAll, 5000);
    return () => clearInterval(iv);
  }, [fetchAll, fetchTrustedIps, liveMode]);

  useEffect(() => {
    if (window.Notification && Notification.permission !== "granted") {
      Notification.requestPermission();
    }
  }, []);

  useEffect(() => {
    if (newAlerts.length > 0 && window.Notification && Notification.permission === "granted") {
      newAlerts.forEach(a => {
        if (a.severity.includes('HIGH') || a.severity.includes('CRITICAL')) {
          new Notification("🚨 SentinelIQ Alert: " + a.title, {
            body: `Severity: ${a.severity}\nIP: ${a.src_ip}\nType: ${a.attack_type}`,
            icon: '/favicon.ico'
          });
        }
      });
    }
  }, [newAlerts]);

  const handleBlockIP = async (id, ip) => {
    if (!window.confirm(`⚠️ Are you sure you want to block ${ip} via Windows Defender Firewall?`)) return;
    try {
      const res = await fetch(`${API}/api/siem/alerts/${id}/block`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        alert(`✅ IP ${ip} successfully blocked at the OS Firewall level!\nStatus: ${data.firewall_status}`);
        fetchAll();
      } else {
        alert(`Failed to block: ${data.error || data.detail}`);
      }
    } catch(err) {
      alert("Error contacting backend.");
    }
  };

  const handleUnblockIP = async (id, ip) => {
    if (!window.confirm(`⚠️ Are you sure you want to UNBLOCK ${ip} and remove it from Windows Defender Firewall?`)) return;
    try {
      const res = await fetch(`${API}/api/siem/alerts/${id}/unblock`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        alert(`✅ IP ${ip} successfully UNBLOCKED!`);
        fetchAll();
      } else {
        alert(`Failed to unblock: ${data.error || data.detail}`);
      }
    } catch(err) {
      alert("Error contacting backend.");
    }
  };

  const addTrustedIp = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API}/api/siem/trusted-ips`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip_prefix: newIp, description: newIpDesc })
      });
      if (!res.ok) {
        throw new Error(`Server responded with ${res.status}`);
      }
      setNewIp('');
      setNewIpDesc('');
      fetchTrustedIps();
    } catch (err) {
      alert(`Erreur de connexion a l'API: ${err.message}. Veuillez reessayer.`);
    }
  };

  const deleteTrustedIp = async (id) => {
    await fetch(`${API}/api/siem/trusted-ips/${id}`, { method: 'DELETE' });
    fetchTrustedIps();
  };

  // ── derived data ──────────────────────────────────────────────────────────
  const bySeverity = dashboard?.by_severity || {};
  const byTactic = dashboard?.by_mitre_tactic || [];
  const topIPs = dashboard?.top_source_ips || [];
  const maxTactic = Math.max(...byTactic.map(t => t.count), 1);

  // alert timeline (last 10 buckets of 1 min)
  const timeline = (() => {
    const buckets = {};
    const now = Date.now() - (timelineOffset * 60 * 1000);
    for (let i = 9; i >= 0; i--) {
      const key = new Date(now - i * 60000).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
      buckets[key] = 0;
    }
    alerts.forEach(a => {
      if (!a.created_at) return;
      const isoStr = a.created_at.endsWith('Z') ? a.created_at : a.created_at + 'Z';
      const k = new Date(isoStr).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
      if (k in buckets) buckets[k]++;
    });
    return Object.entries(buckets).map(([time, count]) => ({ time, count }));
  })();

  const attackTypes = (() => {
    const m = {};
    alerts.forEach(a => { m[a.attack_type] = (m[a.attack_type] || 0) + 1; });
    return Object.entries(m).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  })();

  const PIE_COLORS = ['#f85149', '#f0883e', '#d29922', '#3fb950', '#388bfd', '#bc8cff', '#39d0d8'];

  // ── render ────────────────────────────────────────────────────────────────
  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', flexDirection: 'column', gap: 16 }}>
      <div style={{ width: 48, height: 48, border: '3px solid #388bfd44', borderTop: '3px solid #388bfd', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
      <p style={{ color: '#8b949e' }}>Connecting to SentinelIQ…</p>
    </div>
  );

  return (
    <div style={{ minHeight: '100vh', padding: '0 0 40px' }}>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100% { box-shadow: 0 0 0 0 currentColor; } 70% { box-shadow: 0 0 0 8px transparent; } }
        @keyframes slideIn { from { transform: translateX(100%); opacity:0; } to { transform: translateX(0); opacity:1; } }
        .row { display: flex; gap: 16px; flex-wrap: wrap; }
        .col { display: flex; flex-direction: column; gap: 16px; }
        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px 24px; }
        .card-title { font-size: 13px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase; letter-spacing: .06em; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .alert-row { display: grid; grid-template-columns: 80px 1fr 110px 120px 80px; gap: 12px; align-items: center; padding: 10px 16px; border-radius: 8px; cursor: pointer; transition: background .15s; font-size: 13px; }
        .alert-row:hover { background: rgba(56,139,253,.06); }
        .alert-row.selected { background: rgba(56,139,253,.1); border-left: 2px solid #388bfd; }
        .tag { background: rgba(56,139,253,.12); color: #388bfd; border-radius: 4px; padding: '2px 6px'; font-size: 11px; font-weight: 600; }
      `}</style>

      {/* ── NAV ── */}
      <nav style={{
        background: 'rgba(6,11,20,.92)', backdropFilter: 'blur(12px)',
        borderBottom: '1px solid var(--border)', position: 'sticky', top: 0, zIndex: 100,
        padding: '0 32px', display: 'flex', alignItems: 'center', gap: 20, height: 56
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 20 }}>🛡️</span>
          <span style={{ fontWeight: 800, fontSize: 16, background: 'linear-gradient(135deg, #388bfd, #39d0d8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            SentinelIQ
          </span>
          <span style={{ color: 'var(--text-dim)', fontSize: 12 }}>/ {activeTab === 'dashboard' ? 'Live Dashboard' : 'Settings'}</span>
        </div>
        
        <div style={{ display: 'flex', gap: 16, marginLeft: 32 }}>
          <button onClick={() => setActiveTab('dashboard')} style={{ background: 'none', border: 'none', color: activeTab === 'dashboard' ? '#388bfd' : 'var(--text-secondary)', fontWeight: 600, cursor: 'pointer' }}>Dashboard</button>
          <button onClick={() => setActiveTab('settings')} style={{ background: 'none', border: 'none', color: activeTab === 'settings' ? '#388bfd' : 'var(--text-secondary)', fontWeight: 600, cursor: 'pointer' }}>⚙️ Settings</button>
        </div>

        <div style={{ flex: 1 }} />

        {/* live indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {liveMode && <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#3fb950', boxShadow: '0 0 6px #3fb950', display: 'inline-block' }} />}
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
            {liveMode ? 'LIVE' : 'PAUSED'} · {lastRefresh ? fmt(lastRefresh.toISOString()) : '—'}
          </span>
        </div>
        <button onClick={() => setLiveMode(l => !l)} style={{
          background: liveMode ? 'rgba(63,185,80,.15)' : 'rgba(248,81,73,.1)',
          border: `1px solid ${liveMode ? '#3fb950' : '#f85149'}44`,
          color: liveMode ? '#3fb950' : '#f85149',
          borderRadius: 6, padding: '5px 14px', fontSize: 12, fontWeight: 600, cursor: 'pointer'
        }}>{liveMode ? '⏸ Pause' : '▶ Resume'}</button>
        <button onClick={fetchAll} style={{
          background: 'rgba(56,139,253,.12)', border: '1px solid #388bfd44',
          color: '#388bfd', borderRadius: 6, padding: '5px 14px', fontSize: 12, fontWeight: 600, cursor: 'pointer'
        }}>↺ Refresh</button>
      </nav>

      {/* ── NEW ALERT TOAST ── */}
      {newAlerts.map((a, i) => (
        <div key={i} style={{
          position: 'fixed', top: 70 + i * 70, right: 24, zIndex: 200,
          background: '#0d1929', border: '1px solid #f85149',
          borderRadius: 10, padding: '12px 18px', minWidth: 300,
          boxShadow: '0 4px 24px rgba(248,81,73,.3)', animation: 'slideIn .3s ease'
        }}>
          <p style={{ fontSize: 13, fontWeight: 700, color: '#f85149' }}>🚨 New SIEM Alert</p>
          <p style={{ fontSize: 13, fontWeight: 500 }}>{a.attack_type} from {a.src_ip}</p>
        </div>
      ))}

      {activeTab === 'settings' ? (
        <div style={{ maxWidth: 800, margin: '40px auto' }}>
          <h2>⚙️ Platform Settings</h2>
          
          <div className="card" style={{ marginTop: 24 }}>
            <p className="card-title">✅ Trusted IPs (Whitelist)</p>
            <p style={{ color: 'var(--text-dim)', fontSize: 13, marginBottom: 16 }}>
              Add IP prefixes to permanently ignore them from SIEM processing and reduce false positives.
            </p>
            
            <form onSubmit={addTrustedIp} style={{ display: 'flex', gap: 12, marginBottom: 24 }}>
              <input value={newIp} onChange={e => setNewIp(e.target.value)} placeholder="IP Prefix (e.g. 192.168.1.)" required style={{ background: '#0d1929', color: 'white', border: '1px solid var(--border)', padding: '8px 12px', borderRadius: 6, flex: 1 }} />
              <input value={newIpDesc} onChange={e => setNewIpDesc(e.target.value)} placeholder="Description (e.g. Home Router)" required style={{ background: '#0d1929', color: 'white', border: '1px solid var(--border)', padding: '8px 12px', borderRadius: 6, flex: 2 }} />
              <button type="submit" style={{ background: '#3fb950', color: 'white', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 600, cursor: 'pointer' }}>Add IP</button>
            </form>

            <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-dim)' }}>
                  <th style={{ padding: '8px 0' }}>IP Prefix</th>
                  <th>Description</th>
                  <th>Added At</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {trustedIps.map(ip => (
                  <tr key={ip.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td className="mono" style={{ padding: '12px 0' }}>{ip.ip_prefix}</td>
                    <td>{ip.description}</td>
                    <td style={{ color: 'var(--text-dim)' }}>{fmtFull(ip.added_at)}</td>
                    <td><button onClick={() => deleteTrustedIp(ip.id)} style={{ background: 'none', border: 'none', color: '#f85149', cursor: 'pointer', fontWeight: 600 }}>Delete</button></td>
                  </tr>
                ))}
                {trustedIps.length === 0 && <tr><td colSpan="4" style={{ padding: 16, textAlign: 'center', color: 'var(--text-dim)' }}>No trusted IPs configured.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div style={{ padding: '24px 32px', display: 'flex', flexDirection: 'column', gap: 20 }}>

        {/* ── STAT CARDS ── */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
          <StatCard icon="🚨" label="Total Alerts" value={dashboard?.total_alerts ?? alertCount} sub="Lifetime" color="#f85149" pulse={liveMode} />
          <StatCard icon="💀" label="Critical" value={bySeverity['SeverityLevel.CRITICAL'] ?? bySeverity['CRITICAL'] ?? 0} color="#f85149" />
          <StatCard icon="🔥" label="High" value={bySeverity['SeverityLevel.HIGH'] ?? bySeverity['HIGH'] ?? 0} color="#f0883e" />
          <StatCard icon="⚠️" label="Medium" value={bySeverity['SeverityLevel.MEDIUM'] ?? bySeverity['MEDIUM'] ?? 0} color="#d29922" />
          <StatCard icon="🤖" label="ML Classes" value={diagnostic?.model?.classes} sub={`${diagnostic?.model?.features} features`} color="#388bfd" />
          <StatCard icon="🎯" label="Threshold" value={diagnostic ? `${(diagnostic.model?.threshold * 100).toFixed(0)}%` : '—'} sub="Confidence min" color="#39d0d8" />
        </div>

        {/* ── ROW 2: Timeline + Pie ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}>
          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <p className="card-title" style={{ margin: 0 }}>📈 Alert Timeline {timelineOffset > 0 ? `(—${timelineOffset} min)` : '(live)'}</p>
              <div style={{ display: 'flex', gap: 6 }}>
                <button onClick={() => setTimelineOffset(o => o + 10)} style={{ background: 'var(--bg-card2)', color: 'var(--text-secondary)', border: '1px solid var(--border)', borderRadius: 4, cursor: 'pointer', padding: '2px 8px', fontSize: 11 }}>◁ 10m</button>
                <button onClick={() => setTimelineOffset(0)} disabled={timelineOffset === 0} style={{ background: 'var(--bg-card2)', color: timelineOffset === 0 ? 'var(--text-dim)' : '#388bfd', border: '1px solid var(--border)', borderRadius: 4, cursor: timelineOffset === 0 ? 'not-allowed' : 'pointer', padding: '2px 8px', fontSize: 11 }}>Live ▷</button>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={timeline}>
                <defs>
                  <linearGradient id="aGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#388bfd" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#388bfd" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,.04)" />
                <XAxis dataKey="time" tick={{ fill: '#8b949e', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#8b949e', fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, dataMax => Math.max(10, dataMax)]} allowDecimals={false} />
                <Tooltip content={<ChartTip />} />
                <Area type="monotone" dataKey="count" name="Alerts" stroke="#388bfd" fill="url(#aGrad)" strokeWidth={2} dot={{ fill: '#388bfd', r: 3 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="card">
            <p className="card-title">🧩 By Attack Type</p>
            {attackTypes.length === 0
              ? <p style={{ color: 'var(--text-dim)', textAlign: 'center', marginTop: 40 }}>No data yet</p>
              : <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={attackTypes} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} strokeWidth={0}>
                    {attackTypes.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                  </Pie>
                  <Tooltip content={<ChartTip />} />
                  <Legend formatter={v => <span style={{ fontSize: 11, color: '#8b949e' }}>{v}</span>} />
                </PieChart>
              </ResponsiveContainer>
            }
          </div>
        </div>

        {/* ── ROW 3: MITRE heatmap + Top IPs ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}>
          <div className="card">
            <p className="card-title">🗺️ MITRE ATT&CK Tactics (All Time)</p>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {byTactic.length === 0
                ? <p style={{ color: 'var(--text-dim)' }}>No MITRE data yet</p>
                : byTactic.map((t, i) => <MitreCell key={i} tactic={t.tactic} count={t.count} max={maxTactic} />)
              }
            </div>
          </div>

          <div className="card">
            <p className="card-title">🌐 Top Source IPs</p>
            {topIPs.length === 0
              ? <p style={{ color: 'var(--text-dim)' }}>No IP data yet</p>
              : topIPs.slice(0, 8).map((ip, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '7px 0', borderBottom: '1px solid var(--border)' }}>
                  <span className="mono" style={{ fontSize: 12, color: 'var(--text-primary)' }}>{ip.ip || '—'}</span>
                  <span style={{ background: 'rgba(248,81,73,.12)', color: '#f85149', borderRadius: 4, padding: '1px 8px', fontSize: 12, fontWeight: 700 }}>{ip.count}</span>
                </div>
              ))
            }
          </div>
        </div>

        {/* ── ROW 4: Alert table ── */}
        <div className="card" style={{ padding: 0 }}>
          <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 12 }}>
            <p className="card-title" style={{ margin: 0 }}>🚨 Live Alert Feed</p>
            <span style={{ background: 'rgba(248,81,73,.12)', color: '#f85149', borderRadius: 10, padding: '1px 10px', fontSize: 12, fontWeight: 700 }}>{alerts.length}</span>
          </div>

          {/* table header */}
          <div className="alert-row" style={{ color: 'var(--text-dim)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '.05em', cursor: 'default', padding: '8px 16px' }}>
            <span>Severity</span><span>Title</span><span>Attack Type</span><span>Source IP</span><span>Time</span>
          </div>

          <div style={{ maxHeight: 380, overflowY: 'auto' }}>
            {alerts.length === 0
              ? <p style={{ color: 'var(--text-dim)', textAlign: 'center', padding: 32 }}>No alerts yet — run the attack simulator!</p>
              : alerts.map((a, i) => (
                <div key={a.id || i} className={`alert-row${selected?.id === a.id ? ' selected' : ''}`}
                  onClick={() => setSelected(s => s?.id === a.id ? null : a)}>
                  <Badge sev={a.severity?.replace('SeverityLevel.', '')} />
                  <span style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title}</span>
                  <span className="mono" style={{ fontSize: 12, color: '#39d0d8' }}>{a.attack_type}</span>
                  <span className="mono" style={{ fontSize: 12, color: a.is_blocked ? '#f85149' : 'inherit' }}>
                    {a.is_blocked && <span style={{ marginRight: 4 }}>🚫</span>}
                    <span style={{ textDecoration: a.is_blocked ? 'line-through' : 'none' }}>{a.src_ip}</span>
                  </span>
                  <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{fmt(a.created_at)}</span>
                </div>
              ))
            }
          </div>
        </div>

        {/* ── ALERT DETAIL DRAWER ── */}
        {selected && (
          <div className="card" style={{ borderColor: sev(selected.severity?.replace('SeverityLevel.', '')) + '44' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <p style={{ fontWeight: 700, fontSize: 15 }}>🔍 Alert Detail — #{selected.id}</p>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <button onClick={() => handleUnblockIP(selected.id, selected.src_ip)} style={{ background: '#3fb95020', color: '#3fb950', border: '1px solid #3fb950', borderRadius: 6, padding: '4px 12px', cursor: 'pointer', fontWeight: 600 }}>🟢 Unblock IP</button>
                <button onClick={() => handleBlockIP(selected.id, selected.src_ip)} style={{ background: '#f8514920', color: '#f85149', border: '1px solid #f85149', borderRadius: 6, padding: '4px 12px', cursor: 'pointer', fontWeight: 600 }}>🛑 Block IP</button>
                <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 18 }}>✕</button>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16 }}>
              {[
                ['Title', selected.title],
                ['Severity', <Badge sev={selected.severity?.replace('SeverityLevel.', '')} />],
                ['Attack Type', selected.attack_type],
                ['Source IP', <span style={{ color: selected.is_blocked ? '#f85149' : 'inherit' }}>{selected.is_blocked && '🚫 '}<span style={{ textDecoration: selected.is_blocked ? 'line-through' : 'none' }}>{selected.src_ip}</span>{selected.ip_country ? ` ${getFlag(selected.ip_country)} ${selected.ip_country}` : ''}</span>],
                ['ISP / Org', selected.ip_isp || '—'],
                ['Abuse Score', selected.ip_abuse_score !== null && selected.ip_abuse_score !== undefined ? `${selected.ip_abuse_score}/100` : '—'],
                ['MITRE Technique', selected.mitre_technique_id || '—'],
                ['Confidence', selected.confidence ? `${(selected.confidence * 100).toFixed(1)}%` : '—'],
                ['Detected At', fmtFull(selected.created_at)],
              ].map(([k, v], i) => (
                <div key={i} style={{ background: 'var(--bg-card2)', borderRadius: 8, padding: '12px 14px' }}>
                  <p style={{ color: 'var(--text-dim)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '.05em', marginBottom: 4 }}>{k}</p>
                  <p className="mono" style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>{v}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
      )}

      {/* ── footer ── */}
      <p style={{ textAlign: 'center', color: 'var(--text-dim)', fontSize: 12, marginTop: 8 }}>
        SentinelIQ · Threat Detector Dashboard · Auto-refresh every 5s · Backend: localhost:8000
      </p>
    </div>
  );
}