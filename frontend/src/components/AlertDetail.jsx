import React, { useState, useEffect } from 'react';
import {
  BarChart, Bar, Cell, XAxis, Tooltip as RTooltip, ResponsiveContainer,
} from 'recharts';
import { API, apiFetch } from '../api';

const SEV = {
  CRITICAL: { fg: '#f85149', bg: 'rgba(248,81,73,.12)' },
  HIGH:     { fg: '#f0883e', bg: 'rgba(240,136,62,.12)' },
  MEDIUM:   { fg: '#d29922', bg: 'rgba(210,153,34,.12)' },
  LOW:      { fg: '#3fb950', bg: 'rgba(63,185,80,.12)'  },
  INFO:     { fg: '#58a6ff', bg: 'rgba(88,166,255,.12)' },
};
const normSev = s => (s || '').replace('SeverityLevel.', '');

const displayDevice = id => id || '—';

const COUNTRY_NAMES = {
  AF:'Afghanistan',AL:'Albania',DZ:'Algeria',AR:'Argentina',AU:'Australia',
  AT:'Austria',AZ:'Azerbaijan',BD:'Bangladesh',BE:'Belgium',BR:'Brazil',
  BG:'Bulgaria',CA:'Canada',CL:'Chile',CN:'China',CO:'Colombia',HR:'Croatia',
  CZ:'Czechia',DK:'Denmark',EG:'Egypt',EE:'Estonia',FI:'Finland',FR:'France',
  DE:'Germany',GH:'Ghana',GR:'Greece',HK:'Hong Kong',HU:'Hungary',IN:'India',
  ID:'Indonesia',IR:'Iran',IQ:'Iraq',IE:'Ireland',IL:'Israel',IT:'Italy',
  JP:'Japan',JO:'Jordan',KZ:'Kazakhstan',KE:'Kenya',KR:'South Korea',
  KW:'Kuwait',LV:'Latvia',LB:'Lebanon',LT:'Lithuania',LU:'Luxembourg',
  MY:'Malaysia',MX:'Mexico',MA:'Morocco',NL:'Netherlands',NZ:'New Zealand',
  NG:'Nigeria',NO:'Norway',PK:'Pakistan',PE:'Peru',PH:'Philippines',PL:'Poland',
  PT:'Portugal',QA:'Qatar',RO:'Romania',RU:'Russia',SA:'Saudi Arabia',
  SG:'Singapore',SK:'Slovakia',ZA:'South Africa',ES:'Spain',SE:'Sweden',
  CH:'Switzerland',TW:'Taiwan',TH:'Thailand',TN:'Tunisia',TR:'Turkey',
  UA:'Ukraine',AE:'United Arab Emirates',GB:'United Kingdom',
  US:'United States',VN:'Vietnam',
};
const displayCountry = v => {
  if (!v) return '—';
  if (v.length > 2) return v;
  return COUNTRY_NAMES[v.toUpperCase()] || v;
};
const sf = k => (SEV[normSev(k)] || SEV.INFO).fg;
const sb = k => (SEV[normSev(k)] || SEV.INFO).bg;

const MITRE_DESC = {
  'T1498':     'Network Denial of Service — attacker floods network infrastructure to deny availability.',
  'T1499':     'Endpoint DoS — overwhelms target server resources (CPU/memory/sockets).',
  'T1499.002': 'Service Exhaustion Flood — sends excessive requests to exhaust service capacity.',
  'T1110':     'Brute Force — systematic credential guessing against authentication services.',
  'T1110.001': 'Password Guessing — trying common or default passwords against known accounts.',
  'T1046':     'Network Service Discovery — scanning to enumerate open ports and running services.',
  'T1071.001': 'Web Protocols — C2 communication over HTTP/HTTPS to blend with normal web traffic.',
  'T1190':     'Exploit Public-Facing Application — exploiting vulnerabilities in internet-accessible apps.',
  'T1189':     'Drive-by Compromise — XSS or malicious script injection into web pages.',
  'T1552.004': 'Private Keys — Heartbleed exploit to extract private keys and session tokens from memory.',
};

const KILL_CHAIN = {
  'PortScan':              { phase: 'Reconnaissance',     color: '#58a6ff', icon: '🔍' },
  'SSH-Patator':           { phase: 'Credential Access',  color: '#f0883e', icon: '🔑' },
  'FTP-Patator':           { phase: 'Credential Access',  color: '#f0883e', icon: '🔑' },
  'Bot':                   { phase: 'Command & Control',  color: '#9b59b6', icon: '📡' },
  'Infiltration':          { phase: 'Lateral Movement',   color: '#d29922', icon: '🕵️' },
  'DoS Hulk':              { phase: 'Impact',             color: '#f85149', icon: '💥' },
  'DoS slowloris':         { phase: 'Impact',             color: '#f85149', icon: '💥' },
  'DoS Slowhttptest':      { phase: 'Impact',             color: '#f85149', icon: '💥' },
  'DoS GoldenEye':         { phase: 'Impact',             color: '#f85149', icon: '💥' },
  'DDoS':                  { phase: 'Impact',             color: '#f85149', icon: '💥' },
  'Web Attack – Brute Force': { phase: 'Credential Access', color: '#f0883e', icon: '🔑' },
  'Web Attack – XSS':      { phase: 'Execution',          color: '#d29922', icon: '⚡' },
  'Web Attack – Sql Injection': { phase: 'Exfiltration',  color: '#f85149', icon: '🗄️' },
  'Heartbleed':            { phase: 'Credential Access',  color: '#f85149', icon: '💔' },
};

function fmtFull(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', {
    month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
}

function SevBadge({ v }) {
  const k = normSev(v);
  const c = SEV[k] || SEV.INFO;
  return (
    <span style={{
      background: c.bg, color: c.fg,
      border: `1px solid ${c.fg}44`,
      padding: '2px 8px', borderRadius: 3,
      fontSize: 10, fontWeight: 800, letterSpacing: '.08em',
    }}>{k}</span>
  );
}

function ConfBar({ value }) {
  const pct = Math.round((value || 0) * 100);
  const color = value >= .85 ? '#f85149' : value >= .70 ? '#f0883e' : value >= .55 ? '#d29922' : '#3fb950';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <div style={{ flex: 1, background: '#0a0f1a', borderRadius: 4, height: 8, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 4, transition: 'width .3s' }} />
      </div>
      <span style={{ color, fontSize: 15, fontWeight: 800, minWidth: 44, textAlign: 'right' }}>{pct}%</span>
    </div>
  );
}

function inferChain(relatedAlerts) {
  const seen = new Map();
  relatedAlerts.forEach(a => {
    const kc = KILL_CHAIN[a.attack_type];
    if (kc && !seen.has(kc.phase)) seen.set(kc.phase, kc);
  });
  const ORDER = ['Reconnaissance', 'Credential Access', 'Execution', 'Command & Control', 'Lateral Movement', 'Exfiltration', 'Impact'];
  return ORDER.filter(p => seen.has(p)).map(p => seen.get(p));
}

// ── Timeline sub-components ───────────────────────────────────────────────────

function TlStatBox({ label, value, sub, color }) {
  return (
    <div style={{
      flex: 1, background: '#0a0f1a', border: '1px solid #1a2538',
      borderRadius: 8, padding: '10px 14px',
    }}>
      <div style={{ fontSize: 9, color: '#6e7681', textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 20, fontWeight: 800, color, lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: '#4a5568', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

function TlActivityChart({ relAlerts }) {
  const now = Date.now();
  const buckets = {};
  for (let i = 11; i >= 0; i--) {
    const lbl = new Date(now - i * 60000).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
    buckets[lbl] = { time: lbl, count: 0, maxSev: 'LOW' };
  }
  const SEV_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  relAlerts.forEach(a => {
    if (!a.created_at) return;
    const iso = a.created_at.endsWith('Z') ? a.created_at : a.created_at + 'Z';
    const lbl = new Date(iso).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
    if (lbl in buckets) {
      buckets[lbl].count++;
      const sev = normSev(a.severity);
      if (SEV_ORDER.indexOf(sev) > SEV_ORDER.indexOf(buckets[lbl].maxSev))
        buckets[lbl].maxSev = sev;
    }
  });
  const data = Object.values(buckets);
  const sevCol = { CRITICAL: '#f85149', HIGH: '#f0883e', MEDIUM: '#d29922', LOW: '#3fb950' };

  return (
    <div style={{ background: '#0a0f1a', border: '1px solid #1a2538', borderRadius: 8, padding: '12px 14px' }}>
      <div style={{ fontSize: 10, color: '#6e7681', textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 10 }}>
        Activity — last 12 minutes
      </div>
      <ResponsiveContainer width="100%" height={72}>
        <BarChart data={data} barSize={16} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
          <XAxis dataKey="time" tick={{ fill: '#3d4d5f', fontSize: 9 }} axisLine={false} tickLine={false} interval={2} />
          <RTooltip
            cursor={{ fill: 'rgba(255,255,255,.04)' }}
            content={({ active, payload, label }) =>
              active && payload?.length ? (
                <div style={{ background: '#0d1929', border: '1px solid #1e2940', borderRadius: 6, padding: '6px 10px', fontSize: 11, color: '#c9d1d9' }}>
                  <div style={{ color: '#6e7681', marginBottom: 2 }}>{label}</div>
                  <div style={{ fontWeight: 700 }}>{payload[0].value} event{payload[0].value !== 1 ? 's' : ''}</div>
                </div>
              ) : null
            }
          />
          <Bar dataKey="count" radius={[3, 3, 0, 0]}>
            {data.map((entry, i) => (
              <Cell key={i}
                fill={entry.count > 0 ? sevCol[entry.maxSev] : '#1a2538'}
                fillOpacity={entry.count > 0 ? 0.85 : 0.5}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function TlKillChainFlow({ chain }) {
  return (
    <div style={{ background: '#0a0f1a', border: '1px solid #1a2538', borderRadius: 8, padding: '12px 14px' }}>
      <div style={{ fontSize: 10, color: '#6e7681', textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 10 }}>
        Attack Kill Chain
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        {chain.map((c, i) => (
          <React.Fragment key={i}>
            <div style={{
              background: `${c.color}15`, border: `1px solid ${c.color}55`,
              borderRadius: 8, padding: '8px 12px',
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3,
              minWidth: 76, transition: 'transform .15s',
            }}
              onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.borderColor = c.color; }}
              onMouseLeave={e => { e.currentTarget.style.transform = 'none'; e.currentTarget.style.borderColor = `${c.color}55`; }}
            >
              <span style={{ fontSize: 20 }}>{c.icon}</span>
              <span style={{ fontSize: 9, color: c.color, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em', textAlign: 'center', lineHeight: 1.3 }}>
                {c.phase}
              </span>
            </div>
            {i < chain.length - 1 && (
              <span style={{ color: '#2d3f57', fontSize: 16 }}>→</span>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

function TlEventCard({ a, isThis, isExpanded, onToggle }) {
  const k   = normSev(a.severity);
  const kc  = KILL_CHAIN[a.attack_type];
  const pct = Math.round((a.confidence || 0) * 100);
  const confColor = pct >= 85 ? '#f85149' : pct >= 70 ? '#f0883e' : '#3fb950';

  return (
    <div
      onClick={onToggle}
      style={{
        borderLeft: `3px solid ${isThis ? sf(k) : isExpanded ? `${sf(k)}66` : '#1e2940'}`,
        background: isThis ? `${sb(k)}` : isExpanded ? '#0d1929' : 'transparent',
        borderRadius: '0 8px 8px 0',
        marginBottom: 3,
        cursor: 'pointer',
        transition: 'background .12s',
      }}
      onMouseEnter={e => { if (!isThis && !isExpanded) e.currentTarget.style.background = 'rgba(255,255,255,.03)'; }}
      onMouseLeave={e => { if (!isThis && !isExpanded) e.currentTarget.style.background = 'transparent'; }}
    >
      {/* ── Always-visible header row ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 14px' }}>
        <div style={{
          width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
          background: isThis ? sf(k) : '#0a0f1a',
          border: `2px solid ${sf(k)}`,
          boxShadow: isThis ? `0 0 8px ${sf(k)}88` : 'none',
          transition: 'box-shadow .2s',
        }} />
        <span style={{ color: '#4a5568', fontSize: 10, fontFamily: 'monospace', flexShrink: 0, minWidth: 118 }}>
          {fmtFull(a.created_at)}
        </span>
        <SevBadge v={a.severity} />
        <span style={{ color: '#e6edf3', fontSize: 12, fontWeight: 600, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {a.attack_type}
        </span>
        {kc && (
          <span style={{ color: kc.color, fontSize: 10, fontWeight: 600, flexShrink: 0 }}>
            {kc.icon} {kc.phase}
          </span>
        )}
        {isThis && (
          <span style={{ background: 'rgba(248,81,73,.15)', color: '#f85149', fontSize: 9, padding: '2px 7px', borderRadius: 3, fontWeight: 800, flexShrink: 0 }}>
            THIS
          </span>
        )}
        <span style={{
          color: '#3d4d5f', fontSize: 11, flexShrink: 0,
          transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
          transition: 'transform .2s',
          display: 'inline-block',
        }}>▾</span>
      </div>

      {/* ── Expanded details ── */}
      {isExpanded && (
        <div style={{ padding: '0 14px 14px 32px', animation: 'tlSlide .15s ease' }}>
          <div style={{
            background: '#060b14', border: '1px solid #1a2538', borderRadius: 6,
            padding: '12px 14px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px 24px',
          }}>
            {[
              ['Source IP',  a.src_ip || '—',                   'mono'],
              ['MITRE ID',   a.mitre_technique_id || '—',       'blue'],
              ['Tactic',     a.mitre_tactic || '—',             ''],
              ['Rule ID',    a.rule_id || '—',                  'mono'],
              ['Country',    a.ip_country || '—',               ''],
              ['Abuse Score', a.ip_abuse_score != null ? `${a.ip_abuse_score}/100` : '—', ''],
            ].map(([lbl, val, style]) => (
              <div key={lbl}>
                <div style={{ color: '#4a5568', fontSize: 9, textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 2 }}>{lbl}</div>
                <div style={{
                  color: style === 'blue' ? '#58a6ff' : '#c9d1d9',
                  fontFamily: style === 'mono' ? 'monospace' : 'inherit',
                  fontSize: 12,
                }}>{val}</div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ flex: 1, background: '#0a0f1a', borderRadius: 3, height: 5, overflow: 'hidden' }}>
              <div style={{
                height: '100%', width: `${pct}%`,
                background: confColor, borderRadius: 3,
                transition: 'width .4s ease',
              }} />
            </div>
            <span style={{ color: confColor, fontSize: 12, fontWeight: 700, minWidth: 36 }}>{pct}%</span>
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────

export default function AlertDetail({ alert, onClose, onRefresh }) {
  const [tab, setTab] = useState('overview');
  const [context, setContext] = useState(null);
  const [loading, setLoading] = useState(false);
  const [actionMsg, setActionMsg] = useState('');
  const [actionErr, setActionErr] = useState(false);
  const [tlFilter, setTlFilter] = useState('ALL');
  const [expandedId, setExpandedId] = useState(null);
  const [confirmBlock, setConfirmBlock] = useState(false);

  useEffect(() => {
    if (!alert) return;
    setTab('overview');
    setContext(null);
    setActionMsg('');
    setConfirmBlock(false);
    loadContext();
  }, [alert?.id]);

  async function loadContext() {
    setLoading(true);
    try {
      const res = await apiFetch(`${API}/api/siem/alerts/${alert.id}/context`);
      const data = await res.json();
      setContext(data);
    } catch {}
    setLoading(false);
  }

  async function act(url, method = 'POST', label) {
    setActionMsg(`${label}...`);
    setActionErr(false);
    try {
      const res = await apiFetch(url, { method });
      const data = await res.json();
      if (data.success || data.status === 'success') {
        setActionMsg(`Done: ${data.blocked_ip || data.unblocked_ip || label}`);
        onRefresh?.();
      } else {
        setActionMsg(data.detail || data.error || 'Failed');
        setActionErr(true);
      }
    } catch (e) {
      setActionMsg('Request failed');
      setActionErr(true);
    }
  }

  const relAlerts = context?.related_alerts || [];
  const relLogs   = context?.related_logs   || [];
  const chain     = inferChain([alert, ...relAlerts]);

  const TABS = [
    { id: 'overview',  label: 'Overview' },
    { id: 'timeline',  label: `Timeline${relAlerts.length ? ` (${relAlerts.length})` : ''}` },
    { id: 'logs',      label: `Raw Logs${relLogs.length ? ` (${relLogs.length})` : ''}` },
    { id: 'actions',   label: 'Actions' },
  ];

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', animation: 'slideIn .2s ease' }}>

      {/* ── Header ── */}
      <div style={{ padding: '14px 20px 10px', borderBottom: '1px solid #1a2538', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 8 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <SevBadge v={alert.severity} />
              <span style={{ color: '#e6edf3', fontWeight: 700, fontSize: 15 }}>{alert.attack_type}</span>
            </div>
            <div style={{ color: '#8b949e', fontSize: 12, fontFamily: 'monospace' }}>
              {alert.src_ip}
              {alert.mitre_technique_id && (
                <span style={{ color: '#58a6ff' }}> · {alert.mitre_technique_id}</span>
              )}
              <span style={{ color: '#4a5568' }}> · {fmtFull(alert.created_at)}</span>
            </div>
          </div>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', color: '#6e7681',
            cursor: 'pointer', fontSize: 22, lineHeight: 1, padding: '0 4px',
          }}>×</button>
        </div>

        {/* Attack chain banner */}
        {chain.length > 1 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap', marginTop: 6 }}>
            <span style={{ color: '#6e7681', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.08em', marginRight: 2 }}>Chain:</span>
            {chain.map((c, i) => (
              <React.Fragment key={i}>
                <span style={{
                  background: `${c.color}18`, color: c.color,
                  border: `1px solid ${c.color}44`,
                  borderRadius: 4, padding: '1px 7px', fontSize: 10, fontWeight: 600,
                }}>
                  {c.icon} {c.phase}
                </span>
                {i < chain.length - 1 && <span style={{ color: '#2d3d52', fontSize: 14 }}>→</span>}
              </React.Fragment>
            ))}
          </div>
        )}
      </div>

      {/* ── Tab bar ── */}
      <div style={{ display: 'flex', borderBottom: '1px solid #1a2538', flexShrink: 0 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding: '8px 16px', background: 'none', border: 'none', cursor: 'pointer',
            color: tab === t.id ? '#58a6ff' : '#6e7681',
            borderBottom: `2px solid ${tab === t.id ? '#58a6ff' : 'transparent'}`,
            fontSize: 12, fontWeight: tab === t.id ? 600 : 400,
            transition: 'color .15s',
          }}>{t.label}</button>
        ))}
      </div>

      {/* ── Content ── */}
      <div style={{ flex: 1, overflow: 'auto', padding: '16px 20px' }}>

        {/* OVERVIEW */}
        {tab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div>
              <div style={{ color: '#6e7681', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 8 }}>Detection Confidence</div>
              <ConfBar value={alert.confidence} />
            </div>

            <div style={{ background: '#0d1929', border: '1px solid #1e2940', borderRadius: 8, padding: 14 }}>
              <div style={{ color: '#6e7681', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 10 }}>Flow Details</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px 16px' }}>
                {[
                  ['Source IP',    alert.src_ip,                  'mono'],
                  ['Destination IP', alert.dst_ip && alert.dst_ip !== '0.0.0.0' ? alert.dst_ip : '—', 'mono'],
                  ['Device',       displayDevice(alert.device_id),  'device'],
                  ['Attack Type',  alert.attack_type],
                  ['MITRE ID',     alert.mitre_technique_id,       'blue'],
                  ['Tactic',       alert.mitre_tactic],
                  ['Country',      displayCountry(alert.ip_country)],
                  ['ISP',          alert.ip_isp || '—'],
                  ['Abuse Score',  alert.ip_abuse_score != null ? `${alert.ip_abuse_score}/100` : '—'],
                  ['Firewall',     alert.is_blocked ? '🔒 Blocked' : '⚡ Active'],
                  ['Known Threat', alert.is_known_malicious ? '⚠ Yes' : 'No'],
                  ['Detected',     fmtFull(alert.created_at)],
                ].map(([k, v, style]) => (
                  <div key={k}>
                    <div style={{ color: '#6e7681', fontSize: 10, marginBottom: 2 }}>{k}</div>
                    {style === 'device' ? (
                      <span style={{
                        display: 'inline-block',
                        background: 'rgba(120,92,255,.15)', color: '#a78bfa',
                        border: '1px solid rgba(120,92,255,.35)',
                        borderRadius: 4, padding: '1px 7px',
                        fontSize: 11, fontFamily: 'monospace', fontWeight: 700,
                      }}>{v || '—'}</span>
                    ) : (
                      <div style={{
                        color: style === 'mono' ? '#e6edf3' : style === 'blue' ? '#58a6ff' : '#c9d1d9',
                        fontFamily: style === 'mono' ? 'monospace' : 'inherit',
                        fontWeight: style === 'blue' ? 700 : 400,
                        fontSize: 12,
                      }}>{v || '—'}</div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {alert.mitre_technique_id && (
              <div style={{ background: 'rgba(88,166,255,0.05)', border: '1px solid #1e3a5a', borderRadius: 8, padding: 14 }}>
                <div style={{ color: '#6e7681', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 8 }}>MITRE ATT&CK</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <span style={{ background: '#1e3a5a', color: '#58a6ff', padding: '2px 8px', borderRadius: 4, fontSize: 12, fontWeight: 700, fontFamily: 'monospace' }}>
                    {alert.mitre_technique_id}
                  </span>
                  <span style={{ color: '#e6edf3', fontWeight: 600, fontSize: 13 }}>{alert.mitre_technique_name}</span>
                </div>
                <p style={{ color: '#8b949e', fontSize: 12, lineHeight: 1.65, margin: 0 }}>
                  {MITRE_DESC[alert.mitre_technique_id] || `Attack technique mapped to MITRE ATT&CK ${alert.mitre_technique_id}.`}
                </p>
              </div>
            )}
          </div>
        )}

        {/* TIMELINE */}
        {tab === 'timeline' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <style>{`
              @keyframes tlSlide {
                from { opacity: 0; transform: translateY(-6px); }
                to   { opacity: 1; transform: translateY(0); }
              }
            `}</style>

            {loading && (
              <div style={{ color: '#6e7681', padding: '40px 0', textAlign: 'center', fontSize: 12 }}>
                Loading timeline…
              </div>
            )}

            {!loading && relAlerts.length === 0 && (
              <div style={{ color: '#6e7681', padding: '60px 0', textAlign: 'center', fontSize: 12 }}>
                No historical events for{' '}
                <span style={{ fontFamily: 'monospace', color: '#8b949e' }}>{alert.src_ip}</span>.
              </div>
            )}

            {!loading && relAlerts.length > 0 && (() => {
              // ── derived data ──────────────────────────────────────────
              const times = relAlerts
                .map(a => a.created_at ? new Date(a.created_at.endsWith('Z') ? a.created_at : a.created_at + 'Z').getTime() : null)
                .filter(Boolean);
              const spanMs  = times.length > 1 ? Math.max(...times) - Math.min(...times) : 0;
              const spanStr = spanMs < 60000
                ? `${Math.round(spanMs / 1000)}s`
                : spanMs < 3600000
                  ? `${Math.round(spanMs / 60000)}m`
                  : `${(spanMs / 3600000).toFixed(1)}h`;
              const types = new Set(relAlerts.map(a => a.attack_type)).size;
              const critCount = relAlerts.filter(a => normSev(a.severity) === 'CRITICAL').length;

              const SEV_LEVELS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
              const sevColors  = { CRITICAL: '#f85149', HIGH: '#f0883e', MEDIUM: '#d29922', LOW: '#3fb950', ALL: '#58a6ff' };

              const filtered = tlFilter === 'ALL'
                ? relAlerts
                : relAlerts.filter(a => normSev(a.severity) === tlFilter);

              return (
                <>
                  {/* ── Stat strip ── */}
                  <div style={{ display: 'flex', gap: 8 }}>
                    <TlStatBox label="Events"       value={relAlerts.length}  color="#58a6ff" />
                    <TlStatBox label="Attack Types" value={types}             color="#f0883e" />
                    <TlStatBox label="Critical"     value={critCount}         color="#f85149" />
                    <TlStatBox label="Time Span"    value={spanStr}           color="#3fb950" sub={`${relAlerts.length} events`} />
                  </div>

                  {/* ── Activity bar chart ── */}
                  <TlActivityChart relAlerts={relAlerts} />

                  {/* ── Kill chain ── */}
                  {chain.length > 1 && <TlKillChainFlow chain={chain} />}

                  {/* ── Severity filter ── */}
                  <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ color: '#6e7681', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.07em', marginRight: 2 }}>
                      Filter:
                    </span>
                    {SEV_LEVELS.map(sev => (
                      <button key={sev} onClick={() => setTlFilter(sev)} style={{
                        padding: '3px 10px', borderRadius: 4, cursor: 'pointer', fontSize: 10, fontWeight: 700,
                        border: `1px solid ${tlFilter === sev ? sevColors[sev] : '#1e2940'}`,
                        background: tlFilter === sev ? `${sevColors[sev]}18` : 'transparent',
                        color: tlFilter === sev ? sevColors[sev] : '#6e7681',
                        transition: 'all .12s',
                      }}>
                        {sev}{sev !== 'ALL' ? ` (${relAlerts.filter(a => normSev(a.severity) === sev).length})` : ''}
                      </button>
                    ))}
                    <span style={{ marginLeft: 'auto', color: '#4a5568', fontSize: 10 }}>
                      {filtered.length} / {relAlerts.length}
                    </span>
                  </div>

                  {/* ── Event list ── */}
                  <div style={{
                    background: '#070d1a', border: '1px solid #1a2538', borderRadius: 8,
                    overflow: 'hidden',
                  }}>
                    {/* header */}
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: '24px 118px 70px 1fr 110px 44px 36px',
                      gap: 8, padding: '6px 14px',
                      borderBottom: '1px solid #1a2538',
                      color: '#3d4d5f', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.08em',
                    }}>
                      <span />
                      <span>Time</span>
                      <span>Severity</span>
                      <span>Attack Type</span>
                      <span>Phase</span>
                      <span style={{ textAlign: 'right' }}>Conf.</span>
                      <span />
                    </div>

                    {filtered.length === 0 && (
                      <div style={{ padding: '24px', color: '#6e7681', textAlign: 'center', fontSize: 12 }}>
                        No events match this filter.
                      </div>
                    )}

                    {filtered.map(a => (
                      <TlEventCard
                        key={a.id}
                        a={a}
                        isThis={a.id === alert.id}
                        isExpanded={expandedId === a.id}
                        onToggle={() => setExpandedId(expandedId === a.id ? null : a.id)}
                      />
                    ))}
                  </div>
                </>
              );
            })()}
          </div>
        )}

        {/* RAW LOGS */}
        {tab === 'logs' && (
          <div>
            {loading && <div style={{ color: '#6e7681', padding: '30px 0' }}>Loading logs...</div>}
            {!loading && relLogs.length === 0 && (
              <div style={{ color: '#6e7681', padding: '50px 0', textAlign: 'center' }}>
                No raw logs found for <span style={{ fontFamily: 'monospace', color: '#8b949e' }}>{alert.src_ip}</span>.
                <br />
                <span style={{ fontSize: 12, marginTop: 6, display: 'block' }}>Logs are written when flows pass through the ML pipeline.</span>
              </div>
            )}
            {!loading && relLogs.map(log => (
              <div key={log.id} style={{
                background: '#0a0f1a', border: '1px solid #1a2538',
                borderRadius: 6, padding: '10px 14px', marginBottom: 6,
                fontFamily: 'monospace', fontSize: 11,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5 }}>
                  <span style={{ color: '#4a5568' }}>{fmtFull(log.timestamp)}</span>
                  <span style={{ background: '#1e2940', color: '#8b949e', padding: '0 5px', borderRadius: 3, fontSize: 10 }}>{log.source}</span>
                  {log.event_type && log.event_type !== 'normal_traffic' && (
                    <span style={{ color: '#d29922', fontWeight: 600, fontSize: 10 }}>{log.event_type}</span>
                  )}
                </div>
                <div style={{ color: '#c9d1d9', marginBottom: log.predicted_label ? 4 : 0 }}>
                  <span style={{ color: '#58a6ff' }}>{log.src_ip}</span>
                  {log.src_port ? <span style={{ color: '#6e7681' }}>:{log.src_port}</span> : ''}
                  <span style={{ color: '#3d4d5f' }}> ──→ </span>
                  <span style={{ color: '#79c0ff' }}>{log.dst_ip}</span>
                  {log.dst_port ? <span style={{ color: '#6e7681' }}>:{log.dst_port}</span> : ''}
                  {log.protocol && <span style={{ color: '#4a5568' }}> [{log.protocol}]</span>}
                </div>
                {log.predicted_label && (
                  <div style={{ color: log.predicted_label !== 'BENIGN' ? '#f85149' : '#3fb950' }}>
                    label=<b>{log.predicted_label}</b>
                    {log.confidence != null && ` conf=${Math.round(log.confidence * 100)}%`}
                  </div>
                )}
                {log.message && (
                  <div style={{ color: '#8b949e', marginTop: 4, wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>
                    {log.message}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* ACTIONS */}
        {tab === 'actions' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {actionMsg && (
              <div style={{
                background: actionErr ? 'rgba(248,81,73,0.08)' : 'rgba(63,185,80,0.08)',
                border: `1px solid ${actionErr ? '#f8514944' : '#3fb95044'}`,
                borderRadius: 6, padding: '10px 14px',
                color: actionErr ? '#f85149' : '#3fb950',
                fontSize: 13,
              }}>{actionMsg}</div>
            )}

            {/* Block / Unblock button */}
            {!confirmBlock ? (
              <button onClick={() => {
                if (alert.is_blocked) {
                  act(`${API}/api/siem/alerts/${alert.id}/unblock`, 'POST', 'Unblocking');
                } else {
                  setConfirmBlock(true);
                }
              }} style={{
                background: alert.is_blocked ? '#0d1929' : 'rgba(248,81,73,0.07)',
                border: `1px solid ${alert.is_blocked ? '#1e2940' : '#f8514933'}`,
                borderRadius: 8, padding: '12px 16px', cursor: 'pointer', textAlign: 'left',
                transition: 'all .15s',
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = alert.is_blocked ? '#3d4d5f' : '#f85149'; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = alert.is_blocked ? '#1e2940' : '#f8514933'; }}
              >
                <div style={{ color: alert.is_blocked ? '#e6edf3' : '#f85149', fontWeight: 600, fontSize: 13, marginBottom: 4 }}>
                  {alert.is_blocked ? '🔓 Unblock IP' : '🔒 Block IP'}
                </div>
                <div style={{ color: '#6e7681', fontSize: 11 }}>
                  {alert.is_blocked
                    ? `Remove Windows Firewall rule for ${alert.src_ip}`
                    : `Add inbound block rule for ${alert.src_ip} via Windows Firewall`}
                </div>
              </button>
            ) : (
              /* ── Inline confirmation panel ── */
              <div style={{
                background: 'rgba(248,81,73,0.06)',
                border: '1px solid #f8514966',
                borderRadius: 10,
                padding: '16px 18px',
                display: 'flex', flexDirection: 'column', gap: 12,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: 22 }}>🔒</span>
                  <div>
                    <div style={{ color: '#f85149', fontWeight: 700, fontSize: 14 }}>
                      Block this IP address?
                    </div>
                    <div style={{ color: '#8b949e', fontSize: 11, marginTop: 2 }}>
                      This action will add a Windows Firewall inbound block rule.
                    </div>
                  </div>
                </div>

                {/* IP + attack info */}
                <div style={{
                  background: '#0a0f1a',
                  border: '1px solid #1a2538',
                  borderRadius: 7,
                  padding: '10px 14px',
                  display: 'flex', flexDirection: 'column', gap: 6,
                }}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span style={{ color: '#6e7681', fontSize: 11, width: 80 }}>IP Address</span>
                    <span style={{ color: '#58a6ff', fontFamily: 'monospace', fontSize: 13, fontWeight: 700 }}>{alert.src_ip}</span>
                  </div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span style={{ color: '#6e7681', fontSize: 11, width: 80 }}>Attack Type</span>
                    <span style={{ color: '#f0883e', fontSize: 12, fontWeight: 600 }}>{alert.attack_type || '—'}</span>
                  </div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span style={{ color: '#6e7681', fontSize: 11, width: 80 }}>Severity</span>
                    <SevBadge v={alert.severity} />
                  </div>
                </div>

                <div style={{ color: '#8b949e', fontSize: 11, lineHeight: 1.6 }}>
                  ⚠️ The IP will be blocked at the firewall level. This will drop all inbound traffic from this address.
                  You can unblock it later from this same panel.
                </div>

                {/* Confirm / Cancel buttons */}
                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    onClick={() => {
                      setConfirmBlock(false);
                      act(`${API}/api/siem/alerts/${alert.id}/block`, 'POST', 'Blocking');
                    }}
                    style={{
                      flex: 1, padding: '10px 0', borderRadius: 7, cursor: 'pointer',
                      background: '#f85149', border: 'none',
                      color: '#fff', fontWeight: 700, fontSize: 13,
                      transition: 'opacity .15s',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.opacity = '.85'; }}
                    onMouseLeave={e => { e.currentTarget.style.opacity = '1'; }}
                  >
                    Yes, Block IP
                  </button>
                  <button
                    onClick={() => setConfirmBlock(false)}
                    style={{
                      flex: 1, padding: '10px 0', borderRadius: 7, cursor: 'pointer',
                      background: 'transparent', border: '1px solid #2d3f57',
                      color: '#8b949e', fontWeight: 600, fontSize: 13,
                      transition: 'border-color .15s, color .15s',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = '#58a6ff'; e.currentTarget.style.color = '#58a6ff'; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = '#2d3f57'; e.currentTarget.style.color = '#8b949e'; }}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {/* Acknowledge button */}
            <button onClick={() => act(`${API}/api/alerts/${alert.id}/acknowledge`, 'POST', 'Acknowledging')}
              style={{
                background: '#0d1929', border: '1px solid #1e2940',
                borderRadius: 8, padding: '12px 16px', cursor: 'pointer', textAlign: 'left',
                transition: 'all .15s',
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = '#3d4d5f'; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = '#1e2940'; }}
            >
              <div style={{ color: '#e6edf3', fontWeight: 600, fontSize: 13, marginBottom: 4 }}>✅ Acknowledge Alert</div>
              <div style={{ color: '#6e7681', fontSize: 11 }}>Mark this alert as reviewed — removes it from the active queue</div>
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
