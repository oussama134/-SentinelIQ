/**
 * SentinelIQ dashboard shell.
 *
 * This component orchestrates the live SOC overview, charts, alert details,
 * log explorer, and configuration panels shown in the frontend.
 */
import React, { useState, useEffect, useCallback, useRef } from 'react';
import AlertDetail from './components/AlertDetail';
import LogExplorer from './components/LogExplorer';
import ConfigPanel from './components/ConfigPanel';
import ThreatGlobe from './components/ThreatGlobe';
import {
  BarChart, Bar, Cell, AreaChart, Area,
  XAxis, YAxis, Tooltip, ResponsiveContainer,
} from 'recharts';

const API = 'http://localhost:8000';

// ── palette ──────────────────────────────────────────────────────────────────
const SEV = {
  CRITICAL: { fg: '#f85149', bg: 'rgba(248,81,73,.13)' },
  HIGH:     { fg: '#f0883e', bg: 'rgba(240,136,62,.13)' },
  MEDIUM:   { fg: '#d29922', bg: 'rgba(210,153,34,.13)' },
  LOW:      { fg: '#3fb950', bg: 'rgba(63,185,80,.13)'  },
};
const sf = k => (SEV[k] || SEV.LOW).fg;
const sb = k => (SEV[k] || SEV.LOW).bg;

// ── helpers ──────────────────────────────────────────────────────────────────
function relTime(iso) {
  if (!iso) return '—';
  const d = Math.floor((Date.now() - new Date(iso.endsWith('Z') ? iso : iso + 'Z')) / 1000);
  if (d < 5)   return 'just now';
  if (d < 60)  return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  return `${Math.floor(d / 3600)}h ago`;
}
function clockNow() {
  return new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function normSev(s) {
  return (s || '').replace('SeverityLevel.', '');
}

// ── tiny components ───────────────────────────────────────────────────────────
const SevBadge = ({ s }) => {
  const k = normSev(s);
  return (
    <span style={{
      background: sb(k), color: sf(k), border: `1px solid ${sf(k)}44`,
      borderRadius: 4, padding: '1px 7px', fontSize: 10, fontWeight: 700,
      letterSpacing: '.06em', textTransform: 'uppercase', flexShrink: 0,
    }}>{k}</span>
  );
};

const ConfDot = ({ v }) => {
  const pct = v != null ? Math.round(v * 100) : null;
  const c = pct == null ? '#6e7681' : pct >= 90 ? '#f85149' : pct >= 70 ? '#f0883e' : '#3fb950';
  return (
    <span style={{ color: c, fontFamily: 'monospace', fontSize: 11 }}>
      {pct != null ? `${pct}%` : '—'}
    </span>
  );
};

// ── StatsBar ─────────────────────────────────────────────────────────────────
function StatsBar({ dashboard, alertCount }) {
  const bySev = dashboard?.by_severity || {};
  const crit  = bySev['SeverityLevel.CRITICAL'] ?? bySev['CRITICAL'] ?? 0;
  const high  = bySev['SeverityLevel.HIGH']     ?? bySev['HIGH']     ?? 0;
  const med   = bySev['SeverityLevel.MEDIUM']   ?? bySev['MEDIUM']   ?? 0;
  const low   = bySev['SeverityLevel.LOW']      ?? bySev['LOW']      ?? 0;

  const items = [
    { label: 'Total Alerts', value: dashboard?.total_alerts ?? alertCount, color: '#58a6ff' },
    { label: 'Critical',     value: crit, color: '#f85149' },
    { label: 'High',         value: high, color: '#f0883e' },
    { label: 'Medium',       value: med,  color: '#d29922' },
    { label: 'Low',          value: low,  color: '#3fb950' },
  ];

  return (
    <div style={{ display: 'flex', gap: 1, borderBottom: '1px solid #1a2538', flexShrink: 0 }}>
      {items.map(({ label, value, color }) => (
        <div key={label} style={{
          flex: 1, padding: '10px 20px', borderRight: '1px solid #1a2538',
          display: 'flex', flexDirection: 'column', gap: 2,
        }}>
          <span style={{ fontSize: 10, color: '#6e7681', textTransform: 'uppercase', letterSpacing: '.07em' }}>{label}</span>
          <span style={{ fontSize: 22, fontWeight: 800, color, lineHeight: 1 }}>{value}</span>
        </div>
      ))}
    </div>
  );
}

// ── AlertRow ─────────────────────────────────────────────────────────────────
function AlertRow({ alert: a, selected, onClick, isNew }) {
  const k = normSev(a.severity);
  return (
    <div
      onClick={onClick}
      style={{
        display: 'flex', flexDirection: 'column', gap: 4,
        padding: '10px 14px', cursor: 'pointer',
        borderLeft: `3px solid ${selected ? sf(k) : isNew ? sf(k) : 'transparent'}`,
        borderBottom: '1px solid #0a0f1a',
        background: selected
          ? `${sb(k)}`
          : isNew ? `${sb(k)}` : 'transparent',
        transition: 'background .1s',
        animation: isNew ? 'flashIn .4s ease' : 'none',
      }}
      onMouseEnter={e => { if (!selected) e.currentTarget.style.background = 'rgba(255,255,255,.03)'; }}
      onMouseLeave={e => { if (!selected) e.currentTarget.style.background = isNew ? sb(k) : 'transparent'; }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
        <SevBadge s={a.severity} />
        <span style={{ color: '#6e7681', fontSize: 10, marginLeft: 'auto', flexShrink: 0 }}>
          {relTime(a.created_at)}
        </span>
      </div>
      <div style={{ fontSize: 12, fontWeight: 600, color: '#c9d1d9', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {a.title}
      </div>
      <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'nowrap', overflow: 'hidden' }}>
        <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#58a6ff', flexShrink: 0 }}>{a.src_ip || '—'}</span>
        {a.dst_ip && a.dst_ip !== '0.0.0.0' && a.dst_ip !== '' && (
          <>
            <span style={{ color: '#3d4d5f', fontSize: 10, flexShrink: 0 }}>→</span>
            <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#7d8fa8', flexShrink: 0 }}>{a.dst_ip}</span>
          </>
        )}
        <span style={{ color: '#3d4d5f', flexShrink: 0 }}>·</span>
        <span style={{ fontSize: 11, color: '#6e7681', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.attack_type}</span>
        <span style={{ marginLeft: 'auto', flexShrink: 0 }}><ConfDot v={a.confidence} /></span>
      </div>
    </div>
  );
}

// ── MITRE Panel ──────────────────────────────────────────────────────────────
function MitrePanel({ dashboard }) {
  const byTactic = dashboard?.by_mitre_tactic || [];
  const topIPs   = dashboard?.top_source_ips   || [];
  const maxCount = Math.max(...byTactic.map(t => t.count), 1);

  const tactics = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
    'Exfiltration', 'Impact',
  ];

  const tacticMap = {};
  byTactic.forEach(t => { tacticMap[t.tactic] = t.count; });

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <div style={{ color: '#58a6ff', fontSize: 13, fontWeight: 700, marginBottom: 16, textTransform: 'uppercase', letterSpacing: '.08em' }}>
          MITRE ATT&amp;CK Kill Chain Coverage
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {tactics.map(tactic => {
            const count = tacticMap[tactic] || 0;
            const pct   = count / maxCount;
            const col   = count === 0 ? '#1e2940'
              : pct > .6 ? '#f85149' : pct > .3 ? '#f0883e' : '#d29922';
            return (
              <div key={tactic} style={{
                background: count > 0 ? `${col}22` : '#0d1929',
                border: `1px solid ${col}`,
                borderRadius: 8, padding: '12px 14px', minWidth: 120, flex: '1 1 120px',
                transition: 'transform .15s', cursor: count > 0 ? 'default' : 'default',
              }}
                onMouseEnter={e => { if (count > 0) e.currentTarget.style.transform = 'translateY(-2px)'; }}
                onMouseLeave={e => e.currentTarget.style.transform = 'none'}
              >
                <div style={{ fontSize: 18, fontWeight: 800, color: count > 0 ? col : '#2d3f57' }}>{count || 0}</div>
                <div style={{ fontSize: 10, color: count > 0 ? '#8b949e' : '#2d3f57', marginTop: 4, lineHeight: 1.3 }}>{tactic}</div>
              </div>
            );
          })}
        </div>
      </div>

      <div>
        <div style={{ color: '#58a6ff', fontSize: 13, fontWeight: 700, marginBottom: 12, textTransform: 'uppercase', letterSpacing: '.08em' }}>
          Top Threat Sources
        </div>
        <div style={{ background: '#0d1929', border: '1px solid #1e2940', borderRadius: 8, overflow: 'hidden' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', gap: 16, padding: '8px 16px', borderBottom: '1px solid #1a2538', color: '#6e7681', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.07em' }}>
            <span>Source IP</span><span>Alerts</span><span>Country</span>
          </div>
          {topIPs.length === 0 && (
            <div style={{ padding: '24px', color: '#6e7681', textAlign: 'center', fontSize: 12 }}>No threat data yet</div>
          )}
          {topIPs.slice(0, 12).map((ip, i) => (
            <div key={i} style={{
              display: 'grid', gridTemplateColumns: '1fr auto auto', gap: 16,
              padding: '10px 16px', borderBottom: '1px solid #0a0f1a',
              fontSize: 12,
            }}>
              <span style={{ fontFamily: 'monospace', color: '#58a6ff' }}>{ip.ip || '—'}</span>
              <span style={{ color: '#f85149', fontWeight: 700 }}>{ip.count}</span>
              <span style={{ color: '#6e7681' }}>{ip.country || '—'}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Alert Timeline ────────────────────────────────────────────────────────────
function AlertTimeline({ alerts }) {
  const [viewOffset,  setViewOffset]  = useState(0);
  const [panelHeight, setPanelHeight] = useState(243);
  const isLive = viewOffset === 0;
  const MAX_OFFSET = 60;

  const handleDragStart = (e) => {
    e.preventDefault();
    const startY = e.clientY;
    const startH = panelHeight;
    const onMove = (ev) => {
      setPanelHeight(Math.max(140, Math.min(520, startH + ev.clientY - startY)));
    };
    const onUp = () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup',   onUp);
      document.body.style.userSelect = '';
      document.body.style.cursor     = '';
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup',   onUp);
    document.body.style.userSelect = 'none';
    document.body.style.cursor     = 'ns-resize';
  };

  const chartHeight = Math.max(40, panelHeight - 100);

  const SEV_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const SEV_COLOR = { CRITICAL: '#f85149', HIGH: '#f0883e', MEDIUM: '#d29922', LOW: '#3fb950' };

  // windowEnd = the rightmost minute of the visible 12-min window
  const windowEnd = Date.now() - viewOffset * 60000;

  const buckets = {};
  for (let i = 11; i >= 0; i--) {
    const k = new Date(windowEnd - i * 60000).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
    buckets[k] = { time: k, count: 0, maxSev: 'LOW' };
  }

  alerts.forEach(a => {
    if (!a.created_at) return;
    const iso = a.created_at.endsWith('Z') ? a.created_at : a.created_at + 'Z';
    const ts  = new Date(iso).getTime();
    // only events inside this 12-min window (+ 30s grace for clock skew)
    if (ts < windowEnd - 11 * 60000 || ts > windowEnd + 30000) return;
    const k = new Date(iso).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
    if (!(k in buckets)) return;
    buckets[k].count++;
    const sev = normSev(a.severity);
    if (SEV_ORDER.indexOf(sev) > SEV_ORDER.indexOf(buckets[k].maxSev))
      buckets[k].maxSev = sev;
  });

  const data        = Object.values(buckets);
  const peak        = Math.max(...data.map(d => d.count), 1);
  const windowTotal = data.reduce((s, d) => s + d.count, 0);
  const hotBucket   = data.reduce((a, b) => b.count > a.count ? b : a, data[0]);

  const navBtn = (label, onClick, disabled, title) => (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      style={{
        background: disabled ? 'transparent' : 'rgba(88,166,255,.08)',
        border: '1px solid ' + (disabled ? '#1a2538' : '#2d3f57'),
        color: disabled ? '#2d3f57' : '#8b949e',
        borderRadius: 4, padding: '2px 7px', fontSize: 11,
        cursor: disabled ? 'default' : 'pointer', lineHeight: 1.4,
        transition: 'background .12s, color .12s',
      }}
    >{label}</button>
  );

  return (
    <div style={{
      margin: '12px 12px 0',
      background: '#070d1a',
      border: '1px solid ' + (isLive ? '#1e2940' : '#2d3f57'),
      borderRadius: 10,
      padding: '14px 16px 0',
      flexShrink: 0,
      height: panelHeight,
      display: 'flex', flexDirection: 'column',
      transition: 'border-color .2s',
      overflow: 'hidden',
    }}>
      {/* ── header row ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: '#c9d1d9', letterSpacing: '.04em' }}>
          Alert Activity
        </span>

        {/* live pulse */}
        {isLive && (
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{
              width: 5, height: 5, borderRadius: '50%', background: '#3fb950',
              animation: 'pulse 1.5s infinite', display: 'inline-block',
            }} />
            <span style={{ fontSize: 9, color: '#3fb950', fontWeight: 700, letterSpacing: '.06em' }}>LIVE</span>
          </span>
        )}

        <span style={{ fontSize: 10, color: isLive ? '#4a5568' : '#58a6ff' }}>
          {isLive
            ? 'last 12 min'
            : `${viewOffset}:00 – ${viewOffset + 12}:00 min ago`}
        </span>

        <div style={{ flex: 1 }} />

        {/* ── navigation controls ── */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          {navBtn('◀◀', () => setViewOffset(v => Math.min(v + 5, MAX_OFFSET)), viewOffset >= MAX_OFFSET, 'Back 5 minutes')}

          {!isLive && (
            <button
              onClick={() => setViewOffset(0)}
              title="Jump to live"
              style={{
                background: 'rgba(63,185,80,.12)', border: '1px solid #3fb95044',
                color: '#3fb950', borderRadius: 4, padding: '2px 8px',
                fontSize: 10, fontWeight: 700, cursor: 'pointer', letterSpacing: '.05em',
              }}
            >LIVE</button>
          )}

          {navBtn('▶▶', () => setViewOffset(v => Math.max(v - 5, 0)), isLive, 'Forward 5 minutes')}
        </div>

        <span style={{ color: '#2d3f57', fontSize: 12, margin: '0 2px' }}>·</span>

        <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#58a6ff', fontWeight: 700 }}>
          {windowTotal}
        </span>
        <span style={{ fontSize: 10, color: '#4a5568' }}>in view</span>

        {hotBucket.count > 0 && (
          <>
            <span style={{ color: '#2d3f57' }}>·</span>
            <span style={{ fontSize: 10, color: SEV_COLOR[hotBucket.maxSev] }}>
              peak {hotBucket.count} @ {hotBucket.time}
            </span>
          </>
        )}
      </div>

      {/* ── bar chart — height tracks panel size ── */}
      <ResponsiveContainer width="100%" height={chartHeight}>
        <BarChart data={data} barSize={22} margin={{ top: 4, right: 4, left: 0, bottom: 0 }}>
          <XAxis
            dataKey="time"
            tick={{ fill: '#3d4d5f', fontSize: 9 }}
            axisLine={{ stroke: '#1a2538' }}
            tickLine={false}
            interval={1}
          />
          <YAxis hide domain={[0, d => Math.max(d, peak, 3)]} />
          <Tooltip
            cursor={{ fill: 'rgba(255,255,255,.04)' }}
            content={({ active, payload, label }) =>
              active && payload?.length
                ? (
                  <div style={{
                    background: '#0d1929', border: '1px solid #1e2940',
                    borderRadius: 6, padding: '8px 14px', fontSize: 11,
                  }}>
                    <div style={{ color: '#6e7681', marginBottom: 4 }}>{label}</div>
                    {payload[0].value > 0 ? (
                      <>
                        <div style={{ color: SEV_COLOR[payload[0].payload.maxSev], fontWeight: 700 }}>
                          {payload[0].value} alert{payload[0].value !== 1 ? 's' : ''}
                        </div>
                        <div style={{ color: '#4a5568', fontSize: 10, marginTop: 3 }}>
                          worst: {payload[0].payload.maxSev}
                        </div>
                      </>
                    ) : (
                      <div style={{ color: '#3d4d5f' }}>no alerts</div>
                    )}
                  </div>
                ) : null
            }
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {data.map((entry, i) => (
              <Cell
                key={i}
                fill={entry.count > 0 ? SEV_COLOR[entry.maxSev] : '#1a2538'}
                fillOpacity={entry.count > 0 ? 0.85 : 0.5}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      {/* ── footer: severity legend + offset scrubber ── */}
      <div style={{ display: 'flex', alignItems: 'center', marginTop: 8, marginBottom: 10 }}>
        <div style={{ display: 'flex', gap: 14 }}>
          {Object.entries(SEV_COLOR).reverse().map(([sev, col]) => (
            <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <div style={{ width: 8, height: 8, borderRadius: 2, background: col }} />
              <span style={{ fontSize: 9, color: '#4a5568', textTransform: 'uppercase', letterSpacing: '.06em' }}>{sev}</span>
            </div>
          ))}
        </div>
        <div style={{ flex: 1 }} />
        {/* scrubber: click on the track to jump to a specific offset */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 9, color: '#2d3f57' }}>−{MAX_OFFSET}m</span>
          <div
            title="Click to jump to a point in history"
            style={{
              width: 90, height: 4, background: '#1a2538', borderRadius: 2, cursor: 'pointer',
              position: 'relative',
            }}
            onClick={e => {
              const rect = e.currentTarget.getBoundingClientRect();
              const pct  = 1 - (e.clientX - rect.left) / rect.width;
              setViewOffset(Math.round(pct * MAX_OFFSET));
            }}
          >
            <div style={{
              position: 'absolute',
              left: `${(1 - viewOffset / MAX_OFFSET) * 100}%`,
              top: -3, transform: 'translateX(-50%)',
              width: 10, height: 10, borderRadius: '50%',
              background: isLive ? '#3fb950' : '#58a6ff',
              border: '2px solid #070d1a',
              transition: 'left .15s, background .2s',
              pointerEvents: 'none',
            }} />
            <div style={{
              position: 'absolute', left: 0, top: 0,
              width: `${(1 - viewOffset / MAX_OFFSET) * 100}%`,
              height: '100%', borderRadius: 2,
              background: isLive ? '#3fb95033' : '#58a6ff33',
              transition: 'width .15s',
            }} />
          </div>
          <span style={{ fontSize: 9, color: '#3fb950' }}>now</span>
        </div>
      </div>

      {/* ── resize handle ── */}
      <div
        onMouseDown={handleDragStart}
        title="Drag to resize"
        style={{
          height: 12, marginTop: 'auto',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          cursor: 'ns-resize',
          borderTop: '1px solid #1a2538',
          flexShrink: 0,
        }}
        onMouseEnter={e => { e.currentTarget.querySelector('span').style.background = '#58a6ff'; }}
        onMouseLeave={e => { e.currentTarget.querySelector('span').style.background = '#2d3f57'; }}
      >
        <span style={{
          display: 'block', width: 32, height: 3, borderRadius: 2,
          background: '#2d3f57', transition: 'background .15s',
          pointerEvents: 'none',
        }} />
      </div>
    </div>
  );
}

// ── Sidebar ───────────────────────────────────────────────────────────────────
function Sidebar({ tab, setTab, critCount, live, setLive, clock }) {
  const items = [
    { id: 'alerts', label: 'Alerts',     icon: '⚡' },
    { id: 'globe',  label: 'Threat Map', icon: '🌍' },
    { id: 'logs',   label: 'Log Stream', icon: '📋' },
    { id: 'mitre',  label: 'MITRE',      icon: '🗺' },
    { id: 'config', label: 'Config',     icon: '⚙' },
  ];

  return (
    <div style={{
      width: 64, background: '#060b14', borderRight: '1px solid #1a2538',
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      padding: '12px 0', gap: 4, flexShrink: 0,
    }}>
      {/* logo */}
      <div style={{ marginBottom: 16, fontSize: 22 }}>S</div>

      {items.map(item => (
        <button key={item.id} onClick={() => setTab(item.id)} title={item.label} style={{
          width: 44, height: 44, borderRadius: 10, border: 'none', cursor: 'pointer',
          background: tab === item.id ? 'rgba(88,166,255,.15)' : 'transparent',
          color: tab === item.id ? '#58a6ff' : '#6e7681',
          fontSize: 18, position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'center',
          transition: 'background .15s, color .15s',
        }}>
          {item.icon}
          {item.id === 'alerts' && critCount > 0 && (
            <span style={{
              position: 'absolute', top: 4, right: 4,
              background: '#f85149', color: '#fff', borderRadius: '50%',
              width: 14, height: 14, fontSize: 9, fontWeight: 800,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              lineHeight: 1,
            }}>
              {critCount > 9 ? '9+' : critCount}
            </span>
          )}
        </button>
      ))}

      <div style={{ flex: 1 }} />

      {/* live toggle */}
      <button onClick={() => setLive(v => !v)} title={live ? 'Pause live' : 'Resume live'} style={{
        width: 44, height: 44, borderRadius: 10, border: 'none', cursor: 'pointer',
        background: live ? 'rgba(63,185,80,.15)' : 'transparent',
        color: live ? '#3fb950' : '#6e7681', fontSize: 13, fontWeight: 700,
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 2,
      }}>
        <span style={{
          width: 6, height: 6, borderRadius: '50%',
          background: live ? '#3fb950' : '#6e7681',
          animation: live ? 'pulse 1.5s infinite' : 'none',
          display: 'block',
        }} />
        <span style={{ fontSize: 8 }}>{live ? 'LIVE' : 'STOP'}</span>
      </button>

      <div style={{ fontSize: 9, color: '#2d3f57', fontFamily: 'monospace', marginTop: 4, marginBottom: 4, writingMode: 'vertical-rl', transform: 'rotate(180deg)' }}>
        {clock}
      </div>
    </div>
  );
}

// ── MAIN APP ──────────────────────────────────────────────────────────────────
// ── DefenseRow — toggle row used in the AD panel ─────────────────────────────
function DefenseRow({ label, sublabel, enabled, dimmed, onChange, accent, isLast }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      gap: 10, opacity: dimmed ? .45 : 1,
    }}>
      <div style={{ minWidth: 0 }}>
        <div style={{ color: '#c9d1d9', fontSize: 11, fontWeight: 600, fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {label}
        </div>
        {sublabel && (
          <div style={{ color: '#6e7681', fontSize: 9, marginTop: 1 }}>{sublabel}</div>
        )}
      </div>
      {/* Toggle pill */}
      <div
        onClick={() => !dimmed && onChange(!enabled)}
        style={{
          width: 36, height: 18, borderRadius: 9, flexShrink: 0,
          background: enabled ? `${accent}44` : '#1e2940',
          border: `1px solid ${enabled ? accent : '#30363d'}`,
          cursor: dimmed ? 'default' : 'pointer',
          position: 'relative', transition: 'all .2s',
        }}
      >
        <div style={{
          position: 'absolute', top: 2, left: enabled ? 18 : 2,
          width: 12, height: 12, borderRadius: '50%',
          background: enabled ? accent : '#6e7681',
          boxShadow: enabled ? `0 0 6px ${accent}` : 'none',
          transition: 'all .2s',
        }} />
      </div>
    </div>
  );
}

// ── FlushOption — row in the flush dropdown ───────────────────────────────────
function FlushOption({ label, sublabel, active, danger, onClick }) {
  const [hov, setHov] = React.useState(false);
  const col = danger ? '#f85149' : '#c9d1d9';
  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        padding: '7px 14px', cursor: 'pointer',
        background: hov ? (danger ? 'rgba(248,81,73,.1)' : '#0d1929') : 'transparent',
        transition: 'background .1s',
      }}
    >
      <div style={{ color: active ? (danger ? '#f85149' : '#58a6ff') : col, fontSize: 11, fontWeight: active ? 700 : 400, fontFamily: label.startsWith('└') || label.startsWith('├') ? 'monospace' : 'inherit' }}>
        {label}
      </div>
      {sublabel && (
        <div style={{ color: '#6e7681', fontSize: 9, marginTop: 1 }}>{sublabel}</div>
      )}
    </div>
  );
}

export default function App() {
  const [tab,       setTab]       = useState('alerts');
  const [alerts,    setAlerts]    = useState([]);
  const [dashboard, setDashboard] = useState(null);
  const [selected,  setSelected]  = useState(null);
  const [live,      setLive]      = useState(true);
  const [clock,     setClock]     = useState(clockNow());
  // inputIp is the raw text-field value; filterIp is what's actually applied.
  // They are separate so typing in the IP box never triggers a server refetch.
  const [inputIp,   setInputIp]   = useState('');
  const [filterIp,  setFilterIp]  = useState('');
  const [filterType,  setFilterType]  = useState('');
  const [filterSev,   setFilterSev]   = useState('');
  const [filterDevice,setFilterDevice]= useState('');
  const [newIds,    setNewIds]    = useState(new Set());
  const [loading,      setLoading]      = useState(true);
  const [adEnabled,    setAdEnabled]    = useState(true);
  const [flushing,     setFlushing]     = useState(false);
  const [flushTarget,  setFlushTarget]  = useState('');       // '' = All
  const [showFlushDrop,setShowFlushDrop]= useState(false);
  const [showAdPanel,  setShowAdPanel]  = useState(false);
  const [deviceStates, setDeviceStates] = useState({ global: true, devices: [] });
  const [toasts,       setToasts]       = useState([]);
  const prevIds       = useRef(new Set());
  const toastIdRef    = useRef(0);
  const prevBanKeys   = useRef(null);
  const prevKsLen     = useRef(null);
  const flushDropRef  = useRef(null);
  const adPanelRef    = useRef(null);

  // Clock tick
  useEffect(() => {
    const t = setInterval(() => setClock(clockNow()), 1000);
    return () => clearInterval(t);
  }, []);

  const addToast = useCallback((type, title, sub) => {
    const id = ++toastIdRef.current;
    setToasts(prev => [...prev, { id, type, title, sub }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 8000);
  }, []);

  const dismissToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  // Debounce IP input → only apply the filter 400 ms after the user stops typing
  useEffect(() => {
    const t = setTimeout(() => setFilterIp(inputIp), 400);
    return () => clearTimeout(t);
  }, [inputIp]);


  // ── Device states (active defense per-machine) ───────────────────────────
  const fetchDeviceStates = useCallback(async () => {
    try {
      const r = await fetch(`${API}/api/active-defense/device-states`);
      const d = await r.json();
      setDeviceStates(d);
      setAdEnabled(d.global);
    } catch {}
  }, []);

  useEffect(() => { fetchDeviceStates(); }, [fetchDeviceStates]);

  // Close dropdowns on outside click
  useEffect(() => {
    const handler = e => {
      if (flushDropRef.current && !flushDropRef.current.contains(e.target))
        setShowFlushDrop(false);
      if (adPanelRef.current && !adPanelRef.current.contains(e.target))
        setShowAdPanel(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const flushBlocks = async (target) => {
    const label = !target ? 'ALL machines' : target === '__windows__' ? 'Windows SIEM' : target;
    if (!window.confirm(`Remove bans for ${label}?`)) return;
    setFlushing(true);
    setShowFlushDrop(false);
    try {
      const endpoint = !target
        ? `${API}/api/active-defense/flush-all`
        : `${API}/api/active-defense/flush-device?device_id=${encodeURIComponent(target)}`;
      await fetch(endpoint, { method: 'POST' });
      await fetchData();
    } catch {}
    setFlushing(false);
  };

  const toggleDeviceDefense = async (deviceId, enabled) => {
    try {
      await fetch(
        `${API}/api/active-defense/toggle-device?device_id=${encodeURIComponent(deviceId)}&enabled=${enabled}`,
        { method: 'POST' }
      );
      if (deviceId === '__global__') setAdEnabled(enabled);
      await fetchDeviceStates();
    } catch {}
  };

  // fetchData never depends on filter state — always fetches all 150 alerts.
  // Filtering is done client-side, so the IP box never triggers a server round-trip.
  const fetchData = useCallback(async () => {
    try {
      const [ar, dr] = await Promise.allSettled([
        fetch(`${API}/api/siem/alerts?limit=150`).then(r => r.json()),
        fetch(`${API}/api/siem/dashboard`).then(r => r.json()),
      ]);

      // Keep defense toggle in sync — catches backend restarts resetting state to ON
      fetchDeviceStates();

      if (ar.status === 'fulfilled' && Array.isArray(ar.value?.alerts)) {
        const list = ar.value.alerts;
        if (list.length > 0) {
          const incoming = new Set(list.map(a => a.id));
          const fresh    = [...incoming].filter(id => !prevIds.current.has(id));
          if (fresh.length > 0) {
            setNewIds(new Set(fresh));
            setTimeout(() => setNewIds(new Set()), 6000);
          }
          prevIds.current = incoming;
          setAlerts(list);
        } else {
          setAlerts(prev => prev.length > 0 ? prev : list);
        }
      }

      if (dr.status === 'fulfilled' && !dr.value?.error) {
        setDashboard(dr.value);
      }
    } catch {}

    // ── IP ban notifications ────────────────────────────────────────
    try {
      const bd = await fetch(`${API}/api/active-defense/bans`).then(r => r.json());
      const ipBans = (bd.bans || []).filter(b => b.ban_type === 'IP');
      // key = identifier + banned_at so a re-ban of the same IP after expiry fires again
      const keys = new Set(ipBans.map(b => `${b.identifier}|${b.banned_at}`));
      if (prevBanKeys.current !== null) {
        ipBans
          .filter(b => !prevBanKeys.current.has(`${b.identifier}|${b.banned_at}`))
          .forEach(b => addToast('block', 'IP Blocked', `${b.identifier} · ${b.attack_type}`));
      }
      prevBanKeys.current = keys;
    } catch {}

    // ── Kill switch notifications ───────────────────────────────────
    try {
      const ks = await fetch(`${API}/api/kill-switch/status`).then(r => r.json());
      const log = ks.audit_log || [];
      if (prevKsLen.current !== null && log.length > prevKsLen.current) {
        log.slice(prevKsLen.current).forEach(e => {
          const label = e.action === 'shutdown' ? 'Machine Shutdown' : 'Machine Isolated';
          addToast('isolate', label, `${e.host || ks.target || ''}${e.reason ? ' · ' + e.reason.slice(0, 60) : ''}`);
        });
      }
      prevKsLen.current = log.length;
    } catch {}

    setLoading(false);
  }, [addToast, fetchDeviceStates]);

  useEffect(() => {
    setLoading(true);
    fetchData();
    if (!live) return;
    const t = setInterval(fetchData, 5000);
    return () => clearInterval(t);
  }, [fetchData, live]);

  // derived
  const bySev   = dashboard?.by_severity || {};
  const critCount = bySev['SeverityLevel.CRITICAL'] ?? bySev['CRITICAL'] ?? 0;

  const visible = alerts.filter(a => {
    const k = normSev(a.severity);
    if (filterSev    && k !== filterSev) return false;
    if (filterIp     && !(a.src_ip     || '').includes(filterIp))   return false;
    if (filterType   && !(a.attack_type || '').toLowerCase().includes(filterType.toLowerCase())) return false;
    if (filterDevice && (a.device_id || '') !== filterDevice) return false;
    return true;
  });

  const attackTypes = [...new Set(alerts.map(a => a.attack_type).filter(Boolean))];

  // Sorted list of device_ids that appear in the current alert set
  const devices = [...new Set(alerts.map(a => a.device_id).filter(Boolean))].sort();

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', flexDirection: 'column', gap: 14, background: '#060b14' }}>
      <div style={{ width: 36, height: 36, border: '2px solid #1e2940', borderTop: '2px solid #58a6ff', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
      <span style={{ color: '#6e7681', fontSize: 12, fontFamily: 'monospace' }}>connecting to sentineliq...</span>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: '#060b14', color: '#c9d1d9', fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #060b14; }
        ::-webkit-scrollbar-thumb { background: #1e2940; border-radius: 2px; }
        ::-webkit-scrollbar-thumb:hover { background: #2d3f57; }
        @keyframes spin    { to { transform: rotate(360deg); } }
        @keyframes pulse   { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(1.3)} }
        @keyframes flashIn { 0%{background:rgba(248,81,73,.25)} 100%{background:transparent} }
        @keyframes slideIn      { from{opacity:0;transform:translateX(16px)} to{opacity:1;transform:translateX(0)} }
        @keyframes slideInRight { from{opacity:0;transform:translateX(32px)} to{opacity:1;transform:translateX(0)} }
        @keyframes toastOut     { from{opacity:1;transform:translateX(0)} to{opacity:0;transform:translateX(32px)} }
      `}</style>

      {/* ── Toast notification stack ── */}
      <div style={{
        position: 'fixed', top: 56, right: 14,
        display: 'flex', flexDirection: 'column', gap: 8,
        zIndex: 9999, pointerEvents: 'none',
        maxWidth: 340,
      }}>
        {toasts.map(t => {
          const isIsolate = t.type === 'isolate';
          const accent = isIsolate ? '#f85149' : '#f0883e';
          return (
            <div key={t.id} style={{
              pointerEvents: 'all',
              display: 'flex', alignItems: 'flex-start', gap: 10,
              padding: '10px 12px',
              background: isIsolate ? 'rgba(248,81,73,.12)' : 'rgba(240,136,62,.12)',
              border: `1px solid ${accent}44`,
              borderLeft: `3px solid ${accent}`,
              borderRadius: 8,
              boxShadow: `0 4px 24px rgba(0,0,0,.5), 0 0 0 1px ${accent}11`,
              backdropFilter: 'blur(10px)',
              animation: 'slideInRight .25s ease',
            }}>
              {/* icon */}
              <span style={{ fontSize: 18, lineHeight: 1.2, flexShrink: 0 }}>
                {isIsolate ? '🔒' : '🛡️'}
              </span>

              {/* text */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 11, fontWeight: 800, color: accent, letterSpacing: '.06em', textTransform: 'uppercase' }}>
                  {t.title}
                </div>
                {t.sub && (
                  <div style={{ fontSize: 11, color: '#8b949e', marginTop: 3, fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    {t.sub}
                  </div>
                )}
              </div>

              {/* dismiss */}
              <button
                onClick={() => dismissToast(t.id)}
                style={{
                  background: 'none', border: 'none', color: '#4a5568',
                  cursor: 'pointer', fontSize: 15, lineHeight: 1,
                  padding: '0 2px', flexShrink: 0,
                  transition: 'color .1s',
                }}
                onMouseEnter={e => e.currentTarget.style.color = '#8b949e'}
                onMouseLeave={e => e.currentTarget.style.color = '#4a5568'}
              >×</button>
            </div>
          );
        })}
      </div>

      <Sidebar tab={tab} setTab={setTab} critCount={critCount} live={live} setLive={setLive} clock={clock} />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* ── top header ── */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 16,
          padding: '0 20px', height: 48, borderBottom: '1px solid #1a2538',
          background: '#070d1a', flexShrink: 0,
        }}>
          <span style={{ fontWeight: 800, fontSize: 15, color: '#58a6ff', letterSpacing: '.04em' }}>SentinelIQ</span>
          <span style={{ color: '#2d3f57', fontSize: 14 }}>/</span>
          <span style={{ color: '#8b949e', fontSize: 13 }}>
            {{ alerts: 'Alert Stream', logs: 'Log Explorer', mitre: 'MITRE ATT&CK', config: 'Configuration' }[tab]}
          </span>

          {critCount > 0 && (
            <span style={{
              background: 'rgba(248,81,73,.18)', color: '#f85149',
              border: '1px solid #f8514944', borderRadius: 4,
              padding: '1px 8px', fontSize: 11, fontWeight: 700,
            }}>
              {critCount} CRITICAL
            </span>
          )}

          <div style={{ flex: 1 }} />

          {tab === 'alerts' && (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input
                value={inputIp} onChange={e => setInputIp(e.target.value)}
                placeholder="Filter IP..."
                style={{ background: '#0d1929', border: '1px solid #1e2940', color: '#c9d1d9', borderRadius: 5, padding: '3px 9px', fontSize: 11, width: 130, outline: 'none', fontFamily: 'monospace' }}
              />
              <select value={filterType} onChange={e => setFilterType(e.target.value)}
                style={{ background: '#0d1929', border: '1px solid #1e2940', color: '#c9d1d9', borderRadius: 5, padding: '3px 8px', fontSize: 11, outline: 'none' }}>
                <option value="">All Types</option>
                {attackTypes.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
              <select value={filterSev} onChange={e => setFilterSev(e.target.value)}
                style={{ background: '#0d1929', border: '1px solid #1e2940', color: '#c9d1d9', borderRadius: 5, padding: '3px 8px', fontSize: 11, outline: 'none' }}>
                <option value="">All Severity</option>
                {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <select
                value={filterDevice}
                onChange={e => setFilterDevice(e.target.value)}
                style={{ background: '#0d1929', border: '1px solid #1e2940', color: '#c9d1d9', borderRadius: 5, padding: '3px 8px', fontSize: 11, outline: 'none', maxWidth: 180 }}
              >
                <option value="">All Devices</option>
                {devices.map((d, i) => (
                  <option key={d} value={d}>
                    {i === devices.length - 1 ? '└── ' : '├── '}{d}
                  </option>
                ))}
              </select>
              {(inputIp || filterType || filterSev || filterDevice) && (
                <button onClick={() => { setInputIp(''); setFilterIp(''); setFilterType(''); setFilterSev(''); setFilterDevice(''); }}
                  style={{ background: 'none', border: 'none', color: '#6e7681', cursor: 'pointer', fontSize: 14 }}>
                  ×
                </button>
              )}
              <span style={{ color: '#6e7681', fontSize: 11 }}>{visible.length} / {alerts.length}</span>
            </div>
          )}

          {/* ── Active Defense expandable panel ── */}
          <div ref={adPanelRef} style={{ position: 'relative' }}>
            <button
              onClick={() => setShowAdPanel(v => !v)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                background: adEnabled ? 'rgba(63,185,80,.12)' : 'rgba(110,118,129,.1)',
                border: `1px solid ${adEnabled ? '#3fb95055' : '#3d4d5f'}`,
                color: adEnabled ? '#3fb950' : '#6e7681',
                borderRadius: 5, padding: '3px 10px', fontSize: 11,
                cursor: 'pointer', fontWeight: 700, transition: 'all .2s',
              }}
            >
              <span style={{
                width: 7, height: 7, borderRadius: '50%',
                background: adEnabled ? '#3fb950' : '#6e7681',
                boxShadow: adEnabled ? '0 0 6px #3fb950' : 'none',
                animation: adEnabled ? 'pulse 2s infinite' : 'none',
                flexShrink: 0,
              }} />
              {adEnabled ? 'Defense ON' : 'Defense OFF'}
              <span style={{ fontSize: 9, opacity: .7, marginLeft: 2 }}>▾</span>
            </button>

            {showAdPanel && (
              <div style={{
                position: 'absolute', top: 'calc(100% + 6px)', right: 0, zIndex: 200,
                background: '#0d1117', border: '1px solid #1e2940',
                borderRadius: 8, width: 270,
                boxShadow: '0 8px 32px #00000099',
                animation: 'slideIn .15s ease',
              }}>
                {/* Header */}
                <div style={{ padding: '10px 14px 8px', borderBottom: '1px solid #1e2940' }}>
                  <div style={{ color: '#8b949e', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.07em' }}>
                    Active Defense
                  </div>
                </div>

                {/* Global toggle row */}
                <div style={{ padding: '8px 14px', borderBottom: '1px solid #1e2940' }}>
                  <DefenseRow
                    label="Global (all machines)"
                    sublabel="Master switch"
                    enabled={deviceStates.global}
                    onChange={v => toggleDeviceDefense('__global__', v)}
                    accent="#3fb950"
                  />
                </div>

                {/* Per-device rows */}
                {deviceStates.devices.length > 0 && (
                  <div style={{ padding: '6px 0', borderBottom: '1px solid #1e2940' }}>
                    <div style={{ padding: '2px 14px 6px', color: '#6e7681', fontSize: 9, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                      Per Machine
                    </div>
                    {deviceStates.devices.map((d, i) => (
                      <div key={d.device_id} style={{ padding: '4px 14px' }}>
                        <DefenseRow
                          label={d.device_id}
                          sublabel={d.inherits_global ? 'inherits global' : d.enabled ? 'override: ON' : 'override: OFF'}
                          enabled={d.inherits_global ? deviceStates.global : d.enabled}
                          dimmed={!deviceStates.global}
                          onChange={v => toggleDeviceDefense(d.device_id, v)}
                          accent="#58a6ff"
                          isLast={i === deviceStates.devices.length - 1}
                        />
                      </div>
                    ))}
                  </div>
                )}

                {/* Stats footer */}
                <div style={{ padding: '8px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: '#6e7681', fontSize: 10 }}>
                    {deviceStates.devices.filter(d =>
                      d.inherits_global ? deviceStates.global : d.enabled
                    ).length} / {Math.max(deviceStates.devices.length, 1)} machines active
                  </span>
                  <button
                    onClick={() => { setShowAdPanel(false); fetchDeviceStates(); }}
                    style={{ background: 'none', border: 'none', color: '#58a6ff', fontSize: 10, cursor: 'pointer' }}
                  >
                    Refresh ↺
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* ── Flush Blocks split-button ── */}
          <div ref={flushDropRef} style={{ position: 'relative' }}>
            <div style={{ display: 'flex', borderRadius: 5, overflow: 'hidden', border: '1px solid #f8514944' }}>
              {/* Main action button */}
              <button
                onClick={() => flushBlocks(flushTarget)}
                disabled={flushing}
                style={{
                  background: flushing ? 'rgba(248,81,73,.05)' : 'rgba(248,81,73,.1)',
                  border: 'none', borderRight: '1px solid #f8514933',
                  color: flushing ? '#6e7681' : '#f85149',
                  padding: '3px 10px', fontSize: 11,
                  cursor: flushing ? 'default' : 'pointer', fontWeight: 600,
                  transition: 'all .2s', whiteSpace: 'nowrap',
                }}
              >
                {flushing ? 'Flushing…' : `Flush ${!flushTarget ? 'All' : flushTarget === '__windows__' ? 'Windows' : flushTarget}`}
              </button>
              {/* Dropdown arrow */}
              <button
                onClick={() => setShowFlushDrop(v => !v)}
                disabled={flushing}
                style={{
                  background: flushing ? 'rgba(248,81,73,.05)' : 'rgba(248,81,73,.08)',
                  border: 'none',
                  color: flushing ? '#6e7681' : '#f85149',
                  padding: '3px 7px', fontSize: 10,
                  cursor: flushing ? 'default' : 'pointer',
                }}
              >▾</button>
            </div>

            {showFlushDrop && !flushing && (
              <div style={{
                position: 'absolute', top: 'calc(100% + 6px)', right: 0, zIndex: 200,
                background: '#0d1117', border: '1px solid #1e2940',
                borderRadius: 8, minWidth: 220,
                boxShadow: '0 8px 32px #00000099',
                animation: 'slideIn .15s ease', overflow: 'hidden',
              }}>
                {/* Section label */}
                <div style={{ padding: '8px 14px 4px', color: '#6e7681', fontSize: 9, textTransform: 'uppercase', letterSpacing: '.07em' }}>
                  Select target
                </div>

                {/* All machines */}
                <FlushOption
                  label="⚠ All Machines"
                  sublabel="Flush every ban — Windows + all Ubuntu"
                  active={flushTarget === ''}
                  danger
                  onClick={() => { setFlushTarget(''); setShowFlushDrop(false); }}
                />

                <div style={{ height: 1, background: '#1e2940', margin: '2px 0' }} />

                {/* Per-device options */}
                {devices.map((d, i) => (
                  <FlushOption
                    key={d}
                    label={`${i === devices.length - 1 ? '└' : '├'}── ${d}`}
                    sublabel="Remote iptables flush (SSH)"
                    active={flushTarget === d}
                    onClick={() => { setFlushTarget(d); setShowFlushDrop(false); }}
                  />
                ))}

                {devices.length === 0 && (
                  <div style={{ padding: '6px 14px 8px', color: '#6e7681', fontSize: 10 }}>
                    No remote devices detected yet
                  </div>
                )}

                <div style={{ height: 1, background: '#1e2940', margin: '2px 0' }} />

                {/* Windows local */}
                <FlushOption
                  label="🖥 Windows SIEM (local)"
                  sublabel="Windows Firewall rules only"
                  active={flushTarget === '__windows__'}
                  onClick={() => { setFlushTarget('__windows__'); setShowFlushDrop(false); }}
                />
              </div>
            )}
          </div>

          <button onClick={fetchData} style={{
            background: 'rgba(88,166,255,.08)', border: '1px solid #1e2940',
            color: '#58a6ff', borderRadius: 5, padding: '3px 10px', fontSize: 11,
            cursor: 'pointer', fontWeight: 600,
          }}>
            Refresh
          </button>
        </div>

        {/* ── stats bar (alerts tab only) ── */}
        {tab === 'alerts' && <StatsBar dashboard={dashboard} alertCount={alerts.length} />}

        {/* ── main content ── */}
        <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

          {/* ALERTS TAB */}
          {tab === 'alerts' && (
            <>
              {/* left column: stream */}
              <div style={{
                width: selected ? 340 : '100%',
                display: 'flex', flexDirection: 'column',
                borderRight: selected ? '1px solid #1a2538' : 'none',
                overflow: 'hidden', flexShrink: 0,
                transition: 'width .2s ease',
              }}>
                <AlertTimeline alerts={alerts} />
                <div style={{ flex: 1, overflowY: 'auto', marginTop: 8 }}>
                  {visible.length === 0 && (
                    <div style={{ padding: '60px 20px', textAlign: 'center', color: '#6e7681' }}>
                      <div style={{ fontSize: 32, marginBottom: 12 }}>-</div>
                      {alerts.length === 0 ? 'No alerts yet. Run the attack simulator.' : 'No alerts match filters.'}
                    </div>
                  )}
                  {visible.map(a => (
                    <AlertRow
                      key={a.id}
                      alert={a}
                      selected={selected?.id === a.id}
                      onClick={() => setSelected(s => s?.id === a.id ? null : a)}
                      isNew={newIds.has(a.id)}
                    />
                  ))}
                </div>
              </div>

              {/* right column: detail */}
              {selected && (
                <div style={{ flex: 1, overflow: 'hidden', animation: 'slideIn .2s ease' }}>
                  <AlertDetail
                    alert={selected}
                    onClose={() => setSelected(null)}
                    onRefresh={fetchData}
                  />
                </div>
              )}
            </>
          )}

          {/* GLOBE TAB */}
          {tab === 'globe' && (
            <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
              <ThreatGlobe alerts={alerts} />
            </div>
          )}

          {/* LOGS TAB */}
          {tab === 'logs' && <LogExplorer />}

          {/* MITRE TAB */}
          {tab === 'mitre' && <MitrePanel dashboard={dashboard} />}

          {/* CONFIG TAB */}
          {tab === 'config' && (
            <div style={{ flex: 1, overflow: 'auto' }}>
              <ConfigPanel />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
