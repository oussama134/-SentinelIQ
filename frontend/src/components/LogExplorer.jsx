import React, { useState, useEffect, useCallback } from 'react';
import { API, apiFetch } from '../api';

const EVENT_COLOR = {
  ddos: '#f85149', dos_hulk: '#f85149', dos_slowloris: '#f0883e',
  dos_goldeneye: '#f0883e', dos_slowhttptest: '#f0883e',
  ssh_brute_force: '#f0883e', ftp_brute_force: '#f0883e',
  port_scan: '#d29922', web_brute_force: '#d29922',
  sql_injection: '#d29922', web_xss: '#d29922',
  botnet_activity: '#9b59b6', heartbleed_exploit: '#e74c3c',
  infiltration: '#e74c3c',
  failed_ssh: '#f0883e', invalid_user: '#d29922',
  normal_traffic: '#3fb950', http_request: '#58a6ff',
};
const evColor = t => EVENT_COLOR[t] || '#8b949e';

function fmtFull(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', {
    month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
}

export default function LogExplorer() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [minutes, setMinutes] = useState(60);
  const [live, setLive] = useState(true);
  const [selected, setSelected] = useState(null);

  const fetchLogs = useCallback(async () => {
    try {
      const p = new URLSearchParams({ limit: 300, minutes });
      if (sourceFilter) p.set('source', sourceFilter);
      const res = await apiFetch(`${API}/api/logs?${p}`);
      const data = await res.json();
      if (data.logs) setLogs(data.logs);
    } catch {}
    setLoading(false);
  }, [sourceFilter, minutes]);

  useEffect(() => {
    setLoading(true);
    fetchLogs();
    if (!live) return;
    const t = setInterval(fetchLogs, 5000);
    return () => clearInterval(t);
  }, [fetchLogs, live]);

  const visible = logs.filter(l => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      l.src_ip?.includes(q) ||
      l.dst_ip?.includes(q) ||
      l.event_type?.includes(q) ||
      l.predicted_label?.toLowerCase().includes(q) ||
      l.message?.toLowerCase().includes(q)
    );
  });

  const colStyle = {
    time:   { width: 155, color: '#6e7681', fontFamily: 'monospace', fontSize: 11 },
    source: { width: 72,  color: '#8b949e', fontSize: 11 },
    srcip:  { width: 130, color: '#58a6ff', fontFamily: 'monospace', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
    dstip:  { width: 130, color: '#79c0ff', fontFamily: 'monospace', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
    proto:  { width: 52,  color: '#8b949e', fontSize: 11 },
    event:  { flex: 1,    fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
    conf:   { width: 52,  fontSize: 11, textAlign: 'right' },
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#060b14' }}>

      {/* Toolbar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '10px 16px', borderBottom: '1px solid #1a2538',
        background: '#070d1a', flexShrink: 0,
      }}>
        <span style={{ color: '#58a6ff', fontSize: 13, fontWeight: 700 }}>Log Explorer</span>
        <div style={{ width: 1, height: 18, background: '#1e2940' }} />

        <input
          value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search IP, event, label..."
          style={{
            background: '#0d1929', border: '1px solid #1e2940',
            color: '#e6edf3', borderRadius: 6, padding: '4px 10px',
            fontSize: 12, width: 200, outline: 'none', fontFamily: 'monospace',
          }}
        />

        <select value={sourceFilter} onChange={e => setSourceFilter(e.target.value)}
          style={{ background: '#0d1929', border: '1px solid #1e2940', color: '#e6edf3', borderRadius: 6, padding: '4px 8px', fontSize: 12, outline: 'none' }}>
          <option value="">All Sources</option>
          <option value="NETWORK">Network (ML)</option>
          <option value="AUTH">Auth logs</option>
          <option value="WEB">Web logs</option>
          <option value="HONEYPOT">Honeypot</option>
        </select>

        <select value={minutes} onChange={e => setMinutes(Number(e.target.value))}
          style={{ background: '#0d1929', border: '1px solid #1e2940', color: '#e6edf3', borderRadius: 6, padding: '4px 8px', fontSize: 12, outline: 'none' }}>
          <option value={15}>Last 15 min</option>
          <option value={60}>Last 1 hour</option>
          <option value={360}>Last 6 hours</option>
          <option value={1440}>Last 24 hours</option>
        </select>

        <button onClick={() => setLive(v => !v)} style={{
          padding: '4px 10px', borderRadius: 5,
          border: `1px solid ${live ? '#1e5f3a' : '#2d3748'}`,
          background: live ? 'rgba(63,185,80,0.08)' : 'transparent',
          color: live ? '#3fb950' : '#6e7681',
          cursor: 'pointer', fontSize: 11, fontWeight: 600,
          display: 'flex', alignItems: 'center', gap: 5,
        }}>
          <span style={{
            width: 6, height: 6, borderRadius: '50%',
            background: live ? '#3fb950' : '#6e7681',
            animation: live ? 'pulse 1.5s infinite' : 'none',
          }} />
          {live ? 'LIVE' : 'PAUSED'}
        </button>

        {search && (
          <button onClick={() => setSearch('')} style={{ background: 'none', border: 'none', color: '#6e7681', cursor: 'pointer', fontSize: 16 }}>×</button>
        )}

        <span style={{ marginLeft: 'auto', color: '#6e7681', fontSize: 11 }}>
          {visible.length} / {logs.length} entries
        </span>
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Table */}
        <div style={{ flex: selected ? '0 0 60%' : 1, overflow: 'auto', borderRight: selected ? '1px solid #1a2538' : 'none' }}>
          {/* Column headers */}
          <div style={{
            display: 'flex', gap: 8, padding: '6px 12px',
            borderBottom: '1px solid #1a2538',
            background: '#060b14', position: 'sticky', top: 0, zIndex: 10,
            color: '#6e7681', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.08em',
          }}>
            <div style={{ width: colStyle.time.width }}>Timestamp</div>
            <div style={{ width: colStyle.source.width }}>Source</div>
            <div style={{ width: colStyle.srcip.width }}>Src IP</div>
            <div style={{ width: colStyle.dstip.width }}>Dst IP</div>
            <div style={{ width: colStyle.proto.width }}>Proto</div>
            <div style={{ flex: 1 }}>Event / Label</div>
            <div style={{ width: colStyle.conf.width, textAlign: 'right' }}>Conf</div>
          </div>

          {loading && (
            <div style={{ padding: '50px 20px', textAlign: 'center', color: '#6e7681' }}>Loading logs...</div>
          )}
          {!loading && visible.length === 0 && (
            <div style={{ padding: '60px 20px', textAlign: 'center', color: '#6e7681' }}>
              <div style={{ fontSize: 32, marginBottom: 12 }}>📋</div>
              No log entries found.
              <br />
              <span style={{ fontSize: 12 }}>Logs are stored when network flows pass through the detection pipeline.</span>
            </div>
          )}

          {visible.map(log => {
            const isSelected = selected?.id === log.id;
            const isAttack = log.predicted_label && log.predicted_label !== 'BENIGN';
            const eColor = evColor(log.event_type);
            return (
              <div key={log.id} onClick={() => setSelected(isSelected ? null : log)}
                style={{
                  display: 'flex', gap: 8, padding: '7px 12px', cursor: 'pointer',
                  borderLeft: `3px solid ${isSelected ? '#58a6ff' : isAttack ? eColor : 'transparent'}`,
                  borderBottom: '1px solid #0a0f1a',
                  background: isSelected
                    ? 'rgba(88,166,255,0.07)'
                    : isAttack ? `${eColor}07` : 'transparent',
                  transition: 'background .1s',
                }}
                onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = 'rgba(255,255,255,0.025)'; }}
                onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = isAttack ? `${eColor}07` : 'transparent'; }}
              >
                <div style={{ ...colStyle.time }}>{fmtFull(log.timestamp)}</div>
                <div style={{ ...colStyle.source, width: colStyle.source.width, flexShrink: 0 }}>{log.source}</div>
                <div style={{ ...colStyle.srcip, width: colStyle.srcip.width, flexShrink: 0 }}>{log.src_ip || '—'}</div>
                <div style={{ ...colStyle.dstip, width: colStyle.dstip.width, flexShrink: 0 }}>{log.dst_ip || '—'}</div>
                <div style={{ ...colStyle.proto, width: colStyle.proto.width, flexShrink: 0 }}>{log.protocol || '—'}</div>
                <div style={{ flex: 1, overflow: 'hidden' }}>
                  {log.event_type && log.event_type !== 'normal_traffic' ? (
                    <span style={{ color: eColor, fontWeight: 600, fontSize: 11 }}>{log.event_type}</span>
                  ) : log.predicted_label ? (
                    <span style={{ color: isAttack ? eColor : '#3fb950', fontSize: 11 }}>{log.predicted_label}</span>
                  ) : (
                    <span style={{ color: '#4a5568', fontSize: 11 }}>—</span>
                  )}
                </div>
                <div style={{ width: colStyle.conf.width, textAlign: 'right', flexShrink: 0 }}>
                  <span style={{ color: isAttack ? '#f85149' : '#3fb950', fontSize: 11 }}>
                    {log.confidence != null ? `${Math.round(log.confidence * 100)}%` : '—'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Log detail pane */}
        {selected && (
          <div style={{ flex: 1, overflow: 'auto', padding: '16px 20px', animation: 'slideIn .2s ease' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <span style={{ color: '#e6edf3', fontWeight: 700, fontSize: 14 }}>
                Log Entry <span style={{ color: '#58a6ff', fontFamily: 'monospace' }}>#{selected.id}</span>
              </span>
              <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: '#6e7681', cursor: 'pointer', fontSize: 20 }}>×</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {/* Flow visualization */}
              <div style={{ background: '#0d1929', border: '1px solid #1e2940', borderRadius: 8, padding: 14 }}>
                <div style={{ color: '#6e7681', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 10 }}>Network Flow</div>
                <div style={{ fontFamily: 'monospace', fontSize: 13, color: '#c9d1d9', display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                  <span style={{ color: '#58a6ff' }}>{selected.src_ip || '?'}</span>
                  {selected.src_port && <span style={{ color: '#6e7681' }}>:{selected.src_port}</span>}
                  <span style={{ color: '#3d4d5f' }}>──[{selected.protocol || '?'}]──→</span>
                  <span style={{ color: '#79c0ff' }}>{selected.dst_ip || '?'}</span>
                  {selected.dst_port && <span style={{ color: '#6e7681' }}>:{selected.dst_port}</span>}
                </div>
              </div>

              {/* Detection details */}
              <div style={{ background: '#0d1929', border: '1px solid #1e2940', borderRadius: 8, padding: 14 }}>
                <div style={{ color: '#6e7681', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 10 }}>Detection</div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 16px', fontSize: 12 }}>
                  {[
                    ['Source',          selected.source],
                    ['Timestamp',       fmtFull(selected.timestamp)],
                    ['Event Type',      selected.event_type || '—'],
                    ['Predicted Label', selected.predicted_label || '—'],
                    ['Confidence',      selected.confidence != null ? `${Math.round(selected.confidence * 100)}%` : '—'],
                  ].map(([k, v]) => (
                    <div key={k}>
                      <div style={{ color: '#6e7681', fontSize: 10, marginBottom: 2 }}>{k}</div>
                      <div style={{
                        color: k === 'Predicted Label' && selected.predicted_label !== 'BENIGN'
                          ? evColor(selected.event_type)
                          : '#c9d1d9',
                        fontWeight: k === 'Predicted Label' ? 600 : 400,
                        fontFamily: k === 'Timestamp' ? 'monospace' : 'inherit',
                        fontSize: 12,
                      }}>{v}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Raw message */}
              {selected.message && (
                <div style={{ background: '#0a0f1a', border: '1px solid #1a2538', borderRadius: 8, padding: 14 }}>
                  <div style={{ color: '#6e7681', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 8 }}>Raw Message</div>
                  <pre style={{ color: '#8b949e', fontSize: 11, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.6 }}>{selected.message}</pre>
                </div>
              )}

              {/* Extra metadata */}
              {selected.extra && Object.keys(selected.extra).length > 0 && (
                <div style={{ background: '#0a0f1a', border: '1px solid #1a2538', borderRadius: 8, padding: 14 }}>
                  <div style={{ color: '#6e7681', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 8 }}>Extra Metadata</div>
                  <pre style={{ color: '#8b949e', fontSize: 11, margin: 0, lineHeight: 1.6 }}>{JSON.stringify(selected.extra, null, 2)}</pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      <style>{`
        @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(1.3)} }
        @keyframes slideIn { from{opacity:0;transform:translateX(12px)} to{opacity:1;transform:translateX(0)} }
      `}</style>
    </div>
  );
}
