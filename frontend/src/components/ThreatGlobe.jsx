/**
 * ThreatGlobe projects geo-enriched alerts onto a 3D globe so analysts can
 * see attack origin patterns and severity hotspots at a glance.
 */
import { useRef, useEffect, useState, useMemo, useCallback } from 'react';
import Globe from 'react-globe.gl';

// ── Country code → [lat, lng] ─────────────────────────────────────────────────
const COORDS = {
  AF:[33.93,67.70],AL:[41.15,20.17],DZ:[28.03,1.65],AO:[-11.20,17.87],AR:[-38.41,-63.61],
  AM:[40.06,45.03],AU:[-25.27,133.77],AT:[47.51,14.55],AZ:[40.14,47.57],BH:[26.00,50.55],
  BD:[23.68,90.35],BY:[53.70,27.95],BE:[50.50,4.46],BJ:[9.30,2.31],BT:[27.51,90.43],
  BO:[-16.29,-63.58],BA:[43.91,17.67],BW:[-22.32,24.68],BR:[-14.23,-51.92],BG:[42.73,25.48],
  KH:[12.56,104.99],CM:[3.84,11.50],CA:[56.13,-106.34],CL:[-35.67,-71.54],CN:[35.86,104.19],
  CO:[4.57,-74.29],CG:[-0.22,15.82],CR:[9.74,-83.75],HR:[45.10,15.20],CU:[21.52,-77.78],
  CY:[35.12,33.42],CZ:[49.81,15.47],DK:[56.26,9.50],DO:[18.73,-70.16],EC:[-1.83,-78.18],
  EG:[26.82,30.80],SV:[13.79,-88.89],EE:[58.59,25.01],ET:[9.14,40.49],FI:[61.92,25.74],
  FR:[46.22,2.21],GA:[-0.80,11.60],GE:[42.31,43.35],DE:[51.16,10.45],GH:[7.94,-1.02],
  GR:[39.07,21.82],GT:[15.78,-90.23],HN:[15.19,-86.24],HK:[22.39,114.10],HU:[47.16,19.50],
  IN:[20.59,78.96],ID:[-0.78,113.92],IR:[32.42,53.68],IQ:[33.22,43.67],IE:[53.41,-8.24],
  IL:[31.04,34.85],IT:[41.87,12.56],JM:[18.10,-77.29],JP:[36.20,138.25],JO:[30.58,36.23],
  KZ:[48.01,66.92],KE:[-0.02,37.90],KP:[40.33,127.51],KR:[35.90,127.76],KW:[29.31,47.48],
  LV:[56.87,24.60],LB:[33.85,35.86],LY:[26.33,17.22],LT:[55.16,23.88],LU:[49.81,6.12],
  MY:[4.21,101.97],MX:[23.63,-102.55],MD:[47.41,28.36],MA:[31.79,-7.09],MZ:[-18.66,35.52],
  MM:[21.91,95.95],NP:[28.39,84.12],NL:[52.13,5.29],NZ:[-40.90,174.88],NI:[12.86,-85.20],
  NG:[9.08,8.67],NO:[60.47,8.46],OM:[21.51,55.92],PK:[30.37,69.34],PS:[31.95,35.23],
  PA:[8.53,-80.78],PY:[-23.44,-58.44],PE:[-9.18,-75.01],PH:[12.87,121.77],PL:[51.91,19.14],
  PT:[39.39,-8.22],QA:[25.35,51.18],RO:[45.94,24.96],RU:[61.52,105.31],SA:[23.88,45.08],
  SN:[14.49,-14.45],RS:[44.01,21.00],SG:[1.35,103.81],SK:[48.66,19.69],SI:[46.15,14.99],
  ZA:[-30.55,22.93],ES:[40.46,-3.74],LK:[7.87,80.77],SE:[60.12,18.64],CH:[46.81,8.22],
  SY:[34.80,38.99],TW:[23.69,120.96],TJ:[38.86,71.27],TZ:[-6.36,34.88],TH:[15.87,100.99],
  TN:[33.88,9.53],TR:[38.96,35.24],TM:[38.96,59.55],UG:[1.37,32.29],UA:[48.37,31.16],
  AE:[23.42,53.84],GB:[55.37,-3.43],US:[37.09,-95.71],UY:[-32.52,-55.76],UZ:[41.37,64.58],
  VN:[14.05,108.27],YE:[15.55,48.51],ZM:[-13.13,27.84],ZW:[-19.01,29.15],
  TOR:[0,0],
};

const SEV_COL = {
  CRITICAL: '#f85149',
  HIGH:     '#f0883e',
  MEDIUM:   '#d29922',
  LOW:      '#3fb950',
};
const SEV_ORDER = ['LOW','MEDIUM','HIGH','CRITICAL'];

function higherSev(a, b) {
  return SEV_ORDER.indexOf(a) >= SEV_ORDER.indexOf(b) ? a : b;
}

const HOME = { lat: 31.79, lng: -7.09, label: 'SentinelIQ' };

// ── Keyframes injected once ───────────────────────────────────────────────────
const STYLE_ID = 'tg-keyframes';
if (!document.getElementById(STYLE_ID)) {
  const s = document.createElement('style');
  s.id = STYLE_ID;
  s.textContent = `
    @keyframes tgSlideIn  { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    @keyframes tgFadeIn   { from { opacity: 0; } to { opacity: 1; } }
    @keyframes tgPulse    { 0%,100% { box-shadow: 0 0 0 0 #3fb95066; } 70% { box-shadow: 0 0 0 6px #3fb95000; } }
    @keyframes tgBlink    { 0%,100% { opacity: 1; } 50% { opacity: .4; } }
  `;
  document.head.appendChild(s);
}

// ── Location Detail Side Panel ────────────────────────────────────────────────
function LocationPanel({ location, onClose }) {
  // Build per-IP summary from the location's alert list
  const ipRows = useMemo(() => {
    const byIp = {};
    (location.alerts || []).forEach(a => {
      if (!a.src_ip) return;
      if (!byIp[a.src_ip]) {
        byIp[a.src_ip] = { ip: a.src_ip, types: new Set(), count: 0, lastSeen: null, maxSev: 'LOW' };
      }
      byIp[a.src_ip].count++;
      const raw = a.attack_type || a.predicted_label;
      if (raw) byIp[a.src_ip].types.add(raw);
      const ts = a.timestamp || a.created_at;
      if (ts && (!byIp[a.src_ip].lastSeen || ts > byIp[a.src_ip].lastSeen))
        byIp[a.src_ip].lastSeen = ts;
      const sev = (a.severity || '').replace('SeverityLevel.', '') || 'LOW';
      byIp[a.src_ip].maxSev = higherSev(byIp[a.src_ip].maxSev, sev);
    });
    return Object.values(byIp).sort((a, b) => b.count - a.count);
  }, [location]);

  const col = SEV_COL[location.maxSev] || '#58a6ff';

  return (
    <div style={{
      position: 'absolute', top: 0, right: 0, bottom: 0, zIndex: 50,
      width: 320, display: 'flex', flexDirection: 'column',
      background: '#0d1117',
      borderLeft: `1px solid ${col}33`,
      boxShadow: '-12px 0 40px #00000099',
      animation: 'tgSlideIn .22s cubic-bezier(.25,.46,.45,.94)',
    }}>

      {/* ── Panel header ── */}
      <div style={{
        padding: '18px 18px 14px',
        background: '#0d1929',
        borderBottom: `1px solid ${col}33`,
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{
                width: 10, height: 10, borderRadius: '50%',
                background: col, boxShadow: `0 0 8px ${col}`,
                animation: 'tgBlink 2s infinite',
                flexShrink: 0,
              }} />
              <span style={{ color: '#c9d1d9', fontSize: 15, fontWeight: 700 }}>
                {location.cc}
              </span>
              <span style={{
                background: `${col}22`, color: col,
                fontSize: 9, fontWeight: 700, padding: '2px 7px', borderRadius: 4,
                letterSpacing: '.05em',
              }}>
                {location.maxSev}
              </span>
            </div>
            <div style={{ color: '#6e7681', fontSize: 10, marginTop: 4, paddingLeft: 18 }}>
              {location.lat.toFixed(2)}°N, {Math.abs(location.lng).toFixed(2)}°{location.lng >= 0 ? 'E' : 'W'}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none', border: '1px solid #30363d', borderRadius: 6,
              color: '#8b949e', cursor: 'pointer', padding: '3px 9px',
              fontSize: 14, lineHeight: 1.4, flexShrink: 0,
            }}
          >✕</button>
        </div>

        {/* Stats row */}
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)',
          gap: 8, marginTop: 14,
        }}>
          {[
            { label: 'Alerts', value: location.count, color: col },
            { label: 'Unique IPs', value: ipRows.length, color: '#58a6ff' },
            { label: 'Attack Types',
              value: new Set(ipRows.flatMap(r => [...r.types])).size,
              color: '#d29922' },
          ].map(({ label, value, color }) => (
            <div key={label} style={{
              background: '#060b14', borderRadius: 6, padding: '8px 10px', textAlign: 'center',
            }}>
              <div style={{ color, fontSize: 18, fontWeight: 700 }}>{value}</div>
              <div style={{ color: '#6e7681', fontSize: 9, marginTop: 2 }}>{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ── IP list ── */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '12px 14px' }}>
        <div style={{
          color: '#8b949e', fontSize: 10, fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 10,
        }}>
          Source IPs ({ipRows.length})
        </div>

        {ipRows.length === 0 ? (
          <div style={{ color: '#6e7681', fontSize: 12, textAlign: 'center', paddingTop: 24 }}>
            No IP data available
          </div>
        ) : ipRows.map(row => (
          <div key={row.ip} style={{
            background: '#0d1929',
            border: `1px solid #1e2940`,
            borderLeft: `3px solid ${SEV_COL[row.maxSev]}`,
            borderRadius: 6, padding: '10px 12px', marginBottom: 8,
            animation: 'tgFadeIn .2s ease',
          }}>
            {/* IP + severity badge */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <code style={{
                color: '#58a6ff', fontSize: 12, fontFamily: '"SFMono-Regular",Consolas,monospace',
              }}>
                {row.ip}
              </code>
              <span style={{
                background: `${SEV_COL[row.maxSev]}22`, color: SEV_COL[row.maxSev],
                fontSize: 8, fontWeight: 700, padding: '2px 6px', borderRadius: 4,
                letterSpacing: '.05em',
              }}>
                {row.maxSev}
              </span>
            </div>

            {/* Attack types */}
            {row.types.size > 0 && (
              <div style={{
                color: '#8b949e', fontSize: 10, marginTop: 5,
                display: 'flex', flexWrap: 'wrap', gap: 4,
              }}>
                {[...row.types].slice(0, 3).map(t => (
                  <span key={t} style={{
                    background: '#1e2940', padding: '1px 6px', borderRadius: 3, fontSize: 9,
                  }}>
                    {t}
                  </span>
                ))}
                {row.types.size > 3 && (
                  <span style={{ color: '#6e7681', fontSize: 9 }}>+{row.types.size - 3} more</span>
                )}
              </div>
            )}

            {/* Alert count + timestamp */}
            <div style={{
              display: 'flex', justifyContent: 'space-between',
              marginTop: 6, paddingTop: 6, borderTop: '1px solid #1e2940',
            }}>
              <span style={{ color: '#8b949e', fontSize: 10 }}>
                {row.count} alert{row.count !== 1 ? 's' : ''}
              </span>
              {row.lastSeen && (
                <span style={{ color: '#6e7681', fontSize: 10 }}>
                  {new Date(row.lastSeen + (row.lastSeen.endsWith('Z') ? '' : 'Z')).toLocaleTimeString([], {
                    hour: '2-digit', minute: '2-digit',
                  })}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* ── Footer hint ── */}
      <div style={{
        padding: '10px 14px', borderTop: '1px solid #1e2940',
        color: '#6e7681', fontSize: 10, textAlign: 'center', flexShrink: 0,
      }}>
        Click another point to switch · Click ✕ to close
      </div>
    </div>
  );
}


// ── Main Globe Component ──────────────────────────────────────────────────────
export default function ThreatGlobe({ alerts }) {
  const containerRef = useRef(null);
  const globeRef     = useRef(null);
  const rotatingRef  = useRef(true);       // tracks current auto-rotate state
  const [dims, setDims]               = useState({ w: 800, h: 500 });
  const [hovered, setHovered]         = useState(null);
  const [selectedLocation, setSelectedLocation] = useState(null);

  // Responsive sizing
  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver(([e]) => {
      setDims({ w: e.contentRect.width, h: e.contentRect.height });
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  // Start auto-rotation after mount
  useEffect(() => {
    if (!globeRef.current) return;
    const timer = setTimeout(() => {
      try {
        const ctrl = globeRef.current.controls();
        ctrl.autoRotate      = true;
        ctrl.autoRotateSpeed = 0.4;
        rotatingRef.current  = true;
        globeRef.current.pointOfView({ altitude: 2.2 }, 1000);
      } catch {}
    }, 600);
    return () => clearTimeout(timer);
  }, []);

  // ── Pause / resume helpers ────────────────────────────────────────────────
  const pauseRotation = useCallback(() => {
    if (!globeRef.current || !rotatingRef.current) return;
    try {
      globeRef.current.controls().autoRotate = false;
      rotatingRef.current = false;
    } catch {}
  }, []);

  const resumeRotation = useCallback(() => {
    if (!globeRef.current || rotatingRef.current) return;
    try {
      globeRef.current.controls().autoRotate = true;
      rotatingRef.current = true;
    } catch {}
  }, []);

  // ── Build geo data from alerts ────────────────────────────────────────────
  const { points, arcs, stats } = useMemo(() => {
    const byCountry = {};
    let publicCount = 0;
    let privateCount = 0;

    alerts.forEach(a => {
      const cc  = (a.ip_country || '').toUpperCase();
      const sev = (a.severity || '').replace('SeverityLevel.', '') || 'LOW';

      if (!cc || !COORDS[cc]) { privateCount++; return; }
      publicCount++;

      if (!byCountry[cc]) {
        byCountry[cc] = {
          cc, lat: COORDS[cc][0], lng: COORDS[cc][1],
          count: 0, maxSev: 'LOW',
          ips: new Set(),
          alerts: [],          // full alert objects for the detail panel
        };
      }
      byCountry[cc].count++;
      byCountry[cc].maxSev = higherSev(byCountry[cc].maxSev, sev);
      if (a.src_ip) byCountry[cc].ips.add(a.src_ip);
      byCountry[cc].alerts.push(a);
    });

    const pts = Object.values(byCountry);

    const arcs = pts.map(p => ({
      startLat: p.lat, startLng: p.lng,
      endLat:   HOME.lat, endLng: HOME.lng,
      color: SEV_COL[p.maxSev] || '#58a6ff',
      count: p.count, cc: p.cc, sev: p.maxSev,
      _point: p,               // reference for click → panel
    }));

    return { points: pts, arcs, stats: { publicCount, privateCount, countries: pts.length } };
  }, [alerts]);

  // ── Click handlers ────────────────────────────────────────────────────────
  const handleLocationClick = useCallback((location) => {
    if (!location) return;
    // Toggle off if same country clicked again
    setSelectedLocation(prev => prev?.cc === location.cc ? null : location);
  }, []);

  const handlePointClick  = useCallback((point) => handleLocationClick(point), [handleLocationClick]);
  const handleArcClick    = useCallback((arc)   => handleLocationClick(arc._point), [handleLocationClick]);

  // ── Hover handlers (tooltip + rotation pause) ─────────────────────────────
  const handlePointHover = useCallback((point) => {
    setHovered(point);
    if (point) pauseRotation(); else resumeRotation();
  }, [pauseRotation, resumeRotation]);

  const handleArcHover = useCallback((arc) => {
    if (arc) pauseRotation(); else resumeRotation();
  }, [pauseRotation, resumeRotation]);

  const hasData = points.length > 0;

  return (
    <div
      ref={containerRef}
      style={{ flex: 1, position: 'relative', background: '#060b14', overflow: 'hidden' }}
      onMouseEnter={pauseRotation}
      onMouseLeave={resumeRotation}
    >

      {/* ── Header ── */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, zIndex: 10,
        padding: '16px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        background: 'linear-gradient(to bottom, #060b14ee, transparent)',
        pointerEvents: 'none',
      }}>
        <div>
          <div style={{ color: '#58a6ff', fontSize: 13, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.08em' }}>
            Global Threat Map
          </div>
          <div style={{ color: '#6e7681', fontSize: 11, marginTop: 2 }}>
            {hasData
              ? `${stats.countries} origin ${stats.countries === 1 ? 'country' : 'countries'} · ${stats.publicCount} public · ${stats.privateCount} internal`
              : `${stats.privateCount} internal network attacks · no public IPs to geolocate`}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 12, pointerEvents: 'none' }}>
          {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => (
            <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: SEV_COL[s] }} />
              <span style={{ color: '#6e7681', fontSize: 10 }}>{s}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── Hover tooltip ── */}
      {hovered && !selectedLocation && (
        <div style={{
          position: 'absolute', top: 64, left: 24, zIndex: 20,
          background: '#0d1929', border: `1px solid ${SEV_COL[hovered.maxSev]}44`,
          borderLeft: `3px solid ${SEV_COL[hovered.maxSev]}`,
          borderRadius: 8, padding: '12px 16px', minWidth: 180,
          pointerEvents: 'none',
          animation: 'tgFadeIn .15s ease',
        }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#c9d1d9', marginBottom: 8 }}>
            {hovered.cc}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {[
              ['Alerts',      hovered.count,    SEV_COL[hovered.maxSev]],
              ['Max Severity',hovered.maxSev,   SEV_COL[hovered.maxSev]],
              ['Unique IPs',  hovered.ips.size, '#58a6ff'],
            ].map(([label, value, color]) => (
              <div key={label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                <span style={{ color: '#6e7681' }}>{label}</span>
                <span style={{ color, fontWeight: 700 }}>{value}</span>
              </div>
            ))}
          </div>
          <div style={{ color: '#6e7681', fontSize: 9, marginTop: 8, textAlign: 'center' }}>
            Click to see IP list
          </div>
        </div>
      )}

      {/* ── No public IP notice ── */}
      {!hasData && (
        <div style={{
          position: 'absolute', bottom: 80, left: '50%', transform: 'translateX(-50%)',
          zIndex: 10, background: '#0d1929aa', border: '1px solid #1e2940',
          borderRadius: 8, padding: '10px 20px',
          color: '#6e7681', fontSize: 12, textAlign: 'center', pointerEvents: 'none',
        }}>
          All {stats.privateCount} attack{stats.privateCount !== 1 ? 's' : ''} from internal network (192.168.56.x) —
          globe activates with public IP attacks
        </div>
      )}

      {/* ── Defender marker ── */}
      <div style={{
        position: 'absolute', bottom: 24, right: selectedLocation ? 336 : 24,
        zIndex: 10,
        background: '#0d1929', border: '1px solid #3fb95044',
        borderLeft: '3px solid #3fb950',
        borderRadius: 8, padding: '8px 14px',
        pointerEvents: 'none',
        transition: 'right .22s cubic-bezier(.25,.46,.45,.94)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{
            width: 8, height: 8, borderRadius: '50%',
            background: '#3fb950', boxShadow: '0 0 8px #3fb950',
            animation: 'tgPulse 2s infinite',
          }} />
          <span style={{ color: '#3fb950', fontSize: 11, fontWeight: 600 }}>SentinelIQ — Active</span>
        </div>
      </div>

      {/* ── Location detail panel ── */}
      {selectedLocation && (
        <LocationPanel
          location={selectedLocation}
          onClose={() => setSelectedLocation(null)}
        />
      )}

      {/* ── Globe ── */}
      <Globe
        ref={globeRef}
        width={dims.w}
        height={dims.h}

        globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
        bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
        backgroundImageUrl="//unpkg.com/three-globe/example/img/night-sky.png"
        backgroundColor="rgba(6,11,20,1)"
        atmosphereColor="#1a3a6e"
        atmosphereAltitude={0.18}
        showGraticules={false}

        // Attack origin points
        pointsData={points}
        pointLat="lat"
        pointLng="lng"
        pointColor={d => selectedLocation?.cc === d.cc
          ? '#ffffff'
          : SEV_COL[d.maxSev] || '#58a6ff'
        }
        pointAltitude={d => 0.01 + Math.min(d.count * 0.008, 0.12)}
        pointRadius={d => {
          const base = 0.35 + Math.min(d.count * 0.04, 0.8);
          return selectedLocation?.cc === d.cc ? base * 1.6 : base;
        }}
        pointsMerge={false}
        onPointHover={handlePointHover}
        onPointClick={handlePointClick}

        // Animated attack arcs
        arcsData={arcs}
        arcStartLat="startLat"
        arcStartLng="startLng"
        arcEndLat="endLat"
        arcEndLng="endLng"
        arcColor={d => selectedLocation?.cc === d.cc ? '#ffffff' : d.color}
        arcAltitude={null}
        arcAltitudeAutoScale={0.4}
        arcStroke={d => {
          const base = 0.3 + Math.min(d.count * 0.05, 1.2);
          return selectedLocation?.cc === d.cc ? base * 2 : base;
        }}
        arcDashLength={0.35}
        arcDashGap={0.15}
        arcDashAnimateTime={d => Math.max(800, 2000 - d.count * 80)}
        onArcHover={handleArcHover}
        onArcClick={handleArcClick}

        // Defender home ring
        ringsData={[{ lat: HOME.lat, lng: HOME.lng }]}
        ringLat="lat"
        ringLng="lng"
        ringColor={() => '#3fb950'}
        ringMaxRadius={3}
        ringPropagationSpeed={2}
        ringRepeatPeriod={1000}
      />
    </div>
  );
}
