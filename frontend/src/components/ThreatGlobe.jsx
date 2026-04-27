import { useRef, useEffect, useState, useMemo } from 'react';
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
  // Extra for common attackers
  TOR:[0,0], // Tor exit nodes placeholder
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

// Defender home — Morocco (adjust if needed)
const HOME = { lat: 31.79, lng: -7.09, label: 'SentinelIQ' };

export default function ThreatGlobe({ alerts }) {
  const containerRef = useRef(null);
  const globeRef     = useRef(null);
  const [dims, setDims]       = useState({ w: 800, h: 500 });
  const [hovered, setHovered] = useState(null);

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
        globeRef.current.controls().autoRotate = true;
        globeRef.current.controls().autoRotateSpeed = 0.4;
        globeRef.current.pointOfView({ altitude: 2.2 }, 1000);
      } catch {}
    }, 600);
    return () => clearTimeout(timer);
  }, []);

  // ── Build geo data from alerts ────────────────────────────────
  const { points, arcs, stats } = useMemo(() => {
    const byCountry = {};
    let publicCount = 0;
    let privateCount = 0;

    alerts.forEach(a => {
      const cc  = (a.ip_country || '').toUpperCase();
      const sev = (a.severity || '').replace('SeverityLevel.', '') || 'LOW';

      if (!cc || !COORDS[cc]) {
        privateCount++;
        return;
      }
      publicCount++;
      if (!byCountry[cc]) {
        byCountry[cc] = { cc, lat: COORDS[cc][0], lng: COORDS[cc][1], count: 0, maxSev: 'LOW', ips: new Set() };
      }
      byCountry[cc].count++;
      byCountry[cc].maxSev = higherSev(byCountry[cc].maxSev, sev);
      if (a.src_ip) byCountry[cc].ips.add(a.src_ip);
    });

    const pts = Object.values(byCountry);

    const arcs = pts.map(p => ({
      startLat: p.lat, startLng: p.lng,
      endLat: HOME.lat, endLng: HOME.lng,
      color: SEV_COL[p.maxSev] || '#58a6ff',
      count: p.count, cc: p.cc, sev: p.maxSev,
    }));

    return { points: pts, arcs, stats: { publicCount, privateCount, countries: pts.length } };
  }, [alerts]);

  const hasData = points.length > 0;

  return (
    <div ref={containerRef} style={{ flex: 1, position: 'relative', background: '#060b14', overflow: 'hidden' }}>

      {/* Header */}
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

        {/* Legend */}
        <div style={{ display: 'flex', gap: 12, pointerEvents: 'none' }}>
          {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => (
            <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: SEV_COL[s] }} />
              <span style={{ color: '#6e7681', fontSize: 10 }}>{s}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Hovered country tooltip */}
      {hovered && (
        <div style={{
          position: 'absolute', top: 64, left: 24, zIndex: 20,
          background: '#0d1929', border: `1px solid ${SEV_COL[hovered.maxSev]}44`,
          borderLeft: `3px solid ${SEV_COL[hovered.maxSev]}`,
          borderRadius: 8, padding: '12px 16px', minWidth: 180,
          pointerEvents: 'none',
          animation: 'slideIn .15s ease',
        }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#c9d1d9', marginBottom: 8 }}>
            {hovered.cc}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
              <span style={{ color: '#6e7681' }}>Alerts</span>
              <span style={{ color: SEV_COL[hovered.maxSev], fontWeight: 700 }}>{hovered.count}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
              <span style={{ color: '#6e7681' }}>Max Severity</span>
              <span style={{ color: SEV_COL[hovered.maxSev], fontWeight: 700 }}>{hovered.maxSev}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
              <span style={{ color: '#6e7681' }}>Unique IPs</span>
              <span style={{ color: '#58a6ff' }}>{hovered.ips.size}</span>
            </div>
          </div>
        </div>
      )}

      {/* No public IP notice */}
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

      {/* Defender marker overlay (always visible) */}
      <div style={{
        position: 'absolute', bottom: 24, right: 24, zIndex: 10,
        background: '#0d1929', border: '1px solid #3fb95044',
        borderLeft: '3px solid #3fb950',
        borderRadius: 8, padding: '8px 14px',
        pointerEvents: 'none',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{
            width: 8, height: 8, borderRadius: '50%',
            background: '#3fb950',
            boxShadow: '0 0 8px #3fb950',
            animation: 'pulse 2s infinite',
          }} />
          <span style={{ color: '#3fb950', fontSize: 11, fontWeight: 600 }}>SentinelIQ — Active</span>
        </div>
      </div>

      {/* The Globe */}
      <Globe
        ref={globeRef}
        width={dims.w}
        height={dims.h}

        // Visuals
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
        pointColor={d => SEV_COL[d.maxSev] || '#58a6ff'}
        pointAltitude={d => 0.01 + Math.min(d.count * 0.008, 0.12)}
        pointRadius={d => 0.35 + Math.min(d.count * 0.04, 0.8)}
        pointsMerge={false}
        onPointHover={setHovered}

        // Animated attack arcs
        arcsData={arcs}
        arcStartLat="startLat"
        arcStartLng="startLng"
        arcEndLat="endLat"
        arcEndLng="endLng"
        arcColor="color"
        arcAltitude={null}
        arcAltitudeAutoScale={0.4}
        arcStroke={d => 0.3 + Math.min(d.count * 0.05, 1.2)}
        arcDashLength={0.35}
        arcDashGap={0.15}
        arcDashAnimateTime={d => Math.max(800, 2000 - d.count * 80)}

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
