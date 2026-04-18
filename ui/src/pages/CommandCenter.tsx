import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'

const API = '/api'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Stats {
  total_1h: number; critical_1h: number; high_1h: number
  auto_remediated_1h: number; false_positives_1h: number; total_all_time: number
}

interface Incident {
  id: string; ts: number; rule: string; severity: string
  namespace: string; hostname: string; action_taken: string; confidence: number
}

interface Particle {
  id: string; incident: Incident; currentSegment: number; color: string; animKey: number
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff2d55', HIGH: '#ff9f0a', MED: '#ffd700', MEDIUM: '#ffd700', LOW: '#8b949e',
}

const SEV_PARTICLE: Record<string, { size: number; clip?: string; br: string }> = {
  CRITICAL: { size: 10, clip: 'polygon(50% 0%,100% 50%,50% 100%,0% 50%)', br: '0' },
  HIGH:     { size: 8,  br: '50%' },
  MED:      { size: 7,  br: '3px' },
  MEDIUM:   { size: 7,  br: '3px' },
  LOW:      { size: 5,  br: '50%' },
}

const LAYERS = [
  { name: 'Falco',    sub: 'Runtime Detection',  color: '#ff9f0a', icon: '🔍', desc: 'Syscall-level detection via eBPF. Shell spawns, file reads, privilege escalation.',  m1: 'Events',      m2: 'Blocked',    activity: 78 },
  { name: 'eBPF',     sub: 'Kernel Layer',        color: '#58a6ff', icon: '⚡', desc: 'CO-RE kernel instrumentation. Raw syscalls before userspace.',                       m1: 'Flows',       m2: 'Dropped',    activity: 91 },
  { name: 'Kyverno',  sub: 'Admission Control',   color: '#bc8cff', icon: '🛡', desc: 'Policy-as-code admission webhooks. Rejects non-compliant workloads.',                m1: 'Policies',    m2: 'Violations', activity: 34 },
  { name: 'Cilium',   sub: 'Network Layer',       color: '#00ff9f', icon: '🌐', desc: 'L3/L4/L7 zero-trust. Default-deny with explicit allow, all flows in Hubble.',       m1: 'Connections', m2: 'Denied',     activity: 65 },
  { name: 'Argus AI', sub: 'AI Analysis',         color: '#00d4ff', icon: '🧠', desc: 'Claude reasoning layer. Enriches context, scores blast radius, routes actions.',     m1: 'Decisions',   m2: 'Auto-fixed', activity: 55 },
]

// CSS keyframe per layer color — all same timing so they glow together
const LAYER_GLOW_CSS = LAYERS.map((l, i) => `
  @keyframes layerGlow${i} {
    0%,100% { box-shadow: 0 4px 14px ${l.color}18, inset 0 1px 0 ${l.color}15; border-color: ${l.color}42; }
    50%     { box-shadow: 0 0 32px ${l.color}70, 0 0 64px ${l.color}28, inset 0 1px 0 ${l.color}38; border-color: ${l.color}99; }
  }
`).join('')

const MOCK_INCIDENTS: Incident[] = [
  { id: 'm1',  ts: Date.now()/1000-30,  rule: 'Shell Spawned in Container',                severity: 'CRITICAL', namespace: 'production',  hostname: 'k3s-worker1', action_taken: 'KILL',           confidence: 0.92 },
  { id: 'm2',  ts: Date.now()/1000-80,  rule: 'Outbound Connection to Rare External IP',   severity: 'HIGH',     namespace: 'staging',     hostname: 'k3s-worker2', action_taken: 'NOTIFY',         confidence: 0.77 },
  { id: 'm3',  ts: Date.now()/1000-140, rule: 'Sensitive File Read — /etc/shadow',          severity: 'HIGH',     namespace: 'production',  hostname: 'k3s-master',  action_taken: 'ISOLATE',        confidence: 0.84 },
  { id: 'm4',  ts: Date.now()/1000-210, rule: 'Kyverno: Disallowed Image Registry',         severity: 'MED',      namespace: 'kube-system', hostname: 'k3s-worker1', action_taken: 'LOG',            confidence: 0.65 },
  { id: 'm5',  ts: Date.now()/1000-290, rule: 'Privilege Escalation — sudo Execution',      severity: 'CRITICAL', namespace: 'production',  hostname: 'k3s-worker2', action_taken: 'HUMAN_REQUIRED', confidence: 0.71 },
  { id: 'm6',  ts: Date.now()/1000-370, rule: 'Cilium Egress Policy Blocked',               severity: 'LOW',      namespace: 'monitoring',  hostname: 'k3s-master',  action_taken: 'LOG',            confidence: 0.45 },
  { id: 'm7',  ts: Date.now()/1000-440, rule: 'Unexpected DNS Exfil Pattern',               severity: 'MED',      namespace: 'production',  hostname: 'k3s-worker1', action_taken: 'NOTIFY',         confidence: 0.58 },
  { id: 'm8',  ts: Date.now()/1000-510, rule: 'Image from Unregistered Registry',           severity: 'HIGH',     namespace: 'staging',     hostname: 'k3s-worker2', action_taken: 'ISOLATE',        confidence: 0.88 },
  { id: 'm9',  ts: Date.now()/1000-590, rule: 'Write Below Binary Dir (/usr/bin)',           severity: 'CRITICAL', namespace: 'default',     hostname: 'k3s-worker1', action_taken: 'KILL',           confidence: 0.95 },
  { id: 'm10', ts: Date.now()/1000-650, rule: 'K8s Service Account Token Mount',            severity: 'HIGH',     namespace: 'production',  hostname: 'k3s-master',  action_taken: 'NOTIFY',         confidence: 0.73 },
]

const MOCK_POOL: Omit<Incident, 'id' | 'ts'>[] = [
  { rule: 'Shell Spawned in Container',             severity: 'CRITICAL', namespace: 'production',  hostname: 'k3s-worker1', action_taken: 'KILL',           confidence: 0.93 },
  { rule: 'Outbound C2 Callback Detected',          severity: 'CRITICAL', namespace: 'staging',     hostname: 'k3s-worker2', action_taken: 'ISOLATE',        confidence: 0.89 },
  { rule: 'Sensitive File Read — /etc/passwd',      severity: 'HIGH',     namespace: 'production',  hostname: 'k3s-master',  action_taken: 'NOTIFY',         confidence: 0.76 },
  { rule: 'Kyverno: Privileged Pod Rejected',       severity: 'MED',      namespace: 'kube-system', hostname: 'k3s-worker1', action_taken: 'LOG',            confidence: 0.62 },
  { rule: 'Privilege Escalation via SUID Binary',   severity: 'CRITICAL', namespace: 'production',  hostname: 'k3s-worker2', action_taken: 'HUMAN_REQUIRED', confidence: 0.68 },
  { rule: 'Unexpected DNS Lookup (data.exfil.io)',  severity: 'HIGH',     namespace: 'production',  hostname: 'k3s-worker1', action_taken: 'NOTIFY',         confidence: 0.81 },
  { rule: 'Cilium L7 Policy Violation',             severity: 'MED',      namespace: 'monitoring',  hostname: 'k3s-master',  action_taken: 'LOG',            confidence: 0.54 },
  { rule: 'Write to Container Root Filesystem',     severity: 'HIGH',     namespace: 'staging',     hostname: 'k3s-worker2', action_taken: 'ISOLATE',        confidence: 0.85 },
  { rule: 'Crypto Miner Process Detected',          severity: 'CRITICAL', namespace: 'default',     hostname: 'k3s-worker1', action_taken: 'KILL',           confidence: 0.97 },
  { rule: 'K8s Secret Accessed via API',            severity: 'HIGH',     namespace: 'production',  hostname: 'k3s-master',  action_taken: 'NOTIFY',         confidence: 0.74 },
  { rule: 'Network Port Scan from Pod',             severity: 'HIGH',     namespace: 'staging',     hostname: 'k3s-worker2', action_taken: 'ISOLATE',        confidence: 0.79 },
  { rule: 'Proc Mount Inside Container',            severity: 'MED',      namespace: 'kube-system', hostname: 'k3s-worker1', action_taken: 'LOG',            confidence: 0.60 },
]

type NotifyChannel = { id: 'slack' | 'pagerduty' | 'email'; color: string }

function getNotifyChannel(id: string): NotifyChannel {
  const n = id.split('').reduce((a, c) => a + c.charCodeAt(0), 0) % 3
  return ([
    { id: 'slack',     color: '#36C5F0' },
    { id: 'pagerduty', color: '#06AC38' },
    { id: 'email',     color: '#a78bfa' },
  ] as NotifyChannel[])[n]
}

// Inline SVG brand icons
function SlackIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none">
      <path d="M6 15a2 2 0 0 1-2 2 2 2 0 0 1-2-2 2 2 0 0 1 2-2h2v2zm1 0a2 2 0 0 1 2-2 2 2 0 0 1 2 2v5a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-5z" fill="#E01E5A"/>
      <path d="M9 6a2 2 0 0 1-2-2 2 2 0 0 1 2-2 2 2 0 0 1 2 2v2H9zm0 1a2 2 0 0 1 2 2 2 2 0 0 1-2 2H4a2 2 0 0 1-2-2 2 2 0 0 1 2-2h5z" fill="#36C5F0"/>
      <path d="M18 9a2 2 0 0 1 2 2 2 2 0 0 1-2 2 2 2 0 0 1-2-2V9h2zm-1 0a2 2 0 0 1-2-2 2 2 0 0 1 2-2h5a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-5z" fill="#2EB67D"/>
      <path d="M15 18a2 2 0 0 1 2-2 2 2 0 0 1 2 2 2 2 0 0 1-2 2h-2v-2zm-1 0a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2 2 2 0 0 1 2 2v5z" fill="#ECB22E"/>
    </svg>
  )
}

function PagerDutyIcon() {
  return (
    <svg width="9" height="12" viewBox="0 0 9 12" fill="#06AC38">
      <path d="M5.5 0L0 6.5h3.5L2 12l7-8H5L5.5 0z"/>
    </svg>
  )
}

function EmailIcon() {
  return (
    <svg width="13" height="10" viewBox="0 0 13 10" fill="none" stroke="#a78bfa" strokeWidth="1.4" strokeLinejoin="round">
      <rect x="0.7" y="0.7" width="11.6" height="8.6" rx="1.3"/>
      <path d="M1 1.5l5.5 4.5L12 1.5" strokeLinecap="round"/>
    </svg>
  )
}

function NotifyBadge({ channel }: { channel: NotifyChannel }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '4px',
      padding: '2px 7px 2px 5px', borderRadius: '4px',
      background: `${channel.color}18`, border: `1px solid ${channel.color}40`,
      fontSize: '8px', fontWeight: 700, color: channel.color,
      fontFamily: 'JetBrains Mono, monospace', flexShrink: 0,
    }}>
      {channel.id === 'slack'     && <SlackIcon />}
      {channel.id === 'pagerduty' && <PagerDutyIcon />}
      {channel.id === 'email'     && <EmailIcon />}
      {channel.id === 'slack'     ? 'Slack' : channel.id === 'pagerduty' ? 'PagerDuty' : 'Email'}
    </span>
  )
}

function ActionBadge({ action }: { action: string }) {
  if (action === 'HUMAN_REQUIRED') {
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: '4px',
        padding: '2px 7px', borderRadius: '4px',
        background: 'rgba(255,107,53,0.1)', border: '1px solid rgba(255,107,53,0.35)',
        fontSize: '8px', fontWeight: 700, color: '#ff6b35',
        fontFamily: 'Inter, sans-serif', flexShrink: 0, letterSpacing: '0.2px',
      }}>
        <svg width="9" height="10" viewBox="0 0 9 10" fill="none" stroke="#ff6b35" strokeWidth="1.4">
          <circle cx="4.5" cy="3" r="2"/>
          <path d="M1 9c0-1.9 1.6-3.5 3.5-3.5S8 7.1 8 9" strokeLinecap="round"/>
        </svg>
        Review Required
      </span>
    )
  }
  if (action === 'KILL') {
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)', fontSize: '8px', fontWeight: 700, color: '#ff2d55', fontFamily: 'Inter, sans-serif', flexShrink: 0 }}>
        <svg width="8" height="8" viewBox="0 0 8 8" fill="none" stroke="#ff2d55" strokeWidth="1.5" strokeLinecap="round"><line x1="1" y1="1" x2="7" y2="7"/><line x1="7" y1="1" x2="1" y2="7"/></svg>
        Terminated
      </span>
    )
  }
  if (action === 'ISOLATE') {
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(255,159,10,0.1)', border: '1px solid rgba(255,159,10,0.3)', fontSize: '8px', fontWeight: 700, color: '#ff9f0a', fontFamily: 'Inter, sans-serif', flexShrink: 0 }}>
        <svg width="8" height="9" viewBox="0 0 8 9" fill="none" stroke="#ff9f0a" strokeWidth="1.4"><rect x="1" y="4" width="6" height="4.5" rx="0.8"/><path d="M2.5 4V2.8a1.5 1.5 0 0 1 3 0V4" strokeLinecap="round"/></svg>
        Isolated
      </span>
    )
  }
  if (action === 'LOG') {
    return <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>Logged</span>
  }
  return <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>{action}</span>
}

function getStartSegment(inc: Incident): number {
  const r = (inc.rule + ' ' + inc.namespace).toLowerCase()
  if (r.includes('network') || r.includes('connect') || r.includes('outbound') || r.includes('dns') || r.includes('egress') || r.includes('flow') || r.includes('cilium') || r.includes('scan')) return 3
  if (r.includes('kyverno') || r.includes('admission') || r.includes('policy') || r.includes('registry') || r.includes('image') || r.includes('mount')) return 2
  if (r.includes('exec') || r.includes('shell') || r.includes('terminal') || r.includes('spawn') || r.includes('privilege') || r.includes('suid') || r.includes('escalat') || r.includes('proc')) return 1
  return inc.severity === 'CRITICAL' ? 0 : (inc.id.charCodeAt(0) % 2 === 0 ? 0 : 1)
}

// ─── Detection Pipeline ───────────────────────────────────────────────────────

function DetectionLayerFlow({ incidents }: { incidents: Incident[] }) {
  const navigate = useNavigate()
  const [particles, setParticles] = useState<Particle[]>([])
  const [hover, setHover] = useState<{ particle: Particle; x: number; y: number } | null>(null)
  const [layerStats, setLayerStats] = useState(() =>
    LAYERS.map(() => ({ v1: 0, v2: 0, rate: 0 }))
  )
  const seenIds = useRef(new Set<string>())

  // Live-updating layer metrics
  useEffect(() => {
    const refresh = () => {
      setLayerStats([
        { v1: Math.floor(Math.random() * 50) + 100,   v2: Math.floor(Math.random() * 10) + 5,  rate: Math.random() * 20 + 10 },
        { v1: Math.floor(Math.random() * 1000) + 5000, v2: Math.floor(Math.random() * 50) + 20, rate: Math.random() * 100 + 200 },
        { v1: 12,                                       v2: Math.floor(Math.random() * 5) + 2,   rate: Math.random() * 5 + 2 },
        { v1: Math.floor(Math.random() * 2000) + 10000,v2: Math.floor(Math.random() * 30) + 10, rate: Math.random() * 150 + 300 },
        { v1: Math.floor(Math.random() * 20) + 50,     v2: Math.floor(Math.random() * 8) + 3,   rate: Math.random() * 3 + 1 },
      ])
    }
    refresh()
    const t = setInterval(refresh, 3000)
    return () => clearInterval(t)
  }, [])

  // Inject new incidents as particles
  useEffect(() => {
    const newIncs = incidents.filter(inc => !seenIds.current.has(inc.id))
    if (!newIncs.length) return
    newIncs.forEach(inc => seenIds.current.add(inc.id))
    setParticles(prev => [
      ...prev,
      ...newIncs.map(inc => ({
        id: inc.id, incident: inc,
        currentSegment: getStartSegment(inc),
        color: SEV_COLOR[inc.severity] || '#8b949e',
        animKey: 0,
      })),
    ].slice(-20))
  }, [incidents])

  const handleAnimEnd = (pid: string, seg: number) => {
    if (seg >= 3) {
      setParticles(prev => prev.filter(p => p.id !== pid))
    } else {
      setParticles(prev => prev.map(p =>
        p.id === pid && p.currentSegment === seg
          ? { ...p, currentSegment: seg + 1, animKey: p.animKey + 1 }
          : p
      ))
    }
  }

  const fmtAge = (ts: number) => {
    const s = Math.floor((Date.now() - ts * 1000) / 1000)
    return s < 60 ? `${s}s ago` : `${Math.floor(s / 60)}m ago`
  }

  return (
    <div style={{ padding: '16px 16px 12px', position: 'relative' }}>
      <style>{`
        ${LAYER_GLOW_CSS}
        @keyframes travelSeg {
          0%   { left: -2%;  opacity: 0; }
          8%   { opacity: 1; }
          86%  { opacity: 1; }
          100% { left: 102%; opacity: 0; }
        }
        @keyframes glowpulse { 0%,100%{opacity:1} 50%{opacity:0.45} }
      `}</style>

      <div style={{ display: 'flex', alignItems: 'stretch' }}>
        {LAYERS.flatMap((layer, i) => {
          const segParticles = particles.filter(p => p.currentSegment === i)
          const stats = layerStats[i]
          const items = []

          // Layer card
          items.push(
            <div key={`node-${i}`} style={{ flex: '0 0 auto', width: '152px' }}>
              <div style={{
                background: `linear-gradient(160deg, ${layer.color}12 0%, ${layer.color}05 100%)`,
                border: `1.5px solid ${layer.color}40`,
                borderRadius: '12px',
                padding: '14px 12px',
                position: 'relative',
                height: '100%',
                boxSizing: 'border-box',
                animation: `layerGlow${i} 4s ease-in-out infinite`,
              }}>
                <div style={{ position: 'absolute', top: '9px', left: '10px', fontSize: '7px', color: `${layer.color}70`, fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>L{i + 1}</div>

                <div style={{ textAlign: 'center', marginTop: '4px', marginBottom: '8px' }}>
                  <div style={{ fontSize: '20px', marginBottom: '4px' }}>{layer.icon}</div>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: layer.color, fontFamily: 'JetBrains Mono, monospace' }}>{layer.name}</div>
                  <div style={{ fontSize: '8px', color: '#8892a4', marginTop: '2px' }}>{layer.sub}</div>
                </div>

                <div style={{ fontSize: '7px', color: '#5a6478', lineHeight: 1.5, marginBottom: '10px', textAlign: 'center' }}>{layer.desc}</div>

                {/* Live metrics */}
                <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '6px', padding: '6px 8px', display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '7px', color: '#5a6478' }}>{layer.m1}</span>
                    <span style={{ fontSize: '10px', color: '#e6edf3', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>{stats.v1}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '7px', color: '#5a6478' }}>{layer.m2}</span>
                    <span style={{ fontSize: '10px', color: layer.color, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>{stats.v2}</span>
                  </div>
                  <div style={{ height: '3px', background: 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden', marginTop: '2px' }}>
                    <div style={{ height: '100%', width: `${layer.activity}%`, background: `linear-gradient(90deg, ${layer.color}55, ${layer.color})`, borderRadius: '2px' }} />
                  </div>
                  <div style={{ fontSize: '7px', color: '#4a5568', textAlign: 'right', fontFamily: 'JetBrains Mono, monospace' }}>{stats.rate.toFixed(1)}/s</div>
                </div>
              </div>
            </div>
          )

          // Connector with travelling particles
          if (i < 4) {
            items.push(
              <div key={`conn-${i}`} style={{ flex: 1, position: 'relative', minWidth: '20px', display: 'flex', alignItems: 'center' }}>
                <div style={{
                  position: 'absolute', left: 0, right: 0,
                  height: '3px', top: '50%', transform: 'translateY(-50%)',
                  background: `linear-gradient(90deg, ${layer.color}28, ${LAYERS[i + 1].color}28)`,
                  borderRadius: '2px',
                }} />
                <div style={{
                  position: 'absolute', right: -1, top: '50%', transform: 'translateY(-50%)',
                  width: 0, height: 0,
                  borderTop: '4px solid transparent', borderBottom: '4px solid transparent',
                  borderLeft: `6px solid ${LAYERS[i + 1].color}55`,
                }} />

                {segParticles.map(p => {
                  const sv = SEV_PARTICLE[p.incident.severity] ?? SEV_PARTICLE.LOW
                  return (
                    <div
                      key={`${p.id}-${p.animKey}`}
                      style={{
                        position: 'absolute', top: '50%', left: 0,
                        width: `${sv.size}px`, height: `${sv.size}px`,
                        marginTop: `-${sv.size / 2}px`,
                        borderRadius: sv.br, clipPath: sv.clip,
                        background: `radial-gradient(circle at 35% 35%, ${p.color}ff, ${p.color}aa)`,
                        boxShadow: `0 0 8px ${p.color}, 0 0 16px ${p.color}70`,
                        cursor: 'pointer', zIndex: 20, pointerEvents: 'all',
                        animation: `travelSeg ${6 + i * 0.5}s linear forwards`,
                      }}
                      onAnimationEnd={() => handleAnimEnd(p.id, i)}
                      onMouseEnter={e => setHover({ particle: p, x: e.clientX, y: e.clientY })}
                      onMouseMove={e => setHover(prev => prev ? { ...prev, x: e.clientX, y: e.clientY } : null)}
                      onMouseLeave={() => setHover(null)}
                      onClick={e => { e.stopPropagation(); navigate(`/threats?id=${p.incident.id}`) }}
                    />
                  )
                })}
              </div>
            )
          }

          return items
        })}
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginTop: '10px', justifyContent: 'center' }}>
        {(['CRITICAL', 'HIGH', 'MED', 'LOW'] as const).map(sev => {
          const sv = SEV_PARTICLE[sev]; const c = SEV_COLOR[sev]
          return (
            <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <div style={{ width: `${sv.size}px`, height: `${sv.size}px`, borderRadius: sv.br, clipPath: sv.clip, background: c, boxShadow: `0 0 5px ${c}80`, flexShrink: 0 }} />
              <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>{sev}</span>
            </div>
          )
        })}
        <span style={{ fontSize: '8px', color: '#3d4a5f', marginLeft: 'auto' }}>
          {particles.length > 0 ? `${particles.length} signal${particles.length > 1 ? 's' : ''} in flight · hover to inspect · click → threat feed` : 'signals injected at detection origin · travel to AI analysis'}
        </span>
      </div>

      {/* Hover tooltip */}
      {hover && (
        <div style={{
          position: 'fixed',
          left: Math.min(hover.x + 18, window.innerWidth - 260),
          top: Math.max(hover.y - 115, 10),
          background: 'linear-gradient(135deg, #0d1421, #0a1018)',
          border: `1px solid ${hover.particle.color}70`,
          borderRadius: '12px', padding: '14px 16px',
          zIndex: 9999, width: '240px',
          boxShadow: `0 12px 40px rgba(0,0,0,0.7), 0 0 0 1px ${hover.particle.color}18`,
          pointerEvents: 'none',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '9px' }}>
            {(() => {
              const sv = SEV_PARTICLE[hover.particle.incident.severity] ?? SEV_PARTICLE.LOW
              const c = SEV_COLOR[hover.particle.incident.severity]
              return <div style={{ width: `${sv.size + 1}px`, height: `${sv.size + 1}px`, borderRadius: sv.br, clipPath: sv.clip, background: c, boxShadow: `0 0 6px ${c}`, flexShrink: 0 }} />
            })()}
            <span style={{ fontSize: '10px', fontWeight: 700, color: SEV_COLOR[hover.particle.incident.severity], fontFamily: 'JetBrains Mono, monospace', letterSpacing: '1px' }}>{hover.particle.incident.severity}</span>
            <span style={{ fontSize: '8px', color: '#5a6478', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>{fmtAge(hover.particle.incident.ts)}</span>
          </div>
          <div style={{ fontSize: '12px', color: '#e6edf3', lineHeight: 1.45, marginBottom: '8px' }}>{hover.particle.incident.rule}</div>
          <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap', marginBottom: '8px' }}>
            {hover.particle.incident.namespace && <span style={{ fontSize: '9px', color: '#58a6ff', background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.22)', padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{hover.particle.incident.namespace}</span>}
            {hover.particle.incident.hostname && <span style={{ fontSize: '9px', color: '#8892a4', background: 'rgba(136,146,164,0.1)', border: '1px solid rgba(136,146,164,0.2)', padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{hover.particle.incident.hostname}</span>}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '8px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <span style={{ fontSize: '9px', fontWeight: 700, color: hover.particle.color, fontFamily: 'JetBrains Mono, monospace' }}>{hover.particle.incident.action_taken}</span>
            <span style={{ fontSize: '8px', color: '#4a5568' }}>click → threat feed</span>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Sparkline ────────────────────────────────────────────────────────────────

function MiniSparkline({ data, color }: { data: number[]; color: string }) {
  const max = Math.max(...data, 1)
  const w = 80, h = 28
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - (v / max) * h}`).join(' ')
  return (
    <svg width={w} height={h} style={{ flexShrink: 0 }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" opacity="0.8" />
      <polyline points={`0,${h} ${pts} ${w},${h}`} fill={color} fillOpacity="0.08" stroke="none" />
    </svg>
  )
}

// ─── Live Event Ticker ────────────────────────────────────────────────────────

function LiveEventTicker({ incidents }: { incidents: Incident[] }) {
  const navigate = useNavigate()
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => { if (ref.current) ref.current.scrollTop = 0 }, [incidents.length])

  const fmt = (ts: number) => {
    const diff = Math.floor((Date.now() - ts * 1000) / 1000)
    return diff < 60 ? `${diff}s` : `${Math.floor(diff / 60)}m`
  }

  return (
    <div ref={ref} style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '2px' }}>
      {incidents.slice(0, 20).map((inc, i) => {
        const isNotify = inc.action_taken === 'NOTIFY'
        const channel = isNotify ? getNotifyChannel(inc.id) : null

        return (
          <div
            key={inc.id}
            onClick={() => navigate(`/threats?id=${inc.id}`)}
            style={{
              display: 'flex', alignItems: 'center', gap: '8px', padding: '5px 8px',
              background: i === 0 ? 'rgba(0,255,159,0.04)' : 'transparent',
              borderRadius: '5px',
              borderLeft: `2px solid ${SEV_COLOR[inc.severity] || '#4a5568'}`,
              animation: i === 0 ? 'fadeInUp 0.3s ease-out' : 'none',
              cursor: 'pointer', transition: 'background 0.15s',
            }}
            onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.background = 'rgba(255,255,255,0.03)' }}
            onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.background = i === 0 ? 'rgba(0,255,159,0.04)' : 'transparent' }}
          >
            <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace', width: '22px', flexShrink: 0 }}>{fmt(inc.ts)}</span>
            <span style={{ fontSize: '9px', fontWeight: 700, color: SEV_COLOR[inc.severity], fontFamily: 'JetBrains Mono, monospace', width: '14px', flexShrink: 0 }}>
              {inc.severity === 'CRITICAL' ? '◆' : inc.severity === 'HIGH' ? '●' : inc.severity === 'MED' || inc.severity === 'MEDIUM' ? '▪' : '·'}
            </span>
            <span style={{ fontSize: '10px', color: '#d1d5db', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inc.rule}</span>
            {inc.namespace && <span style={{ fontSize: '7px', color: '#58a6ff', background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.2)', padding: '1px 4px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>{inc.namespace}</span>}
            {isNotify && channel
              ? <NotifyBadge channel={channel} />
              : <ActionBadge action={inc.action_taken} />
            }
          </div>
        )
      })}
      {incidents.length === 0 && <div style={{ color: '#4a5568', fontSize: '10px', textAlign: 'center', padding: '20px' }}>No events yet</div>}
    </div>
  )
}

// ─── Security Layer Row ───────────────────────────────────────────────────────

function SecurityLayerRow({ name, status, detail, icon }: { name: string; status: 'active' | 'degraded' | 'inactive'; detail: string; icon: string }) {
  const colors = { active: '#00ff9f', degraded: '#ff9f0a', inactive: '#4a5568' }
  const color = colors[status]
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', border: `1px solid ${color}18` }}>
      <span style={{ fontSize: '13px', flexShrink: 0 }}>{icon}</span>
      <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: color, boxShadow: status === 'active' ? `0 0 5px ${color}` : 'none', flexShrink: 0, animation: status === 'active' ? 'glowpulse 3s infinite' : 'none' }} />
      <span style={{ fontSize: '10px', color: '#e6edf3', flex: 1 }}>{name}</span>
      <span style={{ fontSize: '8px', color: '#4a5568' }}>{detail}</span>
      <span style={{ fontSize: '7px', color, background: `${color}18`, border: `1px solid ${color}33`, padding: '1px 5px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace' }}>{status}</span>
    </div>
  )
}

// ─── Node Health Bar ──────────────────────────────────────────────────────────

function NodeHealthBar({ name, ip, status, podCount, cpuPct, memPct }: { name: string; ip: string; status: string; podCount: number; cpuPct: number; memPct: number }) {
  const color = status === 'threat' ? '#ff2d55' : status === 'warning' ? '#ff9f0a' : '#00ff9f'
  return (
    <div style={{ background: '#111827', border: `1px solid ${color}22`, borderRadius: '8px', padding: '10px 12px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '7px', marginBottom: '8px' }}>
        <div style={{ width: '7px', height: '7px', borderRadius: '50%', background: color, boxShadow: `0 0 5px ${color}`, animation: status === 'threat' ? 'glowpulse 1.5s infinite' : 'none' }} />
        <span style={{ fontSize: '10px', fontWeight: 700, color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>{name}</span>
        <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>{ip}</span>
        <span style={{ fontSize: '8px', color, marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>{podCount} pods</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        {[{ label: 'CPU', pct: cpuPct, color: cpuPct > 80 ? '#ff2d55' : cpuPct > 60 ? '#ff9f0a' : '#00ff9f' }, { label: 'MEM', pct: memPct, color: memPct > 80 ? '#ff2d55' : memPct > 60 ? '#ff9f0a' : '#58a6ff' }].map(({ label, pct, color: bc }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace', width: '28px' }}>{label}</span>
            <div style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px', overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${pct}%`, background: bc, borderRadius: '2px', transition: 'width 1s ease-out' }} />
            </div>
            <span style={{ fontSize: '8px', color: bc, fontFamily: 'JetBrains Mono, monospace', width: '28px', textAlign: 'right' }}>{pct}%</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Command Center Page ──────────────────────────────────────────────────────

export default function CommandCenter() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [incidents, setIncidents] = useState<Incident[]>(MOCK_INCIDENTS)
  const [liveConnected, setLiveConnected] = useState(false)
  const mockPoolIndex = useRef(0)
  const mockTimer = useRef<ReturnType<typeof setInterval> | null>(null)
  const [sparkData] = useState(() => ({
    critical: Array.from({ length: 12 }, () => Math.floor(Math.random() * 5)),
    events: Array.from({ length: 12 }, () => Math.floor(Math.random() * 30) + 10),
  }))

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [sRes, iRes] = await Promise.all([
          fetch(`${API}/incidents/stats`),
          fetch(`${API}/incidents?limit=50`),
        ])
        if (sRes.ok) setStats(await sRes.json())
        if (iRes.ok) {
          const data = await iRes.json()
          if (data.incidents?.length) { setIncidents(data.incidents); setLiveConnected(true) }
        }
      } catch {}
    }
    fetchAll()
    const t = setInterval(fetchAll, 5000)
    return () => clearInterval(t)
  }, [])

  // Demo mode: inject a varied mock incident every 7s
  useEffect(() => {
    if (liveConnected) return
    mockTimer.current = setInterval(() => {
      const tpl = MOCK_POOL[mockPoolIndex.current % MOCK_POOL.length]
      mockPoolIndex.current++
      setIncidents(prev => [{ ...tpl, id: `live-${Date.now()}`, ts: Date.now() / 1000 }, ...prev].slice(0, 30))
    }, 7000)
    return () => { if (mockTimer.current) clearInterval(mockTimer.current) }
  }, [liveConnected])

  const kpis = stats
    ? [
        { label: 'Active (1h)',      value: stats.total_1h,             color: '#ff9f0a', spark: sparkData.events },
        { label: 'Critical',         value: stats.critical_1h,          color: '#ff2d55', spark: sparkData.critical },
        { label: 'Auto-remediated',  value: stats.auto_remediated_1h,   color: '#58a6ff', spark: null },
        { label: 'False positives',  value: stats.false_positives_1h,   color: '#00ff9f', spark: null },
        { label: 'High severity',    value: stats.high_1h,              color: '#ff9f0a', spark: null },
        { label: 'Total all time',   value: stats.total_all_time,        color: '#bc8cff', spark: null },
      ]
    : [
        { label: 'Active (1h)',      value: incidents.filter(x => x.severity !== 'LOW').length,                               color: '#ff9f0a', spark: sparkData.events },
        { label: 'Critical',         value: incidents.filter(x => x.severity === 'CRITICAL').length,                          color: '#ff2d55', spark: sparkData.critical },
        { label: 'Auto-remediated',  value: incidents.filter(x => x.action_taken === 'KILL' || x.action_taken === 'ISOLATE').length, color: '#58a6ff', spark: null },
        { label: 'False positives',  value: 1,                                                                                 color: '#00ff9f', spark: null },
        { label: 'High severity',    value: incidents.filter(x => x.severity === 'HIGH').length,                              color: '#ff9f0a', spark: null },
        { label: 'Total all time',   value: incidents.length,                                                                  color: '#bc8cff', spark: null },
      ]

  return (
    <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <style>{`
        @keyframes glowpulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
        @keyframes fadeInUp { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
      `}</style>

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>⌂ Command Center</div>
        {!liveConnected && <span style={{ fontSize: '7px', color: '#4a5568', background: 'rgba(255,255,255,0.04)', padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>demo mode</span>}
      </div>

      {/* KPI row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: '8px' }}>
        {kpis.map(({ label, value, color, spark }) => (
          <div key={label} style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '8px', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px' }}>{label}</div>
            <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between' }}>
              <div style={{ fontSize: '22px', fontWeight: 700, color, letterSpacing: '-0.02em' }}>{value}</div>
              {spark && <MiniSparkline data={spark} color={color} />}
            </div>
          </div>
        ))}
      </div>

      {/* Detection Pipeline — full width */}
      <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '12px' }}>
        <div style={{ padding: '12px 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>Detection Pipeline</span>
          <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00ff9f', animation: 'glowpulse 1.5s infinite', boxShadow: '0 0 5px #00ff9f' }} />
          <span style={{ marginLeft: 'auto', fontSize: '7px', color: '#3d4a5f' }}>signals injected at origin layer · travel to AI analysis · click → threat feed</span>
        </div>
        <DetectionLayerFlow incidents={incidents} />
      </div>

      {/* Bottom row: Node Health | Live Events | Security Layers */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '2px' }}>Node Health</div>
          <NodeHealthBar name="k3s-master"  ip="192.168.139.42" status="healthy" podCount={6} cpuPct={18} memPct={34} />
          <NodeHealthBar name="k3s-worker1" ip="192.168.139.77" status={incidents.some(i => i.hostname === 'k3s-worker1' && i.severity === 'CRITICAL') ? 'threat' : 'healthy'} podCount={8} cpuPct={42} memPct={61} />
          <NodeHealthBar name="k3s-worker2" ip="192.168.139.45" status="healthy" podCount={7} cpuPct={31} memPct={48} />
        </div>

        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '12px', display: 'flex', flexDirection: 'column', minHeight: '200px' }}>
          <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            Live Event Stream
            <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00ff9f', animation: 'glowpulse 1.5s infinite', boxShadow: '0 0 5px #00ff9f' }} />
            <span style={{ fontSize: '7px', color: '#3d4a5f', marginLeft: 'auto' }}>click row → threat feed</span>
          </div>
          <LiveEventTicker incidents={incidents} />
        </div>

        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '4px' }}>Security Layers</div>
          <SecurityLayerRow name="Falco runtime detection"   status="active"   detail="eBPF · 3 nodes"           icon="🔍" />
          <SecurityLayerRow name="Kyverno admission control" status="active"   detail="3 policies enforced"       icon="🛡" />
          <SecurityLayerRow name="Cilium eBPF networking"    status="active"   detail="policy enforcement"        icon="🌐" />
          <SecurityLayerRow name="Prometheus + Grafana"      status="active"   detail="metrics · 5 dashboards"   icon="📊" />
          <SecurityLayerRow name="Argus AI agent"            status="active"   detail={`${stats?.total_all_time || incidents.length} decisions`} icon="🧠" />
          <SecurityLayerRow name="Loki log aggregation"      status="degraded" detail="direct push failing"       icon="📋" />
        </div>
      </div>
    </div>
  )
}
