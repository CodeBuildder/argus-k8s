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
  kyverno_blocked?: boolean
  enrichment_sources?: string[]
}

interface NodeTelemetry {
  name: string
  ip: string
  pods: number
  cpu: number
  mem: number
  rx: number
  tx: number
  lastSeen: number
  recent_incidents?: number
}

interface Particle {
  id: string; incident: Incident; currentSegment: number; targetSegment: number; color: string; animKey: number; blocked?: boolean; startedAt: number
}

interface LayerBurst {
  id: string; layer: number; label: string; color: string; severity: string; ts: number
}

interface ArgusEvent {
  id: string; layer: string; action: string; rule: string; color: string; ts: number
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff2d55', HIGH: '#ff9f0a', MED: '#ffd700', MEDIUM: '#ffd700', LOW: '#8b949e',
}

const SEV_PARTICLE: Record<string, { size: number; clip?: string; br: string }> = {
  CRITICAL: { size: 9, clip: 'polygon(50% 0%,100% 50%,50% 100%,0% 50%)', br: '0' },
  HIGH:     { size: 7, br: '50%' },
  MED:      { size: 6, br: '3px' },
  MEDIUM:   { size: 6, br: '3px' },
  LOW:      { size: 5, br: '50%' },
}

const LAYERS = [
  { name: 'Kyverno', sub: 'Admission Gate',    color: '#bc8cff', desc: 'API server admission check. Rejects bad manifests before a pod is scheduled.',             m1: 'Policies',    m2: 'Rejected', label: 'Gate' },
  { name: 'eBPF',    sub: 'Kernel Layer',      color: '#58a6ff', desc: 'Kernel probes see syscalls, process exec, file access, and memory/module behavior.',      m1: 'Syscalls',    m2: 'Denied',   label: 'Kernel' },
  { name: 'Falco',   sub: 'Runtime Rules',     color: '#ff9f0a', desc: 'Falco turns kernel events into runtime detections: shells, token reads, drift.',          m1: 'Events',      m2: 'Actions',  label: 'Runtime' },
  { name: 'Cilium',  sub: 'Network Datapath',  color: '#00ff9f', desc: 'eBPF networking enforces DNS, L3/L4/L7 policy, C2 egress, Tor, and lateral movement.',  m1: 'Connections', m2: 'Dropped',  label: 'Network' },
]

const ARGUS_ANALYSIS = {
  name: 'Argus',
  color: '#00d4ff',
  desc: 'Receives telemetry after detection, enriches context, explains blast radius, and routes the response. It is not an inline threat hop.',
}

// CSS keyframe per layer color — soft bright glow, red on threat hit (longer duration)
const LAYER_GLOW_CSS = LAYERS.map((l, i) => `
  @keyframes layerGlow${i} {
    0%,100% { box-shadow: 0 8px 22px ${l.color}20, inset 0 1px 0 ${l.color}20; border-color: ${l.color}45; }
    50%     { box-shadow: 0 10px 28px ${l.color}2e, inset 0 1px 0 ${l.color}30; border-color: ${l.color}65; }
  }
  @keyframes layerHit${i} {
    0%   { box-shadow: 0 8px 22px ${l.color}20, inset 0 1px 0 ${l.color}20; border-color: ${l.color}45; transform: scale(1); }
    20%  { box-shadow: 0 12px 34px ${l.color}45, inset 0 2px 0 ${l.color}45; border-color: ${l.color}; transform: scale(1.008); }
    100% { box-shadow: 0 8px 22px ${l.color}20, inset 0 1px 0 ${l.color}20; border-color: ${l.color}45; transform: scale(1); }
  }
`).join('')

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
        display: 'inline-flex', alignItems: 'center', gap: '5px',
        padding: '3px 9px', borderRadius: '5px',
        background: 'rgba(255,107,53,0.12)', border: '1px solid rgba(255,107,53,0.4)',
        fontSize: '9px', fontWeight: 700, color: '#ff6b35',
        fontFamily: 'Inter, sans-serif', flexShrink: 0, letterSpacing: '0.3px',
      }}>
        <svg width="10" height="11" viewBox="0 0 9 10" fill="none" stroke="#ff6b35" strokeWidth="1.5">
          <circle cx="4.5" cy="3" r="2"/>
          <path d="M1 9c0-1.9 1.6-3.5 3.5-3.5S8 7.1 8 9" strokeLinecap="round"/>
        </svg>
        Awaiting Security Review
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

// Get threat path from backend data, or fallback to detection logic
function getThreatPath(inc: Incident): { start: number; end: number; blocked: boolean } {
  // If backend provides detection_layer and target_layer, use them
  if ('detection_layer' in inc && 'target_layer' in inc) {
    return {
      start: (inc as any).detection_layer,
      end: (inc as any).target_layer,
      blocked: isHandledAtLayer(inc)
    }
  }

  // Fallback: infer layer from backend rule names when explicit layer fields are absent.
  const r = inc.rule.toLowerCase()
  let layer = 2

  if (inc.kyverno_blocked || r.includes('kyverno') || r.includes('admission') || r.includes('policy') ||
      r.includes('registry') || r.includes('privileged') || r.includes('rejected') ||
      r.includes('disallowed')) {
    layer = 0
  } else if (r.includes('ebpf') || r.includes('kernel') || r.includes('syscall') || r.includes('memory') || r.includes('module')) {
    layer = 1
  } else if (r.includes('cilium') || r.includes('network') || r.includes('dns') ||
      r.includes('egress') || r.includes('c2') || r.includes('lateral') ||
      r.includes('port scan') || r.includes('connection')) {
    layer = 3
  }

  const start = Math.max(0, layer - 1)
  const blocked = isHandledAtLayer(inc)

  return { start, end: layer, blocked }
}

function isHandledAtLayer(inc: Incident): boolean {
  const r = inc.rule.toLowerCase()
  return Boolean(
    inc.kyverno_blocked ||
    inc.action_taken === 'KILL' ||
    inc.action_taken === 'ISOLATE' ||
    r.includes('blocked') ||
    r.includes('rejected') ||
    r.includes('denied')
  )
}

function actionLabel(inc: Incident): string {
  const layer = getThreatPath(inc).end
  if (inc.kyverno_blocked) return 'API DENIED'
  if (inc.action_taken === 'KILL') return layer === 3 ? 'FLOW KILLED' : 'PROCESS KILLED'
  if (inc.action_taken === 'ISOLATE') return layer === 3 ? 'FLOW DROPPED' : 'POD ISOLATED'
  if (inc.action_taken === 'HUMAN_REQUIRED') return 'REVIEW QUEUED'
  if (inc.action_taken === 'NOTIFY') return 'ALERT SENT'
  return layer === 0 ? 'API CHECKED' : layer === 3 ? 'FLOW OBSERVED' : 'DETECTED'
}

function signalLabel(inc: Incident): string {
  const path = getThreatPath(inc)
  if (path.end === 0) return 'api request'
  if (path.end === 1) return 'syscall'
  if (path.end === 2) return 'kernel event'
  if (path.end === 3) return 'network flow'
  return 'telemetry'
}

function metricActivity(eventCount: number, handledCount: number, rate: number): number {
  if (eventCount <= 0 && handledCount <= 0 && rate <= 0) return 0
  return Math.min(100, Math.max(eventCount * 14, handledCount * 22, Math.round(rate)))
}

// ─── Detection Pipeline ───────────────────────────────────────────────────────

function DetectionLayerFlow({ incidents }: { incidents: Incident[] }) {
  const navigate = useNavigate()
  const [particles, setParticles] = useState<Particle[]>([])
  const [bursts, setBursts] = useState<LayerBurst[]>([])
  const [argusEvents, setArgusEvents] = useState<ArgusEvent[]>([])
  const [hover, setHover] = useState<{ particle: Particle; x: number; y: number } | null>(null)
  const [layerHits, setLayerHits] = useState<Record<number, number>>({})
  const seenIds = useRef(new Set<string>())
  const now = Date.now()
  const recent = incidents.filter(inc => now - inc.ts * 1000 < 60 * 60 * 1000)
  const handled = (inc: Incident) => inc.kyverno_blocked || inc.action_taken === 'KILL' || inc.action_taken === 'ISOLATE'
  const layerStats = LAYERS.map((_, idx) => {
    const layerEvents = recent.filter(inc => getThreatPath(inc).end === idx)
    const handledEvents = layerEvents.filter(handled)
    const newest = layerEvents[0]
    const ageSeconds = newest ? Math.max(1, Math.floor((now - newest.ts * 1000) / 1000)) : 0
    return {
      v1: layerEvents.length,
      v2: handledEvents.length,
      rate: newest ? Math.min(99, 60 / ageSeconds) : 0,
    }
  })

  // Inject new incidents as particles using backend-provided or detected layers
  useEffect(() => {
    const newIncs = incidents.filter(inc => !seenIds.current.has(inc.id)).slice(0, 2)
    if (!newIncs.length) return
    setParticles(prev => {
      const openSlots = Math.max(0, 2 - prev.length)
      const animating = newIncs.slice(0, openSlots)
      const newParticles = animating.flatMap(inc => {
        seenIds.current.add(inc.id)
        const { start, end, blocked } = getThreatPath(inc)
        const layer = LAYERS[end]
        setLayerHits(prevHits => ({ ...prevHits, [end]: Date.now() }))
        if (end === 0) {
          setArgusEvents(prevEvents => [
            {
              id: `${inc.id}-${Date.now()}`,
              layer: layer?.name || 'Layer',
              action: actionLabel(inc),
              rule: inc.rule,
              color: layer?.color || SEV_COLOR[inc.severity] || '#00d4ff',
              ts: Date.now(),
            },
            ...prevEvents,
          ].slice(0, 1))
          setBursts(prevBursts => [
            ...prevBursts,
            { id: `${inc.id}-${Date.now()}`, layer: end, label: actionLabel(inc), color: SEV_COLOR[inc.severity] || '#8b949e', severity: inc.severity, ts: Date.now() },
          ].slice(-3))
        }
        if (end === 0 && blocked) return []
        return {
          id: inc.id, incident: inc,
          currentSegment: start,
          targetSegment: end,
          color: SEV_COLOR[inc.severity] || '#8b949e',
          animKey: 0,
          blocked,
          startedAt: Date.now(),
        }
      })
      return [...prev, ...newParticles].slice(-2)
    })
  }, [incidents])

  useEffect(() => {
    if (!bursts.length) return
    const t = setTimeout(() => {
      setBursts(prev => prev.filter(b => Date.now() - b.ts < 2100))
    }, 2200)
    return () => clearTimeout(t)
  }, [bursts])

  useEffect(() => {
    if (!argusEvents.length) return
    const t = setTimeout(() => {
      setArgusEvents(prev => prev.filter(event => Date.now() - event.ts < 60_000).slice(0, 1))
    }, 1000)
    return () => clearTimeout(t)
  }, [argusEvents])

  const handleAnimEnd = (pid: string, seg: number) => {
    setParticles(prev => {
      const particle = prev.find(p => p.id === pid)
      if (!particle) return prev

      // Connector index is the hop before a layer, so reaching target means finishing target - 1.
      if (seg >= particle.targetSegment - 1) {
        setLayerHits(prevHits => ({ ...prevHits, [particle.targetSegment]: Date.now() }))
        const targetLayer = LAYERS[particle.targetSegment]
        setArgusEvents(prevEvents => [
          {
            id: `${particle.id}-${Date.now()}`,
            layer: targetLayer?.name || 'Layer',
            action: actionLabel(particle.incident),
            rule: particle.incident.rule,
            color: targetLayer?.color || particle.color,
            ts: Date.now(),
          },
          ...prevEvents,
        ].slice(0, 1))
        if (isHandledAtLayer(particle.incident)) {
          setBursts(prevBursts => [
            ...prevBursts,
            {
              id: `${particle.id}-${Date.now()}`,
              layer: particle.targetSegment,
              label: actionLabel(particle.incident),
              color: particle.color,
              severity: particle.incident.severity,
              ts: Date.now(),
            },
          ].slice(-3))
        }
        return prev.filter(p => p.id !== pid)
      }

      // Move to next segment
      const nextLayer = seg + 1
      setLayerHits(prevHits => ({ ...prevHits, [nextLayer]: Date.now() }))

      return prev.map(p =>
        p.id === pid && p.currentSegment === seg
          ? { ...p, currentSegment: seg + 1, animKey: p.animKey + 1 }
          : p
      )
    })
  }

  const fmtAge = (ts: number) => {
    const s = Math.floor((Date.now() - ts * 1000) / 1000)
    return s < 60 ? `${s}s ago` : `${Math.floor(s / 60)}m ago`
  }
  const latestArgusEvent = argusEvents.find(event => Date.now() - event.ts < 60_000)
  const latestArgusAge = latestArgusEvent ? Math.max(0, Math.floor((Date.now() - latestArgusEvent.ts) / 1000)) : 0

  return (
    <div style={{ padding: '16px 16px 12px', position: 'relative' }}>
      <style>{`
        ${LAYER_GLOW_CSS}
        @keyframes travelSeg {
          0%   { left: -4%;  opacity: 0; transform: scale(0.6); }
          8%   { opacity: 1; transform: scale(1); }
          88%  { opacity: 1; transform: scale(1); }
          100% { left: 104%; opacity: 0; transform: scale(0.6); }
        }
        @keyframes terminateSeg {
          0%   { left: -4%; opacity: 0; transform: scale(0.72); filter: blur(1px); }
          10%  { opacity: 1; transform: scale(1); filter: blur(0); }
          68%  { opacity: 1; transform: scale(1); filter: blur(0); }
          82%  { left: 86%; opacity: 1; transform: scale(1.08); filter: blur(0); }
          100% { left: 96%; opacity: 0; transform: scale(0.22); filter: blur(5px); }
        }
        @keyframes signalChip {
          0%   { left: -4%; opacity: 0; transform: translateY(-20px) scale(0.95); }
          10%  { opacity: 1; transform: translateY(-20px) scale(1); }
          68%  { opacity: 1; transform: translateY(-20px) scale(1); }
          82%  { left: 86%; opacity: 1; transform: translateY(-20px) scale(1); }
          100% { left: 96%; opacity: 0; transform: translateY(-20px) scale(0.86); }
        }
        @keyframes glowpulse { 0%,100%{opacity:1} 50%{opacity:0.45} }
        @keyframes blockVanish {
          0% { opacity: 0; transform: translate(-50%, 6px) scale(0.92); filter: blur(2px); }
          18% { opacity: 1; transform: translate(-50%, 0) scale(1); filter: blur(0); }
          62% { opacity: 1; transform: translate(-50%, 0) scale(1); }
          100% { opacity: 0; transform: translate(-50%, -8px) scale(0.9); filter: blur(2px); }
        }
        @keyframes blockRing {
          0% { opacity: 0.35; transform: translate(-50%, -50%) scale(0.45); }
          100% { opacity: 0; transform: translate(-50%, -50%) scale(1.45); }
        }
        @keyframes intakeSwap {
          0% { opacity: 0; transform: translateY(7px); border-color: rgba(0,212,255,0.45); }
          100% { opacity: 1; transform: translateY(0); }
        }
        @keyframes intakeSweep {
          0% { transform: translateX(-100%); opacity: 0; }
          20% { opacity: 1; }
          100% { transform: translateX(130%); opacity: 0; }
        }
      `}</style>

      <div style={{ display: 'flex', alignItems: 'stretch', gap: '0' }}>
        {LAYERS.flatMap((layer, i) => {
          const segParticles = particles.filter(p => p.currentSegment === i)
          const stats = layerStats[i]
          const activity = metricActivity(stats.v1, stats.v2, stats.rate)
          const items = []

          // Layer card
          const hasRecentHit = layerHits[i] && (Date.now() - layerHits[i] < 800)
          items.push(
            <div key={`node-${i}`} style={{ flex: '1 1 0', minWidth: '190px', maxWidth: '230px' }}>
              <div style={{
                background: `linear-gradient(160deg, ${layer.color}15 0%, ${layer.color}06 100%)`,
                border: `2px solid ${layer.color}50`,
                borderRadius: '12px',
                padding: '18px 14px 16px',
                position: 'relative',
                height: '100%',
                boxSizing: 'border-box',
                animation: hasRecentHit ? `layerHit${i} 2s ease-out` : `layerGlow${i} 6s ease-in-out infinite`,
                transition: 'all 0.3s ease-out',
              }}>
                <div style={{ position: 'absolute', top: '11px', left: '14px', fontSize: '8px', color: `${layer.color}80`, fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, letterSpacing: '0.8px' }}>{layer.label}</div>

                <div style={{ textAlign: 'center', marginTop: '8px', marginBottom: '10px' }}>
                  <div style={{ fontSize: '16px', fontWeight: 700, color: layer.color, fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0' }}>{layer.name}</div>
                  <div style={{ fontSize: '10px', color: '#8892a4', marginTop: '4px', fontWeight: 500 }}>{layer.sub}</div>
                </div>

                <div style={{ minHeight: '46px', fontSize: '9px', color: '#7b8495', lineHeight: 1.55, marginBottom: '10px', textAlign: 'center', padding: '0 2px' }}>{layer.desc}</div>

                {i === 1 && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '4px', marginBottom: '9px' }}>
                    {['syscall', 'process', 'memory'].map(tag => (
                      <span key={tag} style={{ fontSize: '7px', color: '#58a6ff', background: 'rgba(88,166,255,0.08)', border: '1px solid rgba(88,166,255,0.18)', borderRadius: '4px', padding: '2px 3px', textAlign: 'center', fontFamily: 'JetBrains Mono, monospace' }}>{tag}</span>
                    ))}
                  </div>
                )}

                {i === 3 && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '4px', marginBottom: '9px' }}>
                    {['DNS', 'L4', 'L7'].map(tag => (
                      <span key={tag} style={{ fontSize: '7px', color: '#00ff9f', background: 'rgba(0,255,159,0.06)', border: '1px solid rgba(0,255,159,0.16)', borderRadius: '4px', padding: '2px 3px', textAlign: 'center', fontFamily: 'JetBrains Mono, monospace' }}>{tag}</span>
                    ))}
                  </div>
                )}

                {/* Live metrics */}
                <div style={{ background: 'rgba(0,0,0,0.4)', borderRadius: '8px', padding: '9px 11px', display: 'flex', flexDirection: 'column', gap: '5px', border: `1px solid ${layer.color}15` }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '9px', color: '#5a6478', fontWeight: 600 }}>{layer.m1}</span>
                    <span style={{ fontSize: '16px', color: '#e6edf3', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>{stats.v1}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '9px', color: '#5a6478', fontWeight: 600 }}>{layer.m2}</span>
                    <span style={{ fontSize: '16px', color: layer.color, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>{stats.v2}</span>
                  </div>
                  <div style={{ height: '5px', background: 'rgba(255,255,255,0.08)', borderRadius: '3px', overflow: 'hidden', marginTop: '4px' }}>
                    <div style={{ height: '100%', width: `${activity}%`, background: `linear-gradient(90deg, ${layer.color}60, ${layer.color})`, borderRadius: '3px', boxShadow: activity > 0 ? `0 0 6px ${layer.color}35` : 'none' }} />
                  </div>
                  <div style={{ fontSize: '9px', color: '#4a5568', textAlign: 'right', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>{stats.rate.toFixed(1)}/s</div>
                </div>

                {bursts.filter(b => b.layer === i).map(b => (
                  <div key={b.id} style={{ position: 'absolute', left: '50%', top: '46%', pointerEvents: 'none', zIndex: 30 }}>
                    <div style={{
                      position: 'absolute', left: 0, top: 0, width: '86px', height: '86px',
                      borderRadius: '50%', border: `1px solid ${b.color}70`,
                      animation: 'blockRing 1.15s ease-out forwards',
                    }} />
                    <div style={{
                      transform: 'translateX(-50%)',
                      color: b.color,
                      background: 'rgba(5,10,18,0.92)',
                      border: `1px solid ${b.color}80`,
                      borderRadius: '6px',
                      boxShadow: `0 8px 24px rgba(0,0,0,0.4)`,
                      fontSize: '10px',
                      fontFamily: 'JetBrains Mono, monospace',
                      fontWeight: 800,
                      letterSpacing: '1.2px',
                      padding: '6px 10px',
                      whiteSpace: 'nowrap',
                      animation: 'blockVanish 2.1s ease-out forwards',
                    }}>
                      {b.label}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )

          // Connector with travelling particles
          if (i < LAYERS.length - 1) {
            items.push(
              <div key={`conn-${i}`} style={{ flex: '0.65 1 0', position: 'relative', minWidth: '70px', display: 'flex', alignItems: 'center' }}>
                <div style={{
                  position: 'absolute', left: 0, right: 0,
                  height: '6px', top: '50%', transform: 'translateY(-50%)',
                  background: `linear-gradient(90deg, ${layer.color}50, ${LAYERS[i + 1].color}50)`,
                  borderRadius: '4px',
                  boxShadow: `0 0 16px ${layer.color}35, 0 0 32px ${layer.color}15`,
                }} />
                <div style={{
                  position: 'absolute', right: -1, top: '50%', transform: 'translateY(-50%)',
                  width: 0, height: 0,
                  borderTop: '8px solid transparent', borderBottom: '8px solid transparent',
                  borderLeft: `13px solid ${LAYERS[i + 1].color}90`,
                  filter: `drop-shadow(0 0 6px ${LAYERS[i + 1].color}60)`,
                }} />

                {segParticles.map((p, pIdx) => {
                  const sv = SEV_PARTICLE[p.incident.severity] ?? SEV_PARTICLE.LOW
                  // Delay each particle so they travel one after another
                  const delay = pIdx * 1.5 // 1.5s delay between particles
                  const particleSize = sv.size + 5
                  const isBlocked = p.blocked
                  const animName = isBlocked ? 'terminateSeg' : 'travelSeg'
                  const animDuration = isBlocked ? 3.2 : 6.2 + i * 0.45
                  const severityColor = SEV_COLOR[p.incident.severity] || p.color

                  return (
                    <div key={`${p.id}-${p.animKey}`}>
                      {/* Invisible hover zone (larger hit area) */}
                      <div
                        style={{
                          position: 'absolute', top: '50%', left: 0,
                          width: `${particleSize}px`, height: `${particleSize}px`,
                          marginTop: `-${particleSize / 2}px`,
                          padding: '18px',
                          cursor: 'pointer', zIndex: 19,
                          animation: `${animName} ${animDuration}s ease-in-out ${delay}s forwards`,
                        }}
                        onMouseEnter={e => setHover({ particle: p, x: e.clientX, y: e.clientY })}
                        onMouseMove={e => setHover(prev => prev ? { ...prev, x: e.clientX, y: e.clientY } : null)}
                        onMouseLeave={() => setHover(null)}
                        onClick={e => { e.stopPropagation(); navigate(`/threats?id=${p.incident.id}`) }}
                      />
                      <div
                        style={{
                          position: 'absolute',
                          top: '50%',
                          left: 0,
                          marginTop: '-38px',
                          padding: '4px 7px',
                          borderRadius: '5px',
                          background: 'rgba(5,10,18,0.86)',
                          border: `1px solid ${severityColor}55`,
                          color: severityColor,
                          fontSize: '8px',
                          fontFamily: 'JetBrains Mono, monospace',
                          fontWeight: 800,
                          letterSpacing: '0.7px',
                          whiteSpace: 'nowrap',
                          pointerEvents: 'none',
                          zIndex: 21,
                          boxShadow: '0 8px 18px rgba(0,0,0,0.35)',
                          animation: `signalChip ${animDuration}s ease-in-out ${delay}s forwards`,
                        }}
                      >
                        {signalLabel(p.incident)}
                      </div>

                      {/* Visible signal */}
                      <div
                        style={{
                          position: 'absolute', top: '50%', left: 0,
                          width: `${particleSize}px`, height: `${particleSize}px`,
                          marginTop: `-${particleSize / 2}px`,
                          borderRadius: sv.br, clipPath: sv.clip,
                          background: `radial-gradient(circle at 30% 30%, ${severityColor}ff, ${severityColor}e6, ${severityColor}b8)`,
                          boxShadow: `0 0 14px ${severityColor}80, inset 0 0 8px ${severityColor}40`,
                          pointerEvents: 'none', zIndex: 20,
                          animation: `${animName} ${animDuration}s ease-in-out ${delay}s forwards`,
                          border: `1px solid ${severityColor}`,
                          filter: 'brightness(1.08) saturate(1.1)',
                        }}
                        onAnimationEnd={() => handleAnimEnd(p.id, i)}
                      />
                    </div>
                  )
                })}
              </div>
            )
          }

          return items
        })}
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '22px', marginTop: '14px', justifyContent: 'center', padding: '0 8px' }}>
        {(['CRITICAL', 'HIGH', 'MED', 'LOW'] as const).map(sev => {
          const sv = SEV_PARTICLE[sev]; const c = SEV_COLOR[sev]
          const legendSize = sv.size + 6
          return (
            <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <div style={{
                width: `${legendSize}px`,
                height: `${legendSize}px`,
                borderRadius: sv.br,
                clipPath: sv.clip,
                background: `radial-gradient(circle at 30% 30%, ${c}ff, ${c}dd)`,
                boxShadow: `0 0 10px ${c}90, 0 0 20px ${c}50`,
                flexShrink: 0,
                border: `2px solid ${c}`,
              }} />
              <span style={{ fontSize: '9px', color: '#6b7280', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, letterSpacing: '0.3px' }}>{sev}</span>
            </div>
          )
        })}
        <span style={{ fontSize: '9px', color: '#3d4a5f', marginLeft: 'auto', fontWeight: 600 }}>
          {particles.length > 0 ? `${particles.length} live signal${particles.length > 1 ? 's' : ''} · hover to inspect · click → threat feed` : 'signals are detected at the enforcement layer; handled events vanish on block/containment'}
        </span>
      </div>

      <div style={{
        marginTop: '12px',
        display: 'grid',
        gridTemplateColumns: '1fr 1.35fr',
        alignItems: 'center',
        gap: '14px',
        background: 'rgba(0,212,255,0.035)',
        border: `1px solid ${ARGUS_ANALYSIS.color}1f`,
        borderRadius: '8px',
        padding: '10px 12px',
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px', marginBottom: '4px' }}>
            <div style={{ width: '7px', height: '7px', borderRadius: '50%', background: ARGUS_ANALYSIS.color, boxShadow: `0 0 8px ${ARGUS_ANALYSIS.color}` }} />
            <div style={{ fontSize: '9px', color: ARGUS_ANALYSIS.color, fontWeight: 800, fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase', letterSpacing: '1.4px' }}>{ARGUS_ANALYSIS.name} intake</div>
          </div>
          <div style={{ fontSize: '10px', color: '#6b7280', lineHeight: 1.45 }}>Telemetry is copied here after enforcement for enrichment, explanation, and response routing.</div>
        </div>
        <div style={{ minHeight: '58px', display: 'flex', alignItems: 'center' }}>
          {latestArgusEvent ? (
            <div key={latestArgusEvent.id} style={{
              position: 'relative',
              overflow: 'hidden',
              width: '100%',
              display: 'grid',
              gridTemplateColumns: '84px 96px 1fr 52px',
              gap: '8px',
              alignItems: 'center',
              background: 'linear-gradient(135deg, rgba(0,0,0,0.28), rgba(0,212,255,0.035))',
              border: `1px solid ${latestArgusEvent.color}30`,
              borderRadius: '8px',
              padding: '8px 10px',
              animation: 'intakeSwap 0.28s ease-out',
            }}>
              <span style={{
                position: 'absolute',
                left: 0,
                top: 0,
                bottom: 0,
                width: '38%',
                background: `linear-gradient(90deg, transparent, ${ARGUS_ANALYSIS.color}18, transparent)`,
                animation: 'intakeSweep 1.2s ease-out',
              }} />
              <span style={{ fontSize: '8px', color: latestArgusEvent.color, fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, position: 'relative' }}>{latestArgusEvent.layer}</span>
              <span style={{ fontSize: '8px', color: ARGUS_ANALYSIS.color, fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, position: 'relative' }}>→ Argus</span>
              <span style={{ fontSize: '9px', color: '#9aa7b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', position: 'relative' }}>{latestArgusEvent.action} · {latestArgusEvent.rule}</span>
              <span style={{ fontSize: '8px', color: '#58a6ff', fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, textAlign: 'right', position: 'relative' }}>{latestArgusAge}s</span>
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '8px', color: ARGUS_ANALYSIS.color, fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', fontWeight: 700 }}>
              waiting for last-1m telemetry
              <span style={{ width: '42px', height: '1px', background: `linear-gradient(90deg, transparent, ${ARGUS_ANALYSIS.color})`, boxShadow: `0 0 10px ${ARGUS_ANALYSIS.color}` }} />
            </div>
          )}
        </div>
      </div>

      {/* Hover tooltip */}
      {hover && (
        <div style={{
          position: 'fixed',
          left: Math.min(hover.x + 18, window.innerWidth - 310),
          top: Math.max(hover.y - 148, 10),
          background: 'linear-gradient(135deg, rgba(13,20,33,0.98), rgba(7,12,20,0.98))',
          border: `1px solid ${hover.particle.color}70`,
          borderRadius: '8px', padding: '13px 14px',
          zIndex: 9999, width: '292px',
          boxShadow: `0 16px 44px rgba(0,0,0,0.72), 0 0 0 1px ${hover.particle.color}18`,
          pointerEvents: 'none',
        }}>
          {(() => {
            const path = getThreatPath(hover.particle.incident)
            const startLayer = LAYERS[path.start]
            const targetLayer = LAYERS[path.end]
            return <>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '9px' }}>
                {(() => {
              const sv = SEV_PARTICLE[hover.particle.incident.severity] ?? SEV_PARTICLE.LOW
              const c = SEV_COLOR[hover.particle.incident.severity]
              return <div style={{ width: `${sv.size + 1}px`, height: `${sv.size + 1}px`, borderRadius: sv.br, clipPath: sv.clip, background: c, boxShadow: `0 0 6px ${c}`, flexShrink: 0 }} />
                })()}
                <span style={{ fontSize: '10px', fontWeight: 700, color: SEV_COLOR[hover.particle.incident.severity], fontFamily: 'JetBrains Mono, monospace', letterSpacing: '1px' }}>{hover.particle.incident.severity}</span>
                <span style={{ fontSize: '8px', color: '#5a6478', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>{fmtAge(hover.particle.incident.ts)}</span>
              </div>
              <div style={{ fontSize: '12px', color: '#f0f6fc', lineHeight: 1.45, marginBottom: '10px', fontWeight: 700 }}>{hover.particle.incident.rule}</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px', marginBottom: '10px' }}>
                <div style={{ background: `${startLayer.color}12`, border: `1px solid ${startLayer.color}30`, borderRadius: '6px', padding: '6px 7px' }}>
                  <div style={{ fontSize: '7px', color: '#5a6478', textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: '3px' }}>Detected by</div>
                  <div style={{ fontSize: '10px', color: startLayer.color, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>{startLayer.name}</div>
                </div>
                <div style={{ background: `${targetLayer.color}12`, border: `1px solid ${targetLayer.color}30`, borderRadius: '6px', padding: '6px 7px' }}>
                  <div style={{ fontSize: '7px', color: '#5a6478', textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: '3px' }}>{path.blocked ? 'Outcome' : 'After detection'}</div>
                  <div style={{ fontSize: '10px', color: targetLayer.color, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>{path.blocked ? actionLabel(hover.particle.incident) : 'Evidence to Argus'}</div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap', marginBottom: '9px' }}>
                {hover.particle.incident.namespace && <span style={{ fontSize: '9px', color: '#58a6ff', background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.22)', padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{hover.particle.incident.namespace}</span>}
                {hover.particle.incident.hostname && <span style={{ fontSize: '9px', color: '#8892a4', background: 'rgba(136,146,164,0.1)', border: '1px solid rgba(136,146,164,0.2)', padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{hover.particle.incident.hostname}</span>}
                <span style={{ fontSize: '9px', color: '#bc8cff', background: 'rgba(188,140,255,0.08)', border: '1px solid rgba(188,140,255,0.2)', padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{Math.round(hover.particle.incident.confidence * 100)}% confidence</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '8px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                <span style={{ fontSize: '9px', fontWeight: 700, color: hover.particle.color, fontFamily: 'JetBrains Mono, monospace' }}>{hover.particle.incident.action_taken}</span>
                <span style={{ fontSize: '8px', color: '#6b7280' }}>click to open incident detail</span>
              </div>
            </>
          })()}
        </div>
      )}
    </div>
  )
}

// ─── Sparkline ────────────────────────────────────────────────────────────────

function MiniSparkline({ data, color }: { data: number[]; color: string }) {
  const max = Math.max(...data, 1)
  const w = 80, h = 28
  const hasActivity = data.some(v => v > 0)
  const pts = data.map((v, i) => `${(i / Math.max(data.length - 1, 1)) * w},${h - (v / max) * h}`).join(' ')
  return (
    <svg width={w} height={h} style={{ flexShrink: 0 }}>
      {hasActivity ? (
        <>
          <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" opacity="0.8" />
          <polyline points={`0,${h} ${pts} ${w},${h}`} fill={color} fillOpacity="0.08" stroke="none" />
        </>
      ) : (
        <line x1="0" y1={h} x2={w} y2={h} stroke={color} strokeWidth="1" opacity="0.18" />
      )}
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

  // Detect which layer caught the threat — prefer kyverno_blocked field, fall back to rule name
  const getDetectionLayer = (inc: Incident) => {
    const r = inc.rule.toLowerCase()
    if (inc.kyverno_blocked || r.includes('kyverno') || r.includes('admission') || r.includes('rejected') || r.includes('disallowed') || r.includes('blocked')) {
      return { name: 'Kyverno', icon: '', color: '#bc8cff', action: 'BLOCKED', isKyverno: true }
    } else if (r.includes('cilium') || r.includes('network') || r.includes('dns') || r.includes('egress') || r.includes('c2') || r.includes('lateral') || r.includes('ssrf') || r.includes('port scan') || r.includes('tor')) {
      return { name: 'Cilium', icon: '', color: '#00ff9f', action: 'DETECTED', isKyverno: false }
    } else if (r.includes('ebpf') || r.includes('kernel') || r.includes('syscall') || r.includes('memory')) {
      return { name: 'eBPF', icon: '', color: '#58a6ff', action: 'DETECTED', isKyverno: false }
    } else {
      return { name: 'Falco', icon: '', color: '#ff9f0a', action: 'DETECTED', isKyverno: false }
    }
  }

  return (
    <div ref={ref} style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '3px' }}>
      {incidents.slice(0, 20).map((inc, i) => {
        const isNotify = inc.action_taken === 'NOTIFY'
        const channel = isNotify ? getNotifyChannel(inc.id) : null
        const layer = getDetectionLayer(inc)
        const isKyverno = layer.isKyverno
        const isBlocked = layer.action === 'BLOCKED' || inc.action_taken === 'KILL' || inc.action_taken === 'ISOLATE'
        const rowBorderColor = isKyverno
          ? 'rgba(188,140,255,0.25)'
          : isBlocked ? 'rgba(255,45,85,0.2)' : 'rgba(255,255,255,0.05)'
        const rowBg = isKyverno
          ? 'rgba(188,140,255,0.04)'
          : i === 0 ? 'rgba(0,255,159,0.05)' : 'rgba(0,0,0,0.2)'

        return (
          <div
            key={inc.id}
            onClick={() => navigate(`/threats?id=${inc.id}`)}
            style={{
              display: 'flex', alignItems: 'center', gap: '7px', padding: '7px 10px',
              background: rowBg, borderRadius: '6px',
              animation: i === 0 ? 'fadeInUp 0.3s ease-out' : 'none',
              cursor: 'pointer', transition: 'all 0.15s',
              border: `1px solid ${rowBorderColor}`,
              borderLeft: `3px solid ${isKyverno ? '#bc8cff' : SEV_COLOR[inc.severity] || '#4a5568'}`,
            }}
            onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.background = 'rgba(255,255,255,0.05)' }}
            onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.background = rowBg }}
          >
            {/* Time */}
            <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace', width: '24px', flexShrink: 0 }}>{fmt(inc.ts)}</span>

            {/* Severity indicator */}
            <span style={{ fontSize: '10px', fontWeight: 700, color: SEV_COLOR[inc.severity], fontFamily: 'JetBrains Mono, monospace', width: '16px', flexShrink: 0, textAlign: 'center' }}>
              {inc.severity === 'CRITICAL' ? '◆' : inc.severity === 'HIGH' ? '●' : inc.severity === 'MED' || inc.severity === 'MEDIUM' ? '▪' : '·'}
            </span>

            {/* Detection Layer Badge */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: '4px',
              padding: '2px 6px', borderRadius: '4px',
              background: `${layer.color}18`, border: `1px solid ${layer.color}45`,
              flexShrink: 0,
            }}>
              <span style={{ fontSize: '10px' }}>{layer.icon}</span>
              <span style={{ fontSize: '7px', fontWeight: 700, color: layer.color, fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.3px' }}>
                {layer.name}
              </span>
            </div>

            {/* Kyverno blocked / action indicator */}
            {isKyverno ? (
              <span style={{
                fontSize: '7px', fontWeight: 800, color: '#bc8cff',
                background: 'rgba(188,140,255,0.12)', border: '1px solid rgba(188,140,255,0.35)',
                padding: '2px 5px', borderRadius: '3px',
                fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.5px', flexShrink: 0,
              }}>
                ⛔ BLOCKED
              </span>
            ) : isBlocked && (
              <span style={{
                fontSize: '7px', fontWeight: 800, color: '#ff2d55',
                background: 'rgba(255,45,85,0.15)', border: '1px solid rgba(255,45,85,0.3)',
                padding: '2px 5px', borderRadius: '3px',
                fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.5px', flexShrink: 0,
              }}>
                ⛔ {layer.action}
              </span>
            )}

            {/* Rule name */}
            <span style={{ fontSize: '10px', color: '#e6edf3', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 500 }}>{inc.rule}</span>

            {/* Namespace */}
            {inc.namespace && <span style={{ fontSize: '7px', color: '#58a6ff', background: 'rgba(88,166,255,0.12)', border: '1px solid rgba(88,166,255,0.25)', padding: '2px 5px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>{inc.namespace}</span>}

            {/* Action badge */}
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

function SecurityLayerRow({
  name,
  status,
  detail,
  eventCount,
  activity,
  updatedAgo,
}: {
  name: string
  status: 'active' | 'degraded' | 'inactive'
  detail: string
  eventCount: number
  activity: number
  updatedAgo: string
}) {
  const colors = { active: '#00ff9f', degraded: '#ff9f0a', inactive: '#4a5568' }
  const color = colors[status]
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '7px', padding: '7px 9px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', border: `1px solid ${color}18` }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
        <div style={{ width: '7px', height: '7px', borderRadius: '50%', background: color, boxShadow: status === 'active' ? `0 0 7px ${color}` : 'none', flexShrink: 0, animation: status === 'active' ? 'glowpulse 2.2s infinite' : 'none' }} />
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '10px', color: '#e6edf3', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{name}</span>
            <span style={{ fontSize: '7px', color, background: `${color}18`, border: `1px solid ${color}33`, padding: '1px 5px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace' }}>{status}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px', marginTop: '4px' }}>
            <div style={{ flex: 1, height: '3px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px', overflow: 'hidden' }}>
              <div style={{ width: `${activity}%`, height: '100%', background: color, borderRadius: '2px', transition: 'width 700ms ease-out', boxShadow: activity > 0 ? `0 0 8px ${color}70` : 'none' }} />
            </div>
            <span style={{ fontSize: '7px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace', whiteSpace: 'nowrap' }}>{updatedAgo}</span>
          </div>
        </div>
      </div>
      <div style={{ minWidth: '82px', textAlign: 'right' }}>
        <div style={{ fontSize: '9px', color, fontFamily: 'JetBrains Mono, monospace', fontWeight: 800 }}>{eventCount}</div>
        <div style={{ fontSize: '7px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{detail}</div>
      </div>
    </div>
  )
}

// ─── Node Health Bar ──────────────────────────────────────────────────────────

function NodeHealthBar({ node, status, recentIncidents }: { node: NodeTelemetry; status: string; recentIncidents: number }) {
  const color = status === 'threat' ? '#ff2d55' : status === 'warning' ? '#ff9f0a' : '#00ff9f'
  const fmtAge = Math.max(0, Math.floor((Date.now() - node.lastSeen) / 1000))
  return (
    <div style={{ background: '#111827', border: `1px solid ${color}22`, borderRadius: '8px', padding: '10px 12px', position: 'relative', overflow: 'hidden' }}>
      <div style={{ position: 'absolute', left: 0, right: 0, top: 0, height: '1px', background: `linear-gradient(90deg, transparent, ${color}90, transparent)`, animation: 'scanline 2.6s linear infinite' }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: '7px', marginBottom: '8px' }}>
        <div style={{ width: '7px', height: '7px', borderRadius: '50%', background: color, boxShadow: `0 0 5px ${color}`, animation: status === 'threat' ? 'glowpulse 1.5s infinite' : 'none' }} />
        <span style={{ fontSize: '10px', fontWeight: 700, color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>{node.name}</span>
        <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>{node.ip}</span>
        <span style={{ fontSize: '8px', color, marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>{node.pods} pods</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        {[
          { label: 'CPU', pct: node.cpu, color: node.cpu > 80 ? '#ff2d55' : node.cpu > 60 ? '#ff9f0a' : '#00ff9f' },
          { label: 'MEM', pct: node.mem, color: node.mem > 80 ? '#ff2d55' : node.mem > 60 ? '#ff9f0a' : '#58a6ff' },
          { label: 'NET', pct: Math.min(96, Math.round((node.rx + node.tx) / 2)), color: '#00d4ff' },
        ].map(({ label, pct, color: bc }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace', width: '28px' }}>{label}</span>
            <div style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px', overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${pct}%`, background: bc, borderRadius: '2px', transition: 'width 900ms ease-out', boxShadow: `0 0 7px ${bc}55` }} />
            </div>
            <span style={{ fontSize: '8px', color: bc, fontFamily: 'JetBrains Mono, monospace', width: '28px', textAlign: 'right' }}>{pct}%</span>
          </div>
        ))}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '8px', paddingTop: '6px', borderTop: '1px solid rgba(255,255,255,0.04)' }}>
        <span style={{ fontSize: '7px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>live {fmtAge}s</span>
        <span style={{ fontSize: '7px', color: recentIncidents > 0 ? color : '#4a5568', fontFamily: 'JetBrains Mono, monospace', marginLeft: 'auto' }}>{recentIncidents} recent events</span>
      </div>
    </div>
  )
}

// ─── Command Center Page ──────────────────────────────────────────────────────

export default function CommandCenter() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [incidents, setIncidents] = useState<Incident[]>([])  // Start empty, load from backend
  const [backendLive, setBackendLive] = useState(false)
  const [lastRefresh, setLastRefresh] = useState('')
  const [simulating, setSimulating] = useState(false)
  const [sparkData] = useState(() => ({
    critical: Array.from({ length: 12 }, () => 0),
    events: Array.from({ length: 12 }, () => 0),
  }))
  const [nodeTelemetry, setNodeTelemetry] = useState<NodeTelemetry[]>([])

  const simulateThreats = async (scenario = 'mixed', count = 20) => {
    setSimulating(true)
    try {
      const response = await fetch(`${API}/simulate-threats`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ count, scenario })
      })
      if (response.ok) {
        // Refresh incidents immediately
        const iRes = await fetch(`${API}/incidents?limit=50`)
        if (iRes.ok) {
          const data = await iRes.json()
          if (data.incidents) setIncidents(data.incidents)
        }
      }
    } catch (error) {
      console.error('Failed to simulate threats:', error)
    } finally {
      setSimulating(false)
    }
  }

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [sRes, iRes, nRes] = await Promise.all([
          fetch(`${API}/incidents/stats`),
          fetch(`${API}/incidents?limit=50`),
          fetch(`${API}/node-telemetry`),
        ])
        if (sRes.ok) setStats(await sRes.json())
        if (iRes.ok) {
          const data = await iRes.json()
          // Always use backend data if available, even if empty
          if (data.incidents !== undefined) {
            setIncidents(data.incidents)
            setBackendLive(true)
            setLastRefresh(new Date().toTimeString().slice(0, 8))
          }
        }
        if (nRes.ok) {
          const nodeData = await nRes.json()
          setNodeTelemetry(nodeData.nodes || [])
        }
      } catch (error) {
        console.error('Failed to fetch incidents:', error)
        setBackendLive(false)
      }
    }
    fetchAll()
    const t = setInterval(fetchAll, 5000)
    return () => clearInterval(t)
  }, [])

  // Seed backend incidents on first load if the backend is empty.
  useEffect(() => {
    const autoSimulate = async () => {
      // Wait a bit for initial data fetch
      await new Promise(resolve => setTimeout(resolve, 2000))

      // If we have less than 10 incidents or they're all the same type, simulate diverse threats
      if (incidents.length < 10) {
        const uniqueRules = new Set(incidents.map(i => i.rule))
        if (uniqueRules.size < 3) {
          console.log('Seeding backend threat stream for live dashboard data')
          await simulateThreats('mixed', 20)
        }
      }
    }

    autoSimulate()
  }, []) // Run once on mount

  // Periodically add new diverse threats (every 45 seconds)
  useEffect(() => {
    const periodicSimulate = setInterval(async () => {
      // Add 3-5 new threats periodically to keep things interesting
      try {
        await fetch(`${API}/simulate-threats`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ count: 3, scenario: 'mixed' })
        })
      } catch (error) {
        console.error('Periodic simulation failed:', error)
      }
    }, 45000) // Every 45 seconds

    return () => clearInterval(periodicSimulate)
  }, [])

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

  const recentWindow = Date.now() - 60 * 60 * 1000
  const recentIncidents = incidents.filter(i => i.ts * 1000 > recentWindow)
  const layerCount = (match: (inc: Incident) => boolean) => recentIncidents.filter(match).length
  const lastLayerEvent = (match: (inc: Incident) => boolean) => {
    if (!backendLive) return 'disconnected'
    const last = incidents.find(match)
    if (!last) return 'idle'
    const seconds = Math.max(0, Math.floor((Date.now() - last.ts * 1000) / 1000))
    return seconds < 60 ? `${seconds}s ago` : `${Math.floor(seconds / 60)}m ago`
  }
  const runtimeEvents = layerCount(i => getThreatPath(i).end === 2)
  const kyvernoEvents = layerCount(i => i.kyverno_blocked || getThreatPath(i).end === 0)
  const ciliumEvents = layerCount(i => getThreatPath(i).end === 3)
  const ebpfEvents = layerCount(i => getThreatPath(i).end === 1)
  const argusEvents = recentIncidents.length
  const lokiEvents = incidents.filter(i => i.enrichment_sources?.includes?.('loki')).length
  const connectedStatus: 'active' | 'inactive' = backendLive ? 'active' : 'inactive'
  const lokiStatus: 'degraded' | 'inactive' = backendLive ? 'degraded' : 'inactive'
  const securityLayers = [
    {
      name: 'Falco runtime detection',
      status: connectedStatus,
      detail: 'runtime events',
      eventCount: runtimeEvents,
      activity: backendLive ? Math.min(100, runtimeEvents * 11) : 0,
      updatedAgo: lastLayerEvent(i => getThreatPath(i).end === 2),
    },
    {
      name: 'Kyverno admission control',
      status: connectedStatus,
      detail: 'policy rejects',
      eventCount: kyvernoEvents,
      activity: backendLive ? Math.min(100, kyvernoEvents * 14) : 0,
      updatedAgo: lastLayerEvent(i => i.kyverno_blocked || getThreatPath(i).end === 0),
    },
    {
      name: 'Cilium eBPF networking',
      status: connectedStatus,
      detail: 'flow decisions',
      eventCount: ciliumEvents,
      activity: backendLive ? Math.min(100, ciliumEvents * 10) : 0,
      updatedAgo: lastLayerEvent(i => getThreatPath(i).end === 3),
    },
    {
      name: 'eBPF kernel telemetry',
      status: connectedStatus,
      detail: 'kernel signals',
      eventCount: ebpfEvents,
      activity: backendLive ? Math.min(100, ebpfEvents * 12) : 0,
      updatedAgo: lastLayerEvent(i => getThreatPath(i).end === 1),
    },
    {
      name: 'Argus agent',
      status: connectedStatus,
      detail: 'decisions routed',
      eventCount: argusEvents,
      activity: backendLive ? Math.min(100, argusEvents * 5) : 0,
      updatedAgo: incidents[0] ? lastLayerEvent(() => true) : 'idle',
    },
    {
      name: 'Loki log aggregation',
      status: lokiStatus,
      detail: 'direct push failing',
      eventCount: lokiEvents,
      activity: backendLive ? Math.min(100, lokiEvents * 16) : 0,
      updatedAgo: backendLive ? (lokiEvents > 0 ? 'retrying' : 'idle') : 'disconnected',
    },
  ]

  return (
    <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <style>{`
        @keyframes glowpulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
        @keyframes fadeInUp { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
        @keyframes pulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(0,255,159,0.4); }
          50% { box-shadow: 0 0 0 6px rgba(0,255,159,0); }
        }
        @keyframes scanline {
          0% { transform: translateX(-100%); opacity: 0; }
          20% { opacity: 1; }
          100% { transform: translateX(100%); opacity: 0; }
        }
        @keyframes liveBlink {
          0%, 100% { opacity: 1; box-shadow: 0 0 6px rgba(0,255,159,0.75); }
          50% { opacity: 0.45; box-shadow: 0 0 14px rgba(0,255,159,0.25); }
        }
      `}</style>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>⌂ Command Center</div>
        <span style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          fontSize: '7px',
          color: backendLive ? '#00ff9f' : '#ff9f0a',
          background: backendLive ? 'rgba(0,255,159,0.06)' : 'rgba(255,159,10,0.08)',
          border: `1px solid ${backendLive ? 'rgba(0,255,159,0.2)' : 'rgba(255,159,10,0.25)'}`,
          padding: '3px 8px',
          borderRadius: '4px',
          fontFamily: 'JetBrains Mono, monospace',
          textTransform: 'uppercase',
          letterSpacing: '0.5px',
        }}>
          <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: backendLive ? '#00ff9f' : '#ff9f0a', animation: backendLive ? 'liveBlink 1.4s infinite' : 'none' }} />
          {backendLive ? `backend live${lastRefresh ? ` · ${lastRefresh}` : ''}` : 'backend disconnected'}
        </span>
        <button
        onClick={() => simulateThreats('human_approval', 3)}
        disabled={simulating}
        style={{
          marginLeft: 'auto',
          padding: '6px 12px',
          background: simulating ? 'rgba(188,140,255,0.12)' : 'linear-gradient(135deg, rgba(188,140,255,0.12), rgba(188,140,255,0.22))',
          border: '1px solid rgba(188,140,255,0.35)',
          borderRadius: '6px',
          color: '#bc8cff',
          fontSize: '9px',
          fontWeight: 700,
          fontFamily: 'JetBrains Mono, monospace',
          cursor: simulating ? 'not-allowed' : 'pointer',
          letterSpacing: '0.5px',
          transition: 'all 0.2s',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
        }}
      >
        Human Approval
      </button>
      <button
        onClick={() => simulateThreats('attack_chain', 5)}
        disabled={simulating}
        style={{
          padding: '6px 12px',
          background: simulating ? 'rgba(255,45,85,0.12)' : 'linear-gradient(135deg, rgba(255,45,85,0.1), rgba(255,45,85,0.2))',
          border: '1px solid rgba(255,45,85,0.35)',
          borderRadius: '6px',
          color: '#ff2d55',
          fontSize: '9px',
          fontWeight: 700,
          fontFamily: 'JetBrains Mono, monospace',
          cursor: simulating ? 'not-allowed' : 'pointer',
          letterSpacing: '0.5px',
          transition: 'all 0.2s',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
        }}
      >
        Attack Chain
      </button>
      <button
          onClick={() => simulateThreats('mixed', 20)}
          disabled={simulating}
          style={{
            padding: '6px 12px',
            background: simulating ? 'rgba(255,159,10,0.2)' : 'linear-gradient(135deg, rgba(255,159,10,0.15), rgba(255,159,10,0.25))',
            border: '1px solid rgba(255,159,10,0.4)',
            borderRadius: '6px',
            color: '#ff9f0a',
            fontSize: '9px',
            fontWeight: 700,
            fontFamily: 'JetBrains Mono, monospace',
            cursor: simulating ? 'not-allowed' : 'pointer',
            letterSpacing: '0.5px',
            transition: 'all 0.2s',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
          onMouseEnter={e => !simulating && (e.currentTarget.style.background = 'linear-gradient(135deg, rgba(255,159,10,0.25), rgba(255,159,10,0.35)')}
          onMouseLeave={e => !simulating && (e.currentTarget.style.background = 'linear-gradient(135deg, rgba(255,159,10,0.15), rgba(255,159,10,0.25)')}
        >
          {simulating ? (
            <>
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#ff9f0a" strokeWidth="3">
                <circle cx="12" cy="12" r="10" opacity="0.25"/>
                <path d="M12 2 A10 10 0 0 1 22 12" strokeLinecap="round">
                  <animateTransform attributeName="transform" type="rotate" from="0 12 12" to="360 12 12" dur="1s" repeatCount="indefinite"/>
                </path>
              </svg>
              Simulating...
            </>
          ) : (
            <>
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#ff9f0a" strokeWidth="2.5">
                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              Simulate Diverse Threats
            </>
          )}
        </button>
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

      {/* Detection Pipeline — FULL WIDTH, LARGER BUT FITS */}
      <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '12px' }}>
        <div style={{ padding: '14px 18px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>⚡ Detection Pipeline</span>
          <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00ff9f', animation: 'glowpulse 1.5s infinite', boxShadow: '0 0 6px #00ff9f' }} />
          <span style={{ marginLeft: 'auto', fontSize: '8px', color: '#3d4a5f', fontWeight: 500 }}>showing max 2 live signals · handled events collapse at enforcement · telemetry copies to Argus</span>
        </div>
        <DetectionLayerFlow incidents={incidents} />
      </div>

      {/* Bottom row: Node Health | Live Events | Security Layers */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '2px', display: 'flex', alignItems: 'center', gap: '7px' }}>
            Node Health
            <span style={{ fontSize: '7px', color: '#4a5568', letterSpacing: '0', marginLeft: 'auto' }}>live /api/node-telemetry</span>
          </div>
          {nodeTelemetry.map(node => {
            const nodeEvents = recentIncidents.filter(i => i.hostname === node.name)
            const status = nodeEvents.some(i => i.severity === 'CRITICAL') ? 'threat' : nodeEvents.some(i => i.severity === 'HIGH') ? 'warning' : 'healthy'
            return (
              <NodeHealthBar
                key={node.name}
                node={node}
                status={status}
                recentIncidents={nodeEvents.length}
              />
            )
          })}
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
          <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '4px', display: 'flex', alignItems: 'center' }}>
            Security Layers
            <span style={{ fontSize: '7px', color: '#4a5568', letterSpacing: '0', marginLeft: 'auto' }}>last 1h activity</span>
          </div>
          {securityLayers.map(layer => (
            <SecurityLayerRow
              key={layer.name}
              name={layer.name}
              status={layer.status}
              detail={layer.detail}
              eventCount={layer.eventCount}
              activity={layer.activity}
              updatedAgo={layer.updatedAgo}
            />
          ))}
        </div>
      </div>
    </div>
  )
}
