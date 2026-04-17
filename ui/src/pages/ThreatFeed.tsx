import React, { useState, useEffect, useRef } from 'react'

const API = '/api'

const SEV_CONFIG: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  CRITICAL: { color: '#ff2d55', bg: 'rgba(255,45,85,0.08)', border: 'rgba(255,45,85,0.3)', dot: '#ff2d55' },
  HIGH:     { color: '#ff9f0a', bg: 'rgba(255,159,10,0.08)', border: 'rgba(255,159,10,0.3)', dot: '#ff9f0a' },
  MED:      { color: '#ffd700', bg: 'rgba(255,215,0,0.06)', border: 'rgba(255,215,0,0.25)', dot: '#ffd700' },
  LOW:      { color: '#8b949e', bg: 'rgba(139,148,158,0.06)', border: 'rgba(139,148,158,0.2)', dot: '#8b949e' },
}

const ACTION_CONFIG: Record<string, { color: string; label: string }> = {
  ISOLATE:        { color: '#ff2d55', label: '⊘ Isolated' },
  KILL:           { color: '#ff2d55', label: '✕ Killed' },
  NOTIFY:         { color: '#ff9f0a', label: '⚑ Notified' },
  HUMAN_REQUIRED: { color: '#bc8cff', label: '◎ Needs review' },
  LOG:            { color: '#8b949e', label: '▪ Logged' },
}

interface Incident {
  id: string
  ts: number
  rule: string
  priority: string
  severity: string
  pod: string
  namespace: string
  hostname: string
  assessment: string
  what_happened?: string[]
  blast_radius_bullets?: string[]
  action_steps?: string[]
  blast_radius: string
  recommended_action: string
  action_taken: string
  action_status: string
  confidence: number
  likely_false_positive: boolean
  mitre_tags: string[]
  enrichment_sources: string[]
  enrichment_duration_ms: number
}

const NODES = [
  { name: 'k3s-master', ip: '192.168.139.42' },
  { name: 'k3s-worker1', ip: '192.168.139.77' },
  { name: 'k3s-worker2', ip: '192.168.139.45' },
]

function ImpactDiagram({ incident }: { incident: any }) {
  const [scanPos, setScanPos] = React.useState(0)
  const [barsAnimated, setBarsAnimated] = React.useState(false)

  React.useEffect(() => {
    const t = setInterval(() => setScanPos(p => (p + 1) % 100), 30)
    return () => clearInterval(t)
  }, [])

  React.useEffect(() => {
    setBarsAnimated(false)
    const t = setTimeout(() => setBarsAnimated(true), 200)
    return () => clearTimeout(t)
  }, [incident.id])

  const threatNode = incident.hostname || 'k3s-worker1'
  const threatPod = incident.pod
  const threatNs = incident.namespace

  const riskBars = [
    { label: 'Data exposure', width: incident.severity === 'CRITICAL' ? 82 : incident.severity === 'HIGH' ? 60 : 35, color: '#ff2d55' },
    { label: 'Lateral movement', width: incident.severity === 'CRITICAL' ? 54 : incident.severity === 'HIGH' ? 40 : 20, color: '#ff9f0a' },
    { label: 'Service disruption', width: incident.severity === 'CRITICAL' ? 48 : incident.severity === 'HIGH' ? 35 : 15, color: '#ff9f0a' },
    { label: 'Node compromise', width: incident.severity === 'CRITICAL' ? 22 : 10, color: '#ffd700' },
    { label: 'Cluster takeover', width: incident.severity === 'CRITICAL' ? 12 : 5, color: '#4a5568' },
  ]

  const getNodeStatus = (nodeName: string) => {
    if (nodeName === threatNode) return 'threat'
    if (incident.severity === 'CRITICAL') return 'risk'
    return 'safe'
  }

  const nodeColors = { threat: '#ff2d55', risk: '#ff9f0a', safe: '#00ff9f' }
  const nodeBgs = { threat: 'rgba(255,45,85,0.12)', risk: 'rgba(255,159,10,0.08)', safe: 'rgba(0,255,159,0.05)' }
  const nodeBorders = { threat: 'rgba(255,45,85,0.4)', risk: 'rgba(255,159,10,0.3)', safe: 'rgba(0,255,159,0.2)' }
  const nodeLabels = { threat: 'THREAT', risk: 'AT RISK', safe: 'CLEAN' }

  return (
    <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.1)', borderRadius: '10px', padding: '12px', marginBottom: '10px', position: 'relative', overflow: 'hidden' }}>
      <div style={{ position: 'absolute', left: 0, right: 0, height: '1px', background: 'linear-gradient(90deg,transparent,rgba(0,255,159,0.4),transparent)', top: `${scanPos}%`, transition: 'top 0.03s linear', pointerEvents: 'none' }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', paddingBottom: '8px', borderBottom: '1px solid rgba(0,255,159,0.06)' }}>
        <span style={{ fontSize: '8px', background: 'rgba(0,255,159,0.08)', border: '1px solid rgba(0,255,159,0.2)', color: '#00ff9f', padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>argus-k8s</span>
        <span style={{ fontSize: '11px', fontWeight: 600, color: '#f0f6fc' }}>Production cluster</span>
        <span style={{ fontSize: '8px', color: '#4a5568', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>3 nodes · 4 namespaces</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '10px' }}>
        {NODES.map(node => {
          const status = getNodeStatus(node.name) as 'threat' | 'risk' | 'safe'
          const isThreat = status === 'threat'
          return (
            <div key={node.name} style={{ background: nodeBgs[status], border: `1px solid ${nodeBorders[status]}`, borderRadius: '7px', padding: '8px 10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: nodeColors[status], boxShadow: isThreat ? `0 0 6px ${nodeColors[status]}` : 'none', flexShrink: 0, animation: isThreat ? 'pulse 1.5s infinite' : 'none' }} />
                <span style={{ fontSize: '10px', fontWeight: 700, color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>{node.name}</span>
                <span style={{ fontSize: '8px', color: nodeColors[status], fontFamily: 'JetBrains Mono, monospace', marginLeft: '2px' }}>{nodeLabels[status]}</span>
                <span style={{ fontSize: '8px', color: '#4a5568', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>{node.ip}</span>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                {isThreat && threatPod && (
                  <span style={{ fontSize: '9px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(255,45,85,0.15)', border: '1px solid rgba(255,45,85,0.4)', color: '#ff2d55', fontFamily: 'JetBrains Mono, monospace', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#ff2d55', display: 'inline-block', animation: 'pulse 1.5s infinite' }} />
                    {threatPod}
                    {threatNs && <span style={{ fontSize: '7px', padding: '0 3px', background: 'rgba(88,166,255,0.15)', borderRadius: '2px', color: '#58a6ff' }}>{threatNs}</span>}
                  </span>
                )}
                {isThreat && (
                  <>
                    <span style={{ fontSize: '9px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(75,85,99,0.2)', border: '1px solid rgba(75,85,99,0.3)', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>isolated api-gateway</span>
                    <span style={{ fontSize: '9px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(255,159,10,0.08)', border: '1px solid rgba(255,159,10,0.25)', color: '#ff9f0a', fontFamily: 'JetBrains Mono, monospace' }}>backend-svc</span>
                    <span style={{ fontSize: '9px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(0,255,159,0.05)', border: '1px solid rgba(0,255,159,0.15)', color: '#00ff9f', fontFamily: 'JetBrains Mono, monospace' }}>falco-agent</span>
                  </>
                )}
                {status === 'risk' && (
                  <>
                    <span style={{ fontSize: '9px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(255,159,10,0.08)', border: '1px solid rgba(255,159,10,0.25)', color: '#ff9f0a', fontFamily: 'JetBrains Mono, monospace' }}>postgres-0</span>
                    <span style={{ fontSize: '9px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(255,159,10,0.08)', border: '1px solid rgba(255,159,10,0.25)', color: '#ff9f0a', fontFamily: 'JetBrains Mono, monospace' }}>auth-service</span>
                    <span style={{ fontSize: '9px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(0,255,159,0.05)', border: '1px solid rgba(0,255,159,0.15)', color: '#00ff9f', fontFamily: 'JetBrains Mono, monospace' }}>prometheus</span>
                  </>
                )}
                {status === 'safe' && (
                  <>
                    <span style={{ fontSize: '9px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(0,255,159,0.05)', border: '1px solid rgba(0,255,159,0.15)', color: '#00ff9f', fontFamily: 'JetBrains Mono, monospace' }}>argus-agent</span>
                    <span style={{ fontSize: '9px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(0,255,159,0.05)', border: '1px solid rgba(0,255,159,0.15)', color: '#00ff9f', fontFamily: 'JetBrains Mono, monospace' }}>kyverno</span>
                    <span style={{ fontSize: '9px', padding: '2px 7px', borderRadius: '4px', background: 'rgba(0,255,159,0.05)', border: '1px solid rgba(0,255,159,0.15)', color: '#00ff9f', fontFamily: 'JetBrains Mono, monospace' }}>cilium</span>
                  </>
                )}
              </div>
            </div>
          )
        })}
      </div>

      <div style={{ borderTop: '1px solid rgba(0,255,159,0.05)', paddingTop: '8px' }}>
        {riskBars.map(({ label, width, color }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span style={{ fontSize: '8px', color: '#6b7280', width: '110px', flexShrink: 0, fontFamily: 'JetBrains Mono, monospace' }}>{label}</span>
            <div style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.04)', borderRadius: '2px', overflow: 'hidden' }}>
              <div style={{ height: '100%', borderRadius: '2px', background: color, width: barsAnimated ? `${width}%` : '0%', transition: 'width 1.2s ease-out' }} />
            </div>
            <span style={{ fontSize: '8px', fontWeight: 700, color, width: '28px', textAlign: 'right', fontFamily: 'JetBrains Mono, monospace' }}>{width}%</span>
          </div>
        ))}
      </div>

      <style>{`@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(255,45,85,0.5)}50%{box-shadow:0 0 0 4px rgba(255,45,85,0)}}`}</style>
    </div>
  )
}

export default function ThreatFeed() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [selected, setSelected] = useState<Incident | null>(null)
  const [filter, setFilter] = useState<string>('ALL')
  const [nsFilter, setNsFilter] = useState<string>('ALL')
  const [loading, setLoading] = useState(true)
  const prevCount = useRef(0)
  const newIds = useRef<Set<string>>(new Set())

  const fetchIncidents = async () => {
    try {
      const r = await fetch(`${API}/incidents?limit=100`)
      if (!r.ok) return
      const data = await r.json()
      const fresh = data.incidents as Incident[]
      if (fresh.length > prevCount.current) {
        const newOnes = fresh.slice(0, fresh.length - prevCount.current)
        newOnes.forEach(i => newIds.current.add(i.id))
        setTimeout(() => {
          newOnes.forEach(i => newIds.current.delete(i.id))
        }, 2000)
      }
      prevCount.current = fresh.length
      setIncidents(fresh)
      setLoading(false)
    } catch {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchIncidents()
    const t = setInterval(fetchIncidents, 3000)
    return () => clearInterval(t)
  }, [])

  const namespaces = ['ALL', ...Array.from(new Set(incidents.map(i => i.namespace).filter(Boolean)))]
  const filtered = incidents.filter(i => {
    if (filter !== 'ALL' && i.severity !== filter) return false
    if (nsFilter !== 'ALL' && i.namespace !== nsFilter) return false
    return true
  })

  const fmt = (ts: number) => {
    const d = new Date(ts * 1000)
    const diff = Math.floor((Date.now() - ts * 1000) / 1000)
    if (diff < 60) return `${diff}s ago`
    if (diff < 3600) return `${Math.floor(diff/60)}m ago`
    return d.toTimeString().slice(0,5)
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 440px' : '1fr', height: '100%', overflow: 'hidden' }}>
      <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: '1px solid rgba(0,255,159,0.1)', display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>
          <span style={{ fontSize: '9px', color: '#8b949e', textTransform: 'uppercase', letterSpacing: '2px' }}>
            ⚡ Live threat feed
          </span>
          <span style={{ fontSize: '9px', color: '#4a5568', marginLeft: 'auto' }}>
            {filtered.length} incidents
          </span>
          {(['ALL','CRITICAL','HIGH','MED','LOW'] as const).map(s => (
            <button key={s} onClick={() => setFilter(s)} style={{
              fontSize: '9px', padding: '3px 10px', borderRadius: '10px', cursor: 'pointer', fontWeight: 700,
              background: filter === s ? (SEV_CONFIG[s]?.bg || 'rgba(0,255,159,0.1)') : 'transparent',
              border: `1px solid ${filter === s ? (SEV_CONFIG[s]?.border || 'rgba(0,255,159,0.2)') : 'rgba(75,85,99,0.3)'}`,
              color: filter === s ? (SEV_CONFIG[s]?.color || '#00ff9f') : '#4a5568',
            }}>{s}</button>
          ))}
          <select value={nsFilter} onChange={e => setNsFilter(e.target.value)} style={{
            fontSize: '8px', background: '#161b22', border: '1px solid rgba(0,255,159,0.1)',
            color: '#8b949e', padding: '2px 6px', borderRadius: '4px', cursor: 'pointer',
          }}>
            {namespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
          </select>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '8px', display: 'flex', flexDirection: 'column', gap: '5px' }}>
          {loading && (
            <div style={{ color: '#4a5568', fontSize: '10px', textAlign: 'center', padding: '20px' }}>
              Connecting to agent...
            </div>
          )}
          {!loading && filtered.length === 0 && (
            <div style={{ color: '#4a5568', fontSize: '10px', textAlign: 'center', padding: '20px' }}>
              No incidents. Cluster is clean.
            </div>
          )}
          {filtered.map(inc => {
            const sev = SEV_CONFIG[inc.severity] || SEV_CONFIG.LOW
            const act = ACTION_CONFIG[inc.action_taken] || ACTION_CONFIG.LOG
            const isNew = newIds.current.has(inc.id)
            return (
              <div key={inc.id} onClick={() => setSelected(selected?.id === inc.id ? null : inc)}
                style={{
                  borderRadius: '6px', border: `1px solid ${selected?.id === inc.id ? 'rgba(0,255,159,0.3)' : sev.border}`,
                  background: selected?.id === inc.id ? '#1c2433' : inc.severity === 'CRITICAL' ? 'rgba(255,45,85,0.05)' : '#1a2233',
                  padding: '13px 15px', minHeight: '80px', cursor: 'pointer', position: 'relative', overflow: 'hidden',
                  fontFamily: 'Inter, sans-serif',
                  transition: 'all 0.12s',
                  animation: isNew ? 'slideIn 0.3s ease-out' : undefined,
                }}
              >
                <div style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: '4px', background: sev.dot, borderRadius: '3px 0 0 3px' }} />
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ fontSize: '10px', fontWeight: 700, padding: '3px 8px', borderRadius: '3px', background: sev.bg, color: sev.color, border: `1px solid ${sev.border}`, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      ● {inc.severity}
                    </span>
                    <span style={{ fontSize: '10px', color: `${act.color}`, background: `${act.color}22`, padding: '2px 8px', borderRadius: '3px', border: `1px solid ${act.color}44` }}>
                      {act.label}
                    </span>
                  </div>
                  <span style={{ fontSize: '10px', color: '#6b7280', fontFamily: 'JetBrains Mono, monospace' }}>{fmt(inc.ts)} · {inc.hostname}</span>
                </div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#f0f6fc', fontFamily: 'Inter, sans-serif', letterSpacing: '-0.01em', marginBottom: '5px', lineHeight: 1.3 }}>{inc.rule}</div>
                <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
                  {inc.namespace && <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'rgba(88,166,255,0.8)', background: 'rgba(88,166,255,0.08)', padding: '2px 7px', borderRadius: '3px', border: '1px solid rgba(88,166,255,0.2)' }}>{inc.namespace}</span>}
                  {inc.pod && <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: '#4a5568', background: '#0d1117', padding: '2px 7px', borderRadius: '3px', border: '1px solid rgba(0,255,159,0.08)' }}>{inc.pod}</span>}
                  {inc.mitre_tags?.map(t => <span key={t} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'rgba(188,140,255,0.8)', background: 'rgba(188,140,255,0.06)', padding: '2px 7px', borderRadius: '3px', border: '1px solid rgba(188,140,255,0.2)' }}>{t}</span>)}
                  <span style={{ fontSize: '10px', color: '#4a5568', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>
                    {Math.round(inc.confidence * 100)}% confidence
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {selected && (
        <div style={{ borderLeft: '1px solid rgba(0,255,159,0.1)', display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#0d1117' }}>
          <div style={{ padding: '10px 14px', borderBottom: '1px solid rgba(0,255,159,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
            <span style={{ fontSize: '11px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px' }}>Incident detail</span>
            <button onClick={() => setSelected(null)} style={{ fontSize: '12px', color: '#4a5568', background: 'transparent', border: 'none', cursor: 'pointer' }}>✕</button>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: '12px', fontFamily: 'Inter, sans-serif' }}>
            <DetailSection title="Alert">
              <Row label="Rule" value={selected.rule} />
              <Row label="Priority" value={selected.priority} />
              <Row label="Severity" value={selected.severity} color={SEV_CONFIG[selected.severity]?.color} />
              <Row label="Hostname" value={selected.hostname} />
            </DetailSection>
            <DetailSection title="Target">
              <Row label="Pod" value={selected.pod || '— host level'} color={!selected.pod ? '#4a5568' : undefined} />
              <Row label="Namespace" value={selected.namespace || '— host level'} color={!selected.namespace ? '#4a5568' : undefined} />
              <Row label="MITRE" value={selected.mitre_tags?.join(', ') || 'none'} />
            </DetailSection>
            <div style={{ marginBottom: '14px' }}>
              <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '10px', paddingBottom: '4px', borderBottom: '1px solid rgba(0,255,159,0.08)', fontFamily: 'JetBrains Mono, monospace' }}>AI Assessment</div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#00ff9f', boxShadow: '0 0 6px #00ff9f', flexShrink: 0, animation: 'glowpulse 2s infinite' }} />
                <span style={{ fontSize: '9px', color: '#00ff9f', fontFamily: 'JetBrains Mono, monospace' }}>ARGUS AI · claude-sonnet-4-6</span>
                <div style={{ flex: 1, height: '1px', background: 'rgba(0,255,159,0.1)' }} />
                <span style={{ fontSize: '9px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>{Math.round(selected.confidence * 100)}% confidence</span>
              </div>

              <div style={{ background: 'rgba(255,45,85,0.05)', border: '1px solid rgba(255,45,85,0.12)', borderRadius: '8px', padding: '10px 12px', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '7px' }}>
                  <span style={{ fontSize: '9px', fontWeight: 700, color: '#ff2d55', textTransform: 'uppercase', letterSpacing: '1px', fontFamily: 'JetBrains Mono, monospace' }}>What happened</span>
                </div>
                {((selected as any).what_happened?.length > 0 ? (selected as any).what_happened : [selected.assessment]).map((bullet: string, i: number) => (
                  <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '5px', alignItems: 'flex-start' }}>
                    <span style={{ color: '#ff2d55', fontSize: '10px', marginTop: '2px', flexShrink: 0 }}>▸</span>
                    <span style={{ fontSize: '11px', color: '#d1d5db', lineHeight: 1.6, fontFamily: 'Inter, sans-serif' }}>{bullet}</span>
                  </div>
                ))}
              </div>

              <ImpactDiagram incident={selected} />

              <div style={{ background: 'rgba(88,166,255,0.04)', border: '1px solid rgba(88,166,255,0.12)', borderRadius: '8px', padding: '10px 12px', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '7px' }}>
                  <span style={{ fontSize: '9px', fontWeight: 700, color: '#58a6ff', textTransform: 'uppercase', letterSpacing: '1px', fontFamily: 'JetBrains Mono, monospace' }}>Recommended actions</span>
                </div>
                {((selected as any).action_steps?.length > 0 ? (selected as any).action_steps : [`Take action: ${selected.recommended_action}`]).map((step: string, i: number) => (
                  <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '7px', alignItems: 'flex-start' }}>
                    <div style={{ width: '18px', height: '18px', borderRadius: '50%', background: 'rgba(88,166,255,0.12)', border: '1px solid rgba(88,166,255,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '8px', color: '#58a6ff', fontWeight: 700, flexShrink: 0, marginTop: '1px', fontFamily: 'JetBrains Mono, monospace' }}>{i + 1}</div>
                    <span style={{ fontSize: '11px', color: '#d1d5db', lineHeight: 1.6, fontFamily: 'Inter, sans-serif' }}>{step}</span>
                  </div>
                ))}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
                <div style={{ background: selected.likely_false_positive ? 'rgba(0,255,159,0.06)' : 'rgba(255,45,85,0.06)', border: `1px solid ${selected.likely_false_positive ? 'rgba(0,255,159,0.2)' : 'rgba(255,45,85,0.2)'}`, borderRadius: '8px', padding: '10px', textAlign: 'center' }}>
                  <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '5px', fontFamily: 'Inter, sans-serif', fontWeight: 600 }}>False positive</div>
                  <div style={{ fontSize: '20px', fontWeight: 700, color: selected.likely_false_positive ? '#00ff9f' : '#ff2d55', fontFamily: 'Inter, sans-serif' }}>{selected.likely_false_positive ? 'Yes' : 'No'}</div>
                </div>
                <div style={{ background: 'rgba(88,166,255,0.06)', border: '1px solid rgba(88,166,255,0.2)', borderRadius: '8px', padding: '10px', textAlign: 'center' }}>
                  <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '5px', fontFamily: 'Inter, sans-serif', fontWeight: 600 }}>Confidence</div>
                  <div style={{ fontSize: '20px', fontWeight: 700, color: '#58a6ff', fontFamily: 'Inter, sans-serif' }}>{Math.round(selected.confidence * 100)}%</div>
                </div>
              </div>
              <style>{`@keyframes glowpulse{0%,100%{box-shadow:0 0 4px #00ff9f}50%{box-shadow:0 0 10px #00ff9f,0 0 20px rgba(0,255,159,0.3)}}`}</style>
            </div>
            <DetailSection title="Response">
              <Row label="Recommended" value={selected.recommended_action} />
              <Row label="Action taken" value={selected.action_taken} color={ACTION_CONFIG[selected.action_taken]?.color} />
              <Row label="Status" value={selected.action_status} />
            </DetailSection>
            <DetailSection title="Enrichment">
              <Row label="Sources" value={selected.enrichment_sources?.join(', ') || 'none'} />
              <Row label="Duration" value={`${selected.enrichment_duration_ms}ms`} />
            </DetailSection>
          </div>
        </div>
      )}

      <style>{`
        @keyframes slideIn { from { opacity: 0; transform: translateX(20px); } to { opacity: 1; transform: translateX(0); } }
        ::-webkit-scrollbar { width: 2px; }
        ::-webkit-scrollbar-thumb { background: rgba(0,255,159,0.15); border-radius: 1px; }
      `}</style>
    </div>
  )
}

function DetailSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: '14px' }}>
      <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '6px', paddingBottom: '4px', borderBottom: '1px solid rgba(0,255,159,0.08)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 500 }}>{title}</div>
      {children}
    </div>
  )
}

function Row({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '2px 0', gap: '8px' }}>
      <span style={{ fontSize: '11px', fontFamily: 'Inter, sans-serif', color: '#6b7280', fontWeight: 500, flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: '11px', fontFamily: 'Inter, sans-serif', color: color || '#e2e8f5', fontWeight: 500, textAlign: 'right', wordBreak: 'break-all' }}>{value}</span>
    </div>
  )
}
