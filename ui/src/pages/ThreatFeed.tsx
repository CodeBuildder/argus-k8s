import { useState, useEffect, useRef } from 'react'

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
              <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '8px', paddingBottom: '4px', borderBottom: '1px solid rgba(0,255,159,0.08)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 500 }}>AI Assessment</div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#00ff9f', boxShadow: '0 0 6px #00ff9f', flexShrink: 0 }} />
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: '#00ff9f', letterSpacing: '1px' }}>ARGUS AI · claude-sonnet-4-6</span>
                <div style={{ flex: 1, height: '1px', background: 'rgba(0,255,159,0.1)' }} />
                <span style={{ fontSize: '10px', color: '#4a5568' }}>{Math.round(selected.confidence * 100)}% confidence</span>
              </div>

              <div style={{ background: 'rgba(0,255,159,0.03)', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '6px', padding: '10px 12px', marginBottom: '10px', position: 'relative' }}>
                <div style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: '2px', background: 'linear-gradient(180deg, #00ff9f, transparent)', borderRadius: '6px 0 0 6px' }} />
                <p style={{ fontSize: '13px', lineHeight: 1.8, color: '#d1d5db', fontFamily: 'Inter, sans-serif', fontWeight: 400, letterSpacing: '0.01em', margin: 0 }}>{selected.assessment}</p>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px', marginBottom: '10px' }}>
                <div style={{ background: selected.likely_false_positive ? 'rgba(0,255,159,0.06)' : 'rgba(255,45,85,0.06)', border: `1px solid ${selected.likely_false_positive ? 'rgba(0,255,159,0.2)' : 'rgba(255,45,85,0.2)'}`, borderRadius: '6px', padding: '8px 10px', textAlign: 'center' }}>
                  <div style={{ fontFamily: 'Inter, sans-serif', fontWeight: 600, letterSpacing: '0.05em', fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', marginBottom: '4px' }}>False positive</div>
                  <div style={{ fontSize: '22px', fontWeight: 700, fontFamily: 'Inter, sans-serif', letterSpacing: '-0.02em', color: selected.likely_false_positive ? '#00ff9f' : '#ff2d55' }}>{selected.likely_false_positive ? 'Yes' : 'No'}</div>
                </div>
                <div style={{ background: 'rgba(88,166,255,0.06)', border: '1px solid rgba(88,166,255,0.2)', borderRadius: '6px', padding: '8px 10px', textAlign: 'center' }}>
                  <div style={{ fontFamily: 'Inter, sans-serif', fontWeight: 600, letterSpacing: '0.05em', fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', marginBottom: '4px' }}>Confidence</div>
                  <div style={{ fontSize: '22px', fontWeight: 700, fontFamily: 'Inter, sans-serif', letterSpacing: '-0.02em', color: '#58a6ff' }}>{Math.round(selected.confidence * 100)}%</div>
                </div>
              </div>

              <div style={{ background: 'rgba(255,159,10,0.04)', border: '1px solid rgba(255,159,10,0.15)', borderRadius: '6px', padding: '8px 10px' }}>
                <div style={{ fontSize: '9px', color: '#ff9f0a', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '4px', fontFamily: 'JetBrains Mono, monospace', fontWeight: 500 }}>Blast radius</div>
                <p style={{ fontSize: '12px', lineHeight: 1.7, fontFamily: 'Inter, sans-serif', color: '#9ca3af', margin: 0 }}>{selected.blast_radius}</p>
              </div>
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
