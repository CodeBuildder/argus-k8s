import { useEffect, useMemo, useState } from 'react'

const API = '/api'

interface NetworkFlow {
  id: string
  incident_id?: string
  source_namespace: string
  source_pod: string
  dest_namespace: string
  dest_pod: string
  dest_port: number
  protocol: string
  verdict: 'FORWARDED' | 'DROPPED' | 'AUDIT'
  bytes: number
  packets: number
  timestamp: number
  rule?: string
  severity?: string
  action_taken?: string
}

interface NamespaceNode {
  name: string
  pods: number
  incidents_1h: number
  critical_1h: number
}

interface FlowResponse {
  source: string
  generated_at: string
  flows: NetworkFlow[]
  namespaces: NamespaceNode[]
  stats: {
    active_flows: number
    forwarded: number
    dropped: number
    audit: number
    flow_rate: number
  }
}

const NS_COLORS = ['#58a6ff', '#ff9f0a', '#bc8cff', '#00ff9f', '#ff6b9d', '#00d4ff', '#ffd700']
const VERDICT_COLOR = { FORWARDED: '#00ff9f', DROPPED: '#ff2d55', AUDIT: '#ff9f0a' }

function nsColor(name: string) {
  const total = name.split('').reduce((sum, ch) => sum + ch.charCodeAt(0), 0)
  return NS_COLORS[total % NS_COLORS.length]
}

function fmtBytes(bytes: number) {
  if (bytes > 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)}MB`
  if (bytes > 1024) return `${Math.round(bytes / 1024)}KB`
  return `${bytes}B`
}

function fmtAge(ts: number) {
  const seconds = Math.max(0, Math.floor((Date.now() - ts * 1000) / 1000))
  if (seconds < 60) return `${seconds}s ago`
  return `${Math.floor(seconds / 60)}m ago`
}

export default function ClusterMap() {
  const [data, setData] = useState<FlowResponse | null>(null)
  const [selectedNamespace, setSelectedNamespace] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchFlows = async () => {
      try {
        const res = await fetch(`${API}/network-flows?limit=80`)
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const next = await res.json()
        setData(next)
        setError(null)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'failed to load network flows')
      } finally {
        setLoading(false)
      }
    }

    fetchFlows()
    const timer = setInterval(fetchFlows, 3000)
    return () => clearInterval(timer)
  }, [])

  const flows = data?.flows || []
  const namespaces = data?.namespaces || []
  const filteredFlows = selectedNamespace
    ? flows.filter(flow => flow.source_namespace === selectedNamespace || flow.dest_namespace === selectedNamespace)
    : flows

  const namespaceStats = useMemo(() => {
    return namespaces.map(ns => {
      const outbound = flows.filter(flow => flow.source_namespace === ns.name)
      const inbound = flows.filter(flow => flow.dest_namespace === ns.name)
      const dropped = [...outbound, ...inbound].filter(flow => flow.verdict === 'DROPPED').length
      return { ...ns, outbound: outbound.length, inbound: inbound.length, dropped }
    })
  }, [flows, namespaces])

  const topEdges = useMemo(() => {
    const counts = new Map<string, { source: string; dest: string; count: number; dropped: number }>()
    flows.forEach(flow => {
      const key = `${flow.source_namespace}->${flow.dest_namespace}`
      const existing = counts.get(key) || { source: flow.source_namespace, dest: flow.dest_namespace, count: 0, dropped: 0 }
      existing.count += 1
      if (flow.verdict === 'DROPPED') existing.dropped += 1
      counts.set(key, existing)
    })
    return Array.from(counts.values()).sort((a, b) => b.count - a.count).slice(0, 6)
  }, [flows])

  const stats = data?.stats || { active_flows: 0, forwarded: 0, dropped: 0, audit: 0, flow_rate: 0 }

  return (
    <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <style>{`
        @keyframes softPulse { 0%,100%{opacity:0.55} 50%{opacity:1} }
        @keyframes slideIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes dataSweep { 0%{transform:translateX(-100%);opacity:0} 20%{opacity:1} 100%{transform:translateX(100%);opacity:0} }
      `}</style>

      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>Network Topology</div>
        <span style={{
          fontSize: '8px',
          color: error ? '#ff9f0a' : '#00d4ff',
          border: `1px solid ${error ? 'rgba(255,159,10,0.25)' : 'rgba(0,212,255,0.25)'}`,
          background: error ? 'rgba(255,159,10,0.06)' : 'rgba(0,212,255,0.06)',
          borderRadius: '4px',
          padding: '3px 7px',
          fontFamily: 'JetBrains Mono, monospace',
        }}>
          {error ? `source unavailable: ${error}` : `source: ${data?.source || 'loading'}`}
        </span>
        <span style={{ marginLeft: 'auto', fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>
          {data?.generated_at ? `updated ${new Date(data.generated_at).toLocaleTimeString()}` : loading ? 'loading...' : 'no update'}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
        {[
          { label: 'Flow rate', value: `${stats.flow_rate.toFixed(2)}/s`, color: '#00d4ff', sub: 'incident-derived' },
          { label: 'Active flows', value: stats.active_flows, color: '#58a6ff', sub: 'last hour' },
          { label: 'Forwarded', value: stats.forwarded, color: '#00ff9f', sub: 'allowed paths' },
          { label: 'Dropped / audit', value: `${stats.dropped}/${stats.audit}`, color: stats.dropped > 0 ? '#ff2d55' : '#ff9f0a', sub: 'policy outcomes' },
        ].map(item => (
          <div key={item.label} style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '8px', padding: '10px 12px', position: 'relative', overflow: 'hidden' }}>
            <div style={{ position: 'absolute', left: 0, right: 0, top: 0, height: '1px', background: `linear-gradient(90deg, transparent, ${item.color}, transparent)`, animation: 'dataSweep 3s linear infinite' }} />
            <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '5px' }}>{item.label}</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
              <span style={{ fontSize: '21px', fontWeight: 800, color: item.color }}>{item.value}</span>
              <span style={{ fontSize: '8px', color: '#5a6478' }}>{item.sub}</span>
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.85fr) minmax(340px, 0.95fr)', gap: '12px', flex: 1, minHeight: 0 }}>
        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '14px', minHeight: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>
              Namespace Traffic
            </div>
            <span style={{ fontSize: '8px', color: '#4a5568', marginLeft: 'auto' }}>click namespace to filter live flows</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.05fr 1fr', gap: '14px', minHeight: 0 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(180px, 1fr))', gap: '10px', alignContent: 'start' }}>
              {namespaceStats.map(ns => {
                const color = nsColor(ns.name)
                const selected = selectedNamespace === ns.name
                const active = ns.inbound + ns.outbound > 0
                return (
                  <button
                    key={ns.name}
                    onClick={() => setSelectedNamespace(selected ? null : ns.name)}
                    style={{
                      textAlign: 'left',
                      background: selected ? `${color}18` : 'rgba(0,0,0,0.22)',
                      border: `1px solid ${selected ? color : `${color}35`}`,
                      borderRadius: '8px',
                      padding: '11px 12px',
                      cursor: 'pointer',
                      transition: 'all 0.16s ease',
                      boxShadow: selected ? `0 0 20px ${color}20` : 'none',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '9px' }}>
                      <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: active ? color : '#2d3748', boxShadow: active ? `0 0 8px ${color}` : 'none', animation: active ? 'softPulse 2s infinite' : 'none' }} />
                      <span style={{ color, fontSize: '12px', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace' }}>{ns.name}</span>
                      <span style={{ marginLeft: 'auto', fontSize: '8px', color: ns.critical_1h > 0 ? '#ff2d55' : '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>
                        {ns.critical_1h} critical
                      </span>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '7px' }}>
                      {[
                        ['pods', ns.pods],
                        ['out', ns.outbound],
                        ['in', ns.inbound],
                        ['drop', ns.dropped],
                      ].map(([label, value]) => (
                        <div key={label} style={{ background: 'rgba(255,255,255,0.03)', borderRadius: '5px', padding: '6px 5px' }}>
                          <div style={{ fontSize: '7px', color: '#4a5568', textTransform: 'uppercase', marginBottom: '3px' }}>{label}</div>
                          <div style={{ fontSize: '12px', color: label === 'drop' && Number(value) > 0 ? '#ff2d55' : '#e6edf3', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace' }}>{value}</div>
                        </div>
                      ))}
                    </div>
                  </button>
                )
              })}
            </div>

            <div style={{ background: 'rgba(0,0,0,0.18)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '8px', padding: '12px', minHeight: '360px', display: 'flex', flexDirection: 'column', gap: '9px' }}>
              <div style={{ fontSize: '9px', color: '#58a6ff', textTransform: 'uppercase', letterSpacing: '1.5px', fontFamily: 'JetBrains Mono, monospace' }}>Top paths</div>
              {topEdges.length === 0 && (
                <div style={{ color: '#4a5568', fontSize: '11px', lineHeight: 1.6, marginTop: '20px' }}>
                  No network-class incidents in the current hour. Trigger Cilium/DNS/egress events to populate this map.
                </div>
              )}
              {topEdges.map(edge => {
                const sourceColor = nsColor(edge.source)
                const destColor = nsColor(edge.dest)
                const width = Math.min(100, 22 + edge.count * 13)
                return (
                  <div key={`${edge.source}-${edge.dest}`} style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '7px', padding: '9px 10px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                      <span style={{ color: sourceColor, fontSize: '9px', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace' }}>{edge.source}</span>
                      <span style={{ flex: 1, height: '2px', background: `linear-gradient(90deg, ${sourceColor}, ${destColor})`, borderRadius: '2px', position: 'relative' }}>
                        <span style={{ position: 'absolute', left: `${width}%`, top: '-3px', width: '8px', height: '8px', borderRadius: '50%', background: edge.dropped > 0 ? '#ff2d55' : destColor, boxShadow: `0 0 8px ${edge.dropped > 0 ? '#ff2d55' : destColor}` }} />
                      </span>
                      <span style={{ color: destColor, fontSize: '9px', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace' }}>{edge.dest}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '8px', color: '#5a6478' }}>
                      <span>{edge.count} flow signals</span>
                      <span style={{ color: edge.dropped > 0 ? '#ff2d55' : '#00ff9f' }}>{edge.dropped} dropped</span>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '9px', minHeight: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>Live Flow Evidence</div>
            <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: error ? '#ff9f0a' : '#00ff9f', animation: 'softPulse 1.5s infinite', boxShadow: `0 0 6px ${error ? '#ff9f0a' : '#00ff9f'}` }} />
          </div>

          {selectedNamespace && (
            <button onClick={() => setSelectedNamespace(null)} style={{ alignSelf: 'flex-start', background: 'rgba(88,166,255,0.08)', border: '1px solid rgba(88,166,255,0.22)', borderRadius: '5px', color: '#58a6ff', fontSize: '8px', padding: '4px 8px', cursor: 'pointer', fontFamily: 'JetBrains Mono, monospace' }}>
              clear filter: {selectedNamespace}
            </button>
          )}

          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '7px', paddingBottom: '12px' }}>
            {filteredFlows.length === 0 && (
              <div style={{ color: '#4a5568', fontSize: '11px', lineHeight: 1.6, padding: '18px 4px' }}>
                {loading ? 'Loading topology evidence...' : 'No flow evidence for the selected scope.'}
              </div>
            )}
            {filteredFlows.map((flow, idx) => {
              const verdictColor = VERDICT_COLOR[flow.verdict]
              return (
                <div key={`${flow.id}-${idx}`} style={{
                  padding: '10px',
                  background: idx === 0 ? `${verdictColor}08` : 'rgba(0,0,0,0.2)',
                  borderRadius: '7px',
                  border: `1px solid ${verdictColor}22`,
                  borderLeft: `3px solid ${verdictColor}`,
                  animation: idx === 0 ? 'slideIn 0.3s ease-out' : 'none',
                  fontSize: '9px',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '7px' }}>
                    <span style={{ padding: '2px 6px', background: `${nsColor(flow.source_namespace)}18`, border: `1px solid ${nsColor(flow.source_namespace)}3d`, borderRadius: '4px', color: nsColor(flow.source_namespace), fontSize: '8px', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace' }}>
                      {flow.source_namespace}
                    </span>
                    <span style={{ color: '#4a5568' }}>→</span>
                    <span style={{ padding: '2px 6px', background: `${nsColor(flow.dest_namespace)}18`, border: `1px solid ${nsColor(flow.dest_namespace)}3d`, borderRadius: '4px', color: nsColor(flow.dest_namespace), fontSize: '8px', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace' }}>
                      {flow.dest_namespace}
                    </span>
                    <span style={{ marginLeft: 'auto', color: verdictColor, fontSize: '8px', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace' }}>{flow.verdict}</span>
                  </div>
                  <div style={{ color: '#c9d1d9', fontSize: '10px', marginBottom: '5px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {flow.source_pod} → {flow.dest_pod}
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '8px', color: '#5a6478', fontFamily: 'JetBrains Mono, monospace', marginBottom: '6px' }}>
                    <span>{flow.protocol}:{flow.dest_port}</span>
                    <span>{fmtBytes(flow.bytes)} · {flow.packets}pkt · {fmtAge(flow.timestamp)}</span>
                  </div>
                  {flow.rule && (
                    <div style={{ color: '#6b7280', fontSize: '8px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {flow.rule}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
