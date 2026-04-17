import React from 'react'

const STAGE_COLORS: Record<string, string> = {
  'Reconnaissance': '#bc8cff',
  'Initial Access': '#ff9f0a',
  'Execution': '#ff2d55',
  'Privilege Escalation': '#ff2d55',
  'Persistence': '#ff6b35',
  'Defense Evasion': '#ffd700',
  'Lateral Movement': '#ff9f0a',
  'Exfiltration': '#ff2d55',
}

const STAGE_ICONS: Record<string, string> = {
  'Reconnaissance': '◉',
  'Initial Access': '▶',
  'Execution': '⚡',
  'Privilege Escalation': '▲',
  'Persistence': '⊕',
  'Defense Evasion': '◎',
  'Lateral Movement': '→',
  'Exfiltration': '↑',
}

interface AttackChain {
  id: string
  created_at: string
  duration_seconds: number
  namespace: string
  hostname: string
  pod: string
  alert_count: number
  stages_detected: string[]
  stage_count: number
  confidence: number
  severity: string
  mitre_tactics: string[]
  alerts: Array<{
    rule: string
    stage: string
    mitre_tactic: string
    ts: number
    severity: string
  }>
}

export default function AttackChains() {
  const [chains, setChains] = React.useState<AttackChain[]>([])
  const [selected, setSelected] = React.useState<AttackChain | null>(null)
  const [loading, setLoading] = React.useState(true)

  const fetchChains = async () => {
    try {
      const r = await fetch('/api/attack-chains')
      if (r.ok) {
        const data = await r.json()
        setChains(data.chains || [])
      }
      setLoading(false)
    } catch {
      setLoading(false)
    }
  }

  React.useEffect(() => {
    fetchChains()
    const t = setInterval(fetchChains, 5000)
    return () => clearInterval(t)
  }, [])

  const fmt = (ts: number) => {
    const diff = Math.floor((Date.now() - ts * 1000) / 1000)
    if (diff < 60) return `${diff}s ago`
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    return `${Math.floor(diff / 3600)}h ago`
  }

  const fmtDuration = (s: number) => {
    if (s < 60) return `${s}s`
    return `${Math.floor(s / 60)}m ${s % 60}s`
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <div style={{ padding: '10px 14px', borderBottom: '1px solid rgba(0,255,159,0.1)', display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
        <span style={{ fontSize: '9px', color: '#8b949e', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>⛓ Attack chains</span>
        <span style={{ fontSize: '9px', color: '#4a5568', marginLeft: 'auto' }}>{chains.length} chains detected</span>
        <button onClick={fetchChains} style={{ background: 'transparent', border: '1px solid rgba(0,255,159,0.2)', borderRadius: '5px', color: '#00ff9f', cursor: 'pointer', padding: '2px 8px', fontSize: '9px', fontFamily: 'JetBrains Mono, monospace' }}>↻</button>
      </div>

      <div style={{ flex: 1, display: 'grid', gridTemplateColumns: selected ? '1fr 420px' : '1fr', overflow: 'hidden' }}>
        <div style={{ overflowY: 'auto', padding: '8px' }}>
          {loading && <div style={{ color: '#4a5568', fontSize: '10px', textAlign: 'center', padding: '20px' }}>Connecting...</div>}
          {!loading && chains.length === 0 && (
            <div style={{ color: '#4a5568', fontSize: '10px', textAlign: 'center', padding: '40px 20px' }}>
              <div style={{ fontSize: '24px', marginBottom: '8px', opacity: 0.3 }}>⛓</div>
              <div style={{ marginBottom: '4px' }}>No attack chains detected yet.</div>
              <div style={{ fontSize: '9px' }}>Chains form when 2+ related alerts fire within 30 minutes.</div>
            </div>
          )}
          {chains.map(chain => (
            <div key={chain.id} onClick={() => setSelected(selected?.id === chain.id ? null : chain)}
              style={{
                borderRadius: '8px',
                border: `1px solid ${selected?.id === chain.id ? 'rgba(0,255,159,0.3)' : chain.severity === 'CRITICAL' ? 'rgba(255,45,85,0.25)' : 'rgba(255,159,10,0.2)'}`,
                background: selected?.id === chain.id ? '#1c2433' : '#161b22',
                padding: '12px 14px',
                cursor: 'pointer',
                marginBottom: '6px',
                transition: 'all 0.12s',
                animation: 'slideIn 0.25s ease-out',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <span style={{ fontSize: '8px', fontWeight: 700, padding: '2px 6px', borderRadius: '3px', background: chain.severity === 'CRITICAL' ? 'rgba(255,45,85,0.15)' : 'rgba(255,159,10,0.12)', color: chain.severity === 'CRITICAL' ? '#ff2d55' : '#ff9f0a', border: `1px solid ${chain.severity === 'CRITICAL' ? 'rgba(255,45,85,0.3)' : 'rgba(255,159,10,0.3)'}`, fontFamily: 'JetBrains Mono, monospace' }}>● {chain.severity}</span>
                <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>{chain.alert_count} alerts · {fmtDuration(chain.duration_seconds)}</span>
                <span style={{ fontSize: '8px', color: '#4a5568', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>{chain.hostname}</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0', marginBottom: '8px', overflowX: 'auto' }}>
                {chain.stages_detected.map((stage, i) => (
                  <React.Fragment key={stage}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '3px', flexShrink: 0 }}>
                      <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: `${STAGE_COLORS[stage]}18`, border: `1.5px solid ${STAGE_COLORS[stage]}`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '11px', color: STAGE_COLORS[stage] }}>
                        {STAGE_ICONS[stage] || '●'}
                      </div>
                      <span style={{ fontSize: '7px', color: STAGE_COLORS[stage], fontFamily: 'JetBrains Mono, monospace', textAlign: 'center', maxWidth: '50px', lineHeight: 1.2 }}>{stage}</span>
                    </div>
                    {i < chain.stages_detected.length - 1 && (
                      <div style={{ flex: 1, height: '1.5px', background: `linear-gradient(90deg, ${STAGE_COLORS[stage]}, ${STAGE_COLORS[chain.stages_detected[i + 1]]})`, minWidth: '20px', margin: '0 4px', marginBottom: '16px', opacity: 0.5 }} />
                    )}
                  </React.Fragment>
                ))}
              </div>

              <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                {chain.namespace && <span style={{ fontSize: '8px', color: '#58a6ff', background: 'rgba(88,166,255,0.08)', border: '1px solid rgba(88,166,255,0.2)', padding: '1px 5px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace' }}>{chain.namespace}</span>}
                {chain.pod && chain.pod !== 'unknown' && <span style={{ fontSize: '8px', color: '#4a5568', background: '#0d1117', border: '1px solid rgba(0,255,159,0.08)', padding: '1px 5px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace' }}>{chain.pod}</span>}
                <span style={{ fontSize: '8px', color: '#4a5568', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>{Math.round(chain.confidence * 100)}% confidence</span>
              </div>
            </div>
          ))}
        </div>

        {selected && (
          <div style={{ borderLeft: '1px solid rgba(0,255,159,0.1)', background: '#0d1117', display: 'flex', flexDirection: 'column', overflow: 'hidden', animation: 'slideInRight 0.2s ease-out' }}>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid rgba(0,255,159,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
              <span style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>Chain detail</span>
              <button onClick={() => setSelected(null)} style={{ fontSize: '12px', color: '#4a5568', background: 'transparent', border: 'none', cursor: 'pointer' }}>✕</button>
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: '14px' }}>
              <div style={{ marginBottom: '14px' }}>
                <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '8px', paddingBottom: '4px', borderBottom: '1px solid rgba(0,255,159,0.08)', fontFamily: 'JetBrains Mono, monospace' }}>Kill chain timeline</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {selected.alerts.map((alert, i) => (
                    <div key={i} style={{ display: 'flex', gap: '10px', alignItems: 'flex-start', animation: `fadeInUp 0.2s ease-out ${i * 0.05}s both` }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                        <div style={{ width: '24px', height: '24px', borderRadius: '50%', background: `${STAGE_COLORS[alert.stage] || '#4a5568'}18`, border: `1.5px solid ${STAGE_COLORS[alert.stage] || '#4a5568'}`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '10px', color: STAGE_COLORS[alert.stage] || '#4a5568' }}>
                          {STAGE_ICONS[alert.stage] || '●'}
                        </div>
                        {i < selected.alerts.length - 1 && <div style={{ width: '1.5px', height: '20px', background: 'rgba(0,255,159,0.1)', margin: '3px 0' }} />}
                      </div>
                      <div style={{ flex: 1, paddingBottom: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '3px' }}>
                          <span style={{ fontSize: '8px', fontWeight: 700, color: STAGE_COLORS[alert.stage] || '#4a5568', fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase' }}>{alert.stage}</span>
                          {alert.mitre_tactic && <span style={{ fontSize: '7px', color: '#bc8cff', background: 'rgba(188,140,255,0.08)', border: '1px solid rgba(188,140,255,0.2)', padding: '1px 4px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace' }}>{alert.mitre_tactic}</span>}
                          <span style={{ fontSize: '7px', color: '#4a5568', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>{fmt(alert.ts)}</span>
                        </div>
                        <div style={{ fontSize: '11px', color: '#d1d5db', fontFamily: 'Inter, sans-serif', lineHeight: 1.4 }}>{alert.rule}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ marginBottom: '14px' }}>
                <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '8px', paddingBottom: '4px', borderBottom: '1px solid rgba(0,255,159,0.08)', fontFamily: 'JetBrains Mono, monospace' }}>Chain metadata</div>
                {[
                  { label: 'Chain ID', value: selected.id },
                  { label: 'Duration', value: fmtDuration(selected.duration_seconds) },
                  { label: 'Alerts correlated', value: String(selected.alert_count) },
                  { label: 'Stages detected', value: String(selected.stage_count) },
                  { label: 'Confidence', value: `${Math.round(selected.confidence * 100)}%` },
                  { label: 'Node', value: selected.hostname },
                  { label: 'Namespace', value: selected.namespace || 'host-level' },
                ].map(({ label, value }) => (
                  <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', borderBottom: '1px solid rgba(0,255,159,0.04)' }}>
                    <span style={{ fontSize: '10px', color: '#6b7280', fontFamily: 'Inter, sans-serif' }}>{label}</span>
                    <span style={{ fontSize: '10px', color: '#e2e8f5', fontFamily: 'JetBrains Mono, monospace' }}>{value}</span>
                  </div>
                ))}
              </div>

              <div style={{ padding: '10px 12px', background: 'rgba(188,140,255,0.04)', border: '1px solid rgba(188,140,255,0.15)', borderRadius: '8px' }}>
                <div style={{ fontSize: '8px', color: '#bc8cff', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '5px', fontFamily: 'JetBrains Mono, monospace' }}>MITRE ATT&CK tactics</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                  {selected.mitre_tactics?.filter(Boolean).map(tactic => (
                    <span key={tactic} style={{ fontSize: '9px', color: '#bc8cff', background: 'rgba(188,140,255,0.08)', border: '1px solid rgba(188,140,255,0.2)', padding: '2px 6px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{tactic}</span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <style>{`
        @keyframes slideIn { from { opacity: 0; transform: translateX(20px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes slideInRight { from { opacity: 0; transform: translateX(20px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
      `}</style>
    </div>
  )
}
