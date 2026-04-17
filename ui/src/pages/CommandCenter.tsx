import { useState, useEffect } from 'react'

const API = '/api'

interface Stats {
  total_1h: number
  critical_1h: number
  high_1h: number
  auto_remediated_1h: number
  false_positives_1h: number
  total_all_time: number
}

export default function CommandCenter() {
  const [stats, setStats] = useState<Stats | null>(null)

  useEffect(() => {
    const fetch_ = async () => {
      try {
        const r = await fetch(`${API}/incidents/stats`)
        if (r.ok) setStats(await r.json())
      } catch {}
    }
    fetch_()
    const t = setInterval(fetch_, 10000)
    return () => clearInterval(t)
  }, [])

  const kpis = stats ? [
    { label: 'Active (1h)', value: stats.total_1h, color: '#ff9f0a' },
    { label: 'Critical (1h)', value: stats.critical_1h, color: '#ff2d55' },
    { label: 'High (1h)', value: stats.high_1h, color: '#ff9f0a' },
    { label: 'Auto-remediated', value: stats.auto_remediated_1h, color: '#58a6ff' },
    { label: 'False positives', value: stats.false_positives_1h, color: '#00ff9f' },
    { label: 'Total all time', value: stats.total_all_time, color: '#bc8cff' },
  ] : [
    { label: 'Active (1h)', value: '--', color: '#ff9f0a' },
    { label: 'Critical (1h)', value: '--', color: '#ff2d55' },
    { label: 'High (1h)', value: '--', color: '#ff9f0a' },
    { label: 'Auto-remediated', value: '--', color: '#58a6ff' },
    { label: 'False positives', value: '--', color: '#00ff9f' },
    { label: 'Total all time', value: '--', color: '#bc8cff' },
  ]

  return (
    <div style={{ padding: '16px', fontFamily: 'monospace', height: '100%', overflowY: 'auto' }}>
      <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '14px' }}>⌂ Command Center</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px', marginBottom: '16px' }}>
        {kpis.map(({ label, value, color }) => (
          <div key={label} style={{ background: '#161b22', border: '1px solid rgba(0,255,159,0.1)', borderRadius: '8px', padding: '14px' }}>
            <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px' }}>{label}</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color }}>{value}</div>
          </div>
        ))}
      </div>
      <div style={{ background: '#161b22', border: '1px solid rgba(0,255,159,0.1)', borderRadius: '8px', padding: '14px' }}>
        <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>Security layers status</div>
        {[
          { name: 'Falco runtime detection', status: 'active', color: '#00ff9f' },
          { name: 'Kyverno admission control', status: 'active', color: '#00ff9f' },
          { name: 'Cilium eBPF networking', status: 'active', color: '#00ff9f' },
          { name: 'Prometheus + Grafana', status: 'active', color: '#00ff9f' },
          { name: 'Argus AI agent', status: 'active', color: '#00ff9f' },
          { name: 'Loki log aggregation', status: 'degraded', color: '#ff9f0a' },
        ].map(({ name, status, color }) => (
          <div key={name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid rgba(0,255,159,0.05)' }}>
            <span style={{ fontSize: '9px', color: '#8b949e' }}>{name}</span>
            <span style={{ fontSize: '8px', color, background: `${color}22`, padding: '1px 6px', borderRadius: '4px', border: `1px solid ${color}44` }}>{status}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
