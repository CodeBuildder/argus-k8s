import { useState, useEffect } from 'react'

const API = '/api'

interface ResourceQuota {
  namespace: string
  cpu_limit: string
  cpu_used: string
  memory_limit: string
  memory_used: string
  pods_limit: number | null
  pods_used: number
  compliance: number
  quota_source?: string
}

interface PDBStatus {
  name: string
  namespace: string
  min_available: number
  current_healthy: number
  total_pods: number
  status: 'healthy' | 'warning' | 'critical'
}

interface AuditLogEntry {
  timestamp: string
  user: string
  verb: string
  resource: string
  namespace: string
  status: number
  source_ip: string
}

interface InfraData {
  source: string
  audit_source?: string
  generated_at: string
  quotas: ResourceQuota[]
  pdbs: PDBStatus[]
  audit_logs: AuditLogEntry[]
}

export default function InfraObservability() {
  const [activeTab, setActiveTab] = useState<'quotas' | 'pdb' | 'audit'>('quotas')
  const [data, setData] = useState<InfraData | null>(null)
  const [loading, setLoading] = useState(true)
  const [backendLive, setBackendLive] = useState(false)
  const [flashKey, setFlashKey] = useState(0)

  const fetchInfra = async () => {
    try {
      const res = await fetch(`${API}/infra-observability`)
      if (!res.ok) throw new Error(`infra status ${res.status}`)
      setData(await res.json())
      setBackendLive(true)
      setFlashKey(prev => prev + 1)
    } catch (error) {
      console.error('Failed to fetch infra observability:', error)
      setBackendLive(false)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchInfra()
    const interval = setInterval(fetchInfra, 5000)
    return () => clearInterval(interval)
  }, [])

  const quotas = data?.quotas || []
  const pdbs = data?.pdbs || []
  const auditLogs = data?.audit_logs || []
  const avgCompliance = quotas.length ? Math.round(quotas.reduce((a, q) => a + q.compliance, 0) / quotas.length) : 0
  const refreshStamp = data?.generated_at ? new Date(data.generated_at).toLocaleTimeString() : '--'

  return (
    <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <style>{`
        @keyframes pulse { 0%, 100% { opacity: 0.35; } 50% { opacity: 1; } }
        @keyframes slideIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes scanline { 0% { transform: translateX(-100%); opacity: 0; } 20% { opacity: 1; } 100% { transform: translateX(100%); opacity: 0; } }
        @keyframes softFlash { 0% { opacity: 0.65; } 100% { opacity: 0; } }
      `}</style>

      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>
          Infrastructure Observability
        </div>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '8px', color: backendLive ? '#00ff9f' : '#ff9f0a', background: backendLive ? 'rgba(0,255,159,0.06)' : 'rgba(255,159,10,0.08)', border: `1px solid ${backendLive ? 'rgba(0,255,159,0.2)' : 'rgba(255,159,10,0.25)'}`, borderRadius: '4px', padding: '3px 8px', fontFamily: 'JetBrains Mono, monospace' }}>
          <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: backendLive ? '#00ff9f' : '#ff9f0a', animation: backendLive ? 'pulse 1.4s infinite' : 'none' }} />
          {data?.source || 'backend pending'}
        </span>
        <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>updated {refreshStamp}</span>
        <button onClick={fetchInfra} disabled={loading} style={{ marginLeft: 'auto', padding: '6px 12px', background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.3)', borderRadius: '6px', color: '#00d4ff', fontSize: '9px', fontFamily: 'JetBrains Mono, monospace', cursor: loading ? 'not-allowed' : 'pointer' }}>
          {loading ? 'Loading...' : 'Refresh backend'}
        </button>
      </div>

      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid rgba(0,255,159,0.12)', paddingBottom: '8px' }}>
        {[
          { id: 'quotas', label: 'Resource Quotas', icon: 'CPU' },
          { id: 'pdb', label: 'PDB Coverage', icon: 'HA' },
          { id: 'audit', label: 'Audit Logs', icon: 'AUD' },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            style={{
              padding: '8px 16px',
              background: activeTab === tab.id ? 'rgba(0,255,159,0.1)' : 'transparent',
              border: activeTab === tab.id ? '1px solid rgba(0,255,159,0.3)' : '1px solid rgba(255,255,255,0.05)',
              borderRadius: '6px',
              color: activeTab === tab.id ? '#00ff9f' : '#8892a4',
              fontSize: '10px',
              fontFamily: 'JetBrains Mono, monospace',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {activeTab === 'quotas' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
            <Metric label="Namespaces" value={quotas.length} color="#00d4ff" activity={quotas.map(q => q.pods_used)} />
            <Metric label="Avg Compliance" value={`${avgCompliance}%`} color="#00ff9f" activity={quotas.map(q => q.compliance)} />
            <Metric label="Over Quota" value={quotas.filter(q => q.compliance < 80).length} color="#ff9f0a" activity={quotas.map(q => 100 - q.compliance)} />
            <Metric label="Total Pods" value={quotas.reduce((a, q) => a + q.pods_used, 0)} color="#bc8cff" activity={quotas.map(q => q.pods_used)} />
          </div>

          {quotas.length === 0 ? <Empty label="quota data" /> : quotas.map(quota => (
            <div key={quota.namespace} style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px', position: 'relative', overflow: 'hidden' }}>
              <div key={flashKey} style={{ position: 'absolute', inset: 0, background: 'linear-gradient(90deg, transparent, rgba(0,212,255,0.08), transparent)', animation: 'softFlash 0.9s ease-out', pointerEvents: 'none' }} />
              <div style={{ position: 'absolute', left: 0, right: 0, top: 0, height: '1px', background: 'linear-gradient(90deg, transparent, rgba(0,255,159,0.45), transparent)', animation: 'scanline 2.8s linear infinite' }} />
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                <span style={{ fontSize: '12px', color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>{quota.namespace}</span>
                <span style={{ fontSize: '8px', color: quota.compliance >= 90 ? '#00ff9f' : quota.compliance >= 80 ? '#ff9f0a' : '#ff2d55', background: 'rgba(255,255,255,0.04)', padding: '3px 8px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>
                  {quota.compliance}% COMPLIANT
                </span>
                <span style={{ marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>
                  <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: backendLive ? '#00ff9f' : '#ff9f0a', animation: backendLive ? 'pulse 1.4s infinite' : 'none' }} />
                  {quota.quota_source || 'live'} · /api/infra-observability
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '10px' }}>
                <Usage label="CPU" used={quota.cpu_used} limit={quota.cpu_limit} unit="cores" color="#00ff9f" />
                <Usage label="MEMORY" used={quota.memory_used} limit={quota.memory_limit} color="#58a6ff" />
                <Usage label="PODS" used={quota.pods_used} limit={quota.pods_limit} color="#bc8cff" />
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#5a6478', fontSize: '8px', fontFamily: 'JetBrains Mono, monospace' }}>
                <span>backend snapshot</span>
                <span style={{ color: '#00d4ff' }}>{refreshStamp}</span>
                <span style={{ color: '#3d4a5f' }}>•</span>
                <span>{quota.pods_used} active pods observed</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'pdb' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
            <Metric label="Total PDBs" value={pdbs.length} color="#00d4ff" />
            <Metric label="Healthy" value={pdbs.filter(p => p.status === 'healthy').length} color="#00ff9f" />
            <Metric label="Warning" value={pdbs.filter(p => p.status === 'warning').length} color="#ff9f0a" />
            <Metric label="Critical" value={pdbs.filter(p => p.status === 'critical').length} color="#ff2d55" />
          </div>

          <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px', position: 'relative', overflow: 'hidden' }}>
            <div key={flashKey} style={{ position: 'absolute', inset: 0, background: 'linear-gradient(90deg, transparent, rgba(0,255,159,0.06), transparent)', animation: 'softFlash 0.9s ease-out', pointerEvents: 'none' }} />
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              Pod Disruption Budget Coverage
              <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00ff9f', animation: 'pulse 1.5s infinite', boxShadow: '0 0 5px #00ff9f' }} />
              <span style={{ fontSize: '8px', color: '#4a5568', marginLeft: 'auto' }}>live /api/infra-observability</span>
            </div>
            {pdbs.length === 0 ? <Empty label="PDB data" /> : pdbs.map(pdb => {
              const statusColor = pdb.status === 'healthy' ? '#00ff9f' : pdb.status === 'warning' ? '#ff9f0a' : '#ff2d55'
              const healthPct = (pdb.current_healthy / pdb.total_pods) * 100
              return (
                <div key={`${pdb.namespace}-${pdb.name}`} style={{ padding: '14px', background: 'rgba(0,0,0,0.2)', border: `1px solid ${statusColor}20`, borderRadius: '8px', marginBottom: '10px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <div>
                      <div style={{ fontSize: '11px', color: '#e6edf3', fontWeight: 600, marginBottom: '2px' }}>{pdb.name}</div>
                      <div style={{ fontSize: '8px', color: '#8892a4' }}>Namespace: <span style={{ color: '#58a6ff' }}>{pdb.namespace}</span></div>
                    </div>
                    <span style={{ fontSize: '8px', color: statusColor, background: `${statusColor}15`, padding: '4px 8px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>{pdb.status.toUpperCase()}</span>
                  </div>
                  <div style={{ display: 'flex', gap: '16px', fontSize: '9px', color: '#8892a4', marginBottom: '8px' }}>
                    <span>Min Available: <span style={{ color: '#e6edf3', fontWeight: 700 }}>{pdb.min_available}</span></span>
                    <span>Current Healthy: <span style={{ color: statusColor, fontWeight: 700 }}>{pdb.current_healthy}</span></span>
                    <span>Total Pods: <span style={{ color: '#e6edf3', fontWeight: 700 }}>{pdb.total_pods}</span></span>
                  </div>
                  <div style={{ height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${healthPct}%`, background: statusColor, borderRadius: '3px', transition: 'width 1s ease-out' }} />
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '8px', fontSize: '8px', color: '#5a6478', fontFamily: 'JetBrains Mono, monospace' }}>
                    <span>coverage ratio</span>
                    <span>{pdb.current_healthy}/{pdb.total_pods} healthy</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {activeTab === 'audit' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', flex: 1 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
            <Metric label="Total Events" value={auditLogs.length} color="#00d4ff" activity={auditLogs.map((_, i) => auditLogs.length - i).slice(0, 12)} />
            <Metric label="Success" value={auditLogs.filter(l => l.status === 200).length} color="#00ff9f" activity={auditLogs.slice(0, 12).map(l => l.status === 200 ? 1 : 0)} />
            <Metric label="Denied" value={auditLogs.filter(l => l.status === 403).length} color="#ff2d55" activity={auditLogs.slice(0, 12).map(l => l.status === 403 ? 1 : 0)} />
            <Metric
              label="Rate"
              value={`${(auditLogs.length / 60).toFixed(1)}/s`}
              color="#bc8cff"
              activity={auditLogs.slice(0, 12).map(() => auditLogs.length / 60)}
            />
          </div>

          <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px', flex: 1, display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              Kubernetes API Activity Stream
              <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00ff9f', animation: 'pulse 1.5s infinite', boxShadow: '0 0 5px #00ff9f' }} />
              <span style={{ fontSize: '8px', color: '#4a5568', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>{data?.audit_source || 'backend stream'}</span>
            </div>

            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {auditLogs.length === 0 ? <Empty label="audit events" /> : auditLogs.map((log, idx) => (
                <div key={`${log.timestamp}-${idx}`} style={{ padding: '8px', background: idx === 0 ? 'rgba(0,255,159,0.05)' : 'rgba(0,0,0,0.2)', border: `1px solid ${log.status === 403 ? 'rgba(255,45,85,0.2)' : 'rgba(255,255,255,0.05)'}`, borderRadius: '6px', fontSize: '9px', fontFamily: 'JetBrains Mono, monospace', animation: idx === 0 ? 'slideIn 0.3s ease-out' : 'none' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{ color: '#8892a4' }}>{new Date(log.timestamp).toLocaleTimeString()}</span>
                    <span style={{ color: log.status === 200 ? '#00ff9f' : log.status === 403 ? '#ff2d55' : '#ff9f0a', fontWeight: 700 }}>{log.status}</span>
                  </div>
                  <div style={{ color: '#e6edf3', marginBottom: '2px' }}>
                    <span style={{ color: '#58a6ff' }}>{log.user}</span> {log.verb} <span style={{ color: '#bc8cff' }}>{log.resource}</span>
                  </div>
                  <div style={{ fontSize: '8px', color: '#4a5568' }}>Namespace: {log.namespace} - IP: {log.source_ip}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Metric({ label, value, color, activity = [] }: { label: string; value: string | number; color: string; activity?: number[] }) {
  const points = activity.slice(-16)
  const max = Math.max(...points, 1)
  const hasActivity = points.some(point => point > 0)
  return (
    <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '8px', padding: '12px', minHeight: '96px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
      <div style={{ fontSize: '8px', color: '#4a5568', marginBottom: '4px' }}>{label}</div>
      <div style={{ fontSize: '24px', fontWeight: 700, color }}>{value}</div>
      <div style={{ display: 'flex', alignItems: 'end', gap: '3px', height: '28px', marginTop: '10px' }}>
        {(points.length ? points : [0, 0, 0, 0, 0, 0]).map((point, idx) => (
          <div
            key={idx}
            style={{
              flex: 1,
              minWidth: '4px',
              height: point <= 0 ? '0%' : `${Math.max(4, (point / max) * 100)}%`,
              borderRadius: '999px',
              background: `linear-gradient(180deg, ${color}, rgba(255,255,255,0.12))`,
              opacity: hasActivity ? (idx === points.length - 1 ? 1 : 0.45) : 0.18,
              transition: 'height 400ms ease, opacity 400ms ease',
            }}
          />
        ))}
      </div>
    </div>
  )
}

function Usage({ label, used, limit, unit, color }: { label: string; used: string | number; limit: string | number | null; unit?: string; color: string }) {
  const parse = (v: string | number | null) => Number(String(v ?? '').replace(/[^\d.]/g, '')) || 0
  const pct = Math.min(100, parse(limit) ? (parse(used) / parse(limit)) * 100 : 0)
  const displayLimit = limit ?? 'unbounded'
  return (
    <div>
      <div style={{ fontSize: '9px', color: '#4a5568', marginBottom: '6px' }}>{label}</div>
      <div style={{ fontSize: '11px', color: '#e6edf3', marginBottom: '4px', fontFamily: 'JetBrains Mono, monospace' }}>
        {used} / {displayLimit}{unit && displayLimit !== 'unbounded' ? ` ${unit}` : ''}
      </div>
      <div style={{ height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: pct > 80 ? '#ff9f0a' : color, borderRadius: '3px', transition: 'width 1s ease-out' }} />
      </div>
    </div>
  )
}

function Empty({ label }: { label: string }) {
  return (
    <div style={{ padding: '26px', textAlign: 'center', color: '#4a5568', fontSize: '10px', border: '1px dashed rgba(0,255,159,0.12)', borderRadius: '8px', background: 'rgba(0,0,0,0.18)' }}>
      No backend {label} yet. Trigger backend simulation or wait for live incidents.
    </div>
  )
}
