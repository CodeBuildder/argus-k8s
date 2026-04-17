import { useState, useEffect } from 'react'

const API = '/api'

interface ResourceQuota {
  namespace: string
  cpu_limit: string
  cpu_used: string
  memory_limit: string
  memory_used: string
  pods_limit: number
  pods_used: number
  compliance: number
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

export default function InfraObservability() {
  const [activeTab, setActiveTab] = useState<'quotas' | 'pdb' | 'audit'>('quotas')
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([])

  useEffect(() => {
    // Simulate audit log streaming
    const interval = setInterval(() => {
      const newLog: AuditLogEntry = {
        timestamp: new Date().toISOString(),
        user: ['system:serviceaccount:kube-system:default', 'admin', 'developer'][Math.floor(Math.random() * 3)],
        verb: ['get', 'list', 'create', 'update', 'delete'][Math.floor(Math.random() * 5)],
        resource: ['pods', 'secrets', 'configmaps', 'deployments', 'services'][Math.floor(Math.random() * 5)],
        namespace: ['default', 'kube-system', 'production'][Math.floor(Math.random() * 3)],
        status: Math.random() > 0.9 ? 403 : 200,
        source_ip: `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
      }
      setAuditLogs(prev => [newLog, ...prev.slice(0, 49)])
    }, 2000)

    return () => clearInterval(interval)
  }, [])

  const quotas: ResourceQuota[] = [
    { namespace: 'production', cpu_limit: '8', cpu_used: '6.2', memory_limit: '16Gi', memory_used: '12.4Gi', pods_limit: 50, pods_used: 38, compliance: 78 },
    { namespace: 'staging', cpu_limit: '4', cpu_used: '2.1', memory_limit: '8Gi', memory_used: '4.2Gi', pods_limit: 30, pods_used: 15, compliance: 95 },
    { namespace: 'development', cpu_limit: '2', cpu_used: '1.8', memory_limit: '4Gi', memory_used: '3.6Gi', pods_limit: 20, pods_used: 18, compliance: 85 },
    { namespace: 'monitoring', cpu_limit: '4', cpu_used: '3.2', memory_limit: '8Gi', memory_used: '6.1Gi', pods_limit: 25, pods_used: 12, compliance: 82 }
  ]

  const pdbs: PDBStatus[] = [
    { name: 'api-server-pdb', namespace: 'production', min_available: 2, current_healthy: 3, total_pods: 3, status: 'healthy' },
    { name: 'database-pdb', namespace: 'production', min_available: 2, current_healthy: 2, total_pods: 3, status: 'warning' },
    { name: 'cache-pdb', namespace: 'production', min_available: 1, current_healthy: 2, total_pods: 2, status: 'healthy' },
    { name: 'worker-pdb', namespace: 'production', min_available: 3, current_healthy: 2, total_pods: 5, status: 'critical' },
    { name: 'frontend-pdb', namespace: 'staging', min_available: 1, current_healthy: 2, total_pods: 2, status: 'healthy' }
  ]

  return (
    <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>
        📊 Infrastructure Observability
      </div>

      {/* Tab Navigation */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid rgba(0,255,159,0.12)', paddingBottom: '8px' }}>
        {[
          { id: 'quotas', label: 'Resource Quotas', icon: '📦' },
          { id: 'pdb', label: 'PDB Coverage', icon: '🛡️' },
          { id: 'audit', label: 'Audit Logs', icon: '📋' }
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
              transition: 'all 0.2s',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Resource Quotas Tab */}
      {activeTab === 'quotas' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
            {[
              { label: 'Namespaces', value: quotas.length, color: '#00d4ff' },
              { label: 'Avg Compliance', value: `${Math.round(quotas.reduce((a, q) => a + q.compliance, 0) / quotas.length)}%`, color: '#00ff9f' },
              { label: 'Over Quota', value: quotas.filter(q => q.compliance < 80).length, color: '#ff9f0a' },
              { label: 'Total Pods', value: quotas.reduce((a, q) => a + q.pods_used, 0), color: '#bc8cff' }
            ].map(stat => (
              <div key={stat.label} style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '8px', padding: '12px' }}>
                <div style={{ fontSize: '8px', color: '#4a5568', marginBottom: '4px' }}>{stat.label}</div>
                <div style={{ fontSize: '24px', fontWeight: 700, color: stat.color }}>{stat.value}</div>
              </div>
            ))}
          </div>

          {quotas.map(quota => (
            <div key={quota.namespace} style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '12px', color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>
                    {quota.namespace}
                  </span>
                  <span style={{
                    fontSize: '8px',
                    color: quota.compliance >= 90 ? '#00ff9f' : quota.compliance >= 80 ? '#ff9f0a' : '#ff2d55',
                    background: quota.compliance >= 90 ? 'rgba(0,255,159,0.1)' : quota.compliance >= 80 ? 'rgba(255,159,10,0.1)' : 'rgba(255,45,85,0.1)',
                    padding: '3px 8px',
                    borderRadius: '4px',
                    fontFamily: 'JetBrains Mono, monospace',
                    fontWeight: 700
                  }}>
                    {quota.compliance}% COMPLIANT
                  </span>
                </div>
                <button style={{
                  padding: '6px 12px',
                  background: 'rgba(0,212,255,0.1)',
                  border: '1px solid rgba(0,212,255,0.3)',
                  borderRadius: '6px',
                  color: '#00d4ff',
                  fontSize: '9px',
                  fontFamily: 'JetBrains Mono, monospace',
                  cursor: 'pointer'
                }}>
                  ENFORCE
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
                {/* CPU */}
                <div>
                  <div style={{ fontSize: '9px', color: '#4a5568', marginBottom: '6px' }}>CPU</div>
                  <div style={{ fontSize: '11px', color: '#e6edf3', marginBottom: '4px', fontFamily: 'JetBrains Mono, monospace' }}>
                    {quota.cpu_used} / {quota.cpu_limit} cores
                  </div>
                  <div style={{ height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{
                      height: '100%',
                      width: `${(parseFloat(quota.cpu_used) / parseFloat(quota.cpu_limit)) * 100}%`,
                      background: parseFloat(quota.cpu_used) / parseFloat(quota.cpu_limit) > 0.8 ? '#ff9f0a' : '#00ff9f',
                      borderRadius: '3px',
                      transition: 'width 1s ease-out'
                    }} />
                  </div>
                </div>

                {/* Memory */}
                <div>
                  <div style={{ fontSize: '9px', color: '#4a5568', marginBottom: '6px' }}>MEMORY</div>
                  <div style={{ fontSize: '11px', color: '#e6edf3', marginBottom: '4px', fontFamily: 'JetBrains Mono, monospace' }}>
                    {quota.memory_used} / {quota.memory_limit}
                  </div>
                  <div style={{ height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{
                      height: '100%',
                      width: `${(parseFloat(quota.memory_used) / parseFloat(quota.memory_limit)) * 100}%`,
                      background: parseFloat(quota.memory_used) / parseFloat(quota.memory_limit) > 0.8 ? '#ff9f0a' : '#58a6ff',
                      borderRadius: '3px',
                      transition: 'width 1s ease-out'
                    }} />
                  </div>
                </div>

                {/* Pods */}
                <div>
                  <div style={{ fontSize: '9px', color: '#4a5568', marginBottom: '6px' }}>PODS</div>
                  <div style={{ fontSize: '11px', color: '#e6edf3', marginBottom: '4px', fontFamily: 'JetBrains Mono, monospace' }}>
                    {quota.pods_used} / {quota.pods_limit}
                  </div>
                  <div style={{ height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{
                      height: '100%',
                      width: `${(quota.pods_used / quota.pods_limit) * 100}%`,
                      background: quota.pods_used / quota.pods_limit > 0.8 ? '#ff9f0a' : '#bc8cff',
                      borderRadius: '3px',
                      transition: 'width 1s ease-out'
                    }} />
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* PDB Coverage Tab */}
      {activeTab === 'pdb' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
            {[
              { label: 'Total PDBs', value: pdbs.length, color: '#00d4ff' },
              { label: 'Healthy', value: pdbs.filter(p => p.status === 'healthy').length, color: '#00ff9f' },
              { label: 'Warning', value: pdbs.filter(p => p.status === 'warning').length, color: '#ff9f0a' },
              { label: 'Critical', value: pdbs.filter(p => p.status === 'critical').length, color: '#ff2d55' }
            ].map(stat => (
              <div key={stat.label} style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '8px', padding: '12px' }}>
                <div style={{ fontSize: '8px', color: '#4a5568', marginBottom: '4px' }}>{stat.label}</div>
                <div style={{ fontSize: '24px', fontWeight: 700, color: stat.color }}>{stat.value}</div>
              </div>
            ))}
          </div>

          <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px' }}>
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px' }}>
              Pod Disruption Budgets
            </div>

            {pdbs.map(pdb => {
              const statusColor = pdb.status === 'healthy' ? '#00ff9f' : pdb.status === 'warning' ? '#ff9f0a' : '#ff2d55'
              const healthPct = (pdb.current_healthy / pdb.total_pods) * 100

              return (
                <div key={`${pdb.namespace}-${pdb.name}`} style={{
                  padding: '12px',
                  background: 'rgba(0,0,0,0.2)',
                  border: `1px solid ${statusColor}20`,
                  borderRadius: '8px',
                  marginBottom: '8px'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <div>
                      <div style={{ fontSize: '11px', color: '#e6edf3', fontWeight: 600, marginBottom: '2px' }}>
                        {pdb.name}
                      </div>
                      <div style={{ fontSize: '8px', color: '#8892a4' }}>
                        Namespace: <span style={{ color: '#58a6ff' }}>{pdb.namespace}</span>
                      </div>
                    </div>
                    <span style={{
                      fontSize: '8px',
                      color: statusColor,
                      background: `${statusColor}15`,
                      padding: '4px 8px',
                      borderRadius: '4px',
                      fontFamily: 'JetBrains Mono, monospace',
                      fontWeight: 700
                    }}>
                      {pdb.status.toUpperCase()}
                    </span>
                  </div>

                  <div style={{ display: 'flex', gap: '16px', fontSize: '9px', color: '#8892a4', marginBottom: '8px' }}>
                    <span>Min Available: <span style={{ color: '#e6edf3', fontWeight: 700 }}>{pdb.min_available}</span></span>
                    <span>Current Healthy: <span style={{ color: statusColor, fontWeight: 700 }}>{pdb.current_healthy}</span></span>
                    <span>Total Pods: <span style={{ color: '#e6edf3', fontWeight: 700 }}>{pdb.total_pods}</span></span>
                  </div>

                  <div style={{ height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{
                      height: '100%',
                      width: `${healthPct}%`,
                      background: statusColor,
                      borderRadius: '3px',
                      transition: 'width 1s ease-out'
                    }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Audit Logs Tab */}
      {activeTab === 'audit' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', flex: 1 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
            {[
              { label: 'Total Events', value: auditLogs.length, color: '#00d4ff' },
              { label: 'Success', value: auditLogs.filter(l => l.status === 200).length, color: '#00ff9f' },
              { label: 'Denied', value: auditLogs.filter(l => l.status === 403).length, color: '#ff2d55' },
              { label: 'Rate', value: `${(auditLogs.length / 60).toFixed(1)}/s`, color: '#bc8cff' }
            ].map(stat => (
              <div key={stat.label} style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '8px', padding: '12px' }}>
                <div style={{ fontSize: '8px', color: '#4a5568', marginBottom: '4px' }}>{stat.label}</div>
                <div style={{ fontSize: '24px', fontWeight: 700, color: stat.color }}>{stat.value}</div>
              </div>
            ))}
          </div>

          <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px', flex: 1, display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              Kubernetes API Audit Stream
              <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00ff9f', animation: 'pulse 1.5s infinite', boxShadow: '0 0 5px #00ff9f' }} />
            </div>

            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {auditLogs.map((log, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: '8px',
                    background: idx === 0 ? 'rgba(0,255,159,0.05)' : 'rgba(0,0,0,0.2)',
                    border: `1px solid ${log.status === 403 ? 'rgba(255,45,85,0.2)' : 'rgba(255,255,255,0.05)'}`,
                    borderRadius: '6px',
                    fontSize: '9px',
                    fontFamily: 'JetBrains Mono, monospace',
                    animation: idx === 0 ? 'slideIn 0.3s ease-out' : 'none'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{ color: '#8892a4' }}>{new Date(log.timestamp).toLocaleTimeString()}</span>
                    <span style={{
                      color: log.status === 200 ? '#00ff9f' : '#ff2d55',
                      fontWeight: 700
                    }}>
                      {log.status}
                    </span>
                  </div>
                  <div style={{ color: '#e6edf3', marginBottom: '2px' }}>
                    <span style={{ color: '#58a6ff' }}>{log.user}</span> {log.verb} <span style={{ color: '#bc8cff' }}>{log.resource}</span>
                  </div>
                  <div style={{ fontSize: '8px', color: '#4a5568' }}>
                    Namespace: {log.namespace} • IP: {log.source_ip}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes pulse { 0%, 100% { opacity: 0.3; } 50% { opacity: 1; } }
        @keyframes slideIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
      `}</style>
    </div>
  )
}

// Made with Bob
