import { useState, useEffect, useRef } from 'react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Flow {
  id: string; srcPod: string; srcNs: string; dstPod: string; dstNs: string
  verdict: 'forwarded' | 'dropped' | 'suspicious'; port: number; protocol: string; bytesPerSec: number
}

interface AuditEntry {
  id: string; ts: string; user: string; verb: string
  resource: string; name: string; namespace: string; status: number; suspicious: boolean
}

interface QuotaRow {
  namespace: string; cpuReq: string; cpuLimit: string
  memReq: string; memLimit: string; pods: string; pct: number
}

interface PdbRow {
  name: string; namespace: string; hasPdb: boolean
  minAvailable: number | null; replicas: number; risk: 'low' | 'medium' | 'high'
}

// ─── Mock data ────────────────────────────────────────────────────────────────

const MOCK_FLOWS: Flow[] = [
  { id: 'f1', srcPod: 'prometheus-0', srcNs: 'monitoring', dstPod: 'nginx-prod', dstNs: 'prod', verdict: 'forwarded', port: 9090, protocol: 'TCP', bytesPerSec: 1420 },
  { id: 'f2', srcPod: 'argus-agent', srcNs: 'argus-system', dstPod: 'api-server', dstNs: 'prod', verdict: 'forwarded', port: 8080, protocol: 'TCP', bytesPerSec: 340 },
  { id: 'f3', srcPod: 'redis-master', srcNs: 'prod', dstPod: 'external', dstNs: '', verdict: 'dropped', port: 6379, protocol: 'TCP', bytesPerSec: 0 },
  { id: 'f4', srcPod: 'api-server', srcNs: 'prod', dstPod: 'redis-master', dstNs: 'prod', verdict: 'forwarded', port: 6379, protocol: 'TCP', bytesPerSec: 8800 },
  { id: 'f5', srcPod: 'nginx-prod', srcNs: 'prod', dstPod: 'metadata-svc', dstNs: 'kube-system', verdict: 'suspicious', port: 80, protocol: 'HTTP', bytesPerSec: 220 },
  { id: 'f6', srcPod: 'loki-0', srcNs: 'monitoring', dstPod: 'promtail', dstNs: 'monitoring', verdict: 'forwarded', port: 3100, protocol: 'TCP', bytesPerSec: 5600 },
  { id: 'f7', srcPod: 'grafana', srcNs: 'monitoring', dstPod: 'loki-0', dstNs: 'monitoring', verdict: 'forwarded', port: 3100, protocol: 'TCP', bytesPerSec: 920 },
  { id: 'f8', srcPod: 'app-staging', srcNs: 'staging', dstPod: 'api-server', dstNs: 'prod', verdict: 'dropped', port: 8080, protocol: 'TCP', bytesPerSec: 0 },
]

const MOCK_AUDIT: AuditEntry[] = [
  { id: 'a1', ts: '14:31:07', user: 'kaushik', verb: 'exec', resource: 'pods', name: 'nginx-prod-abc', namespace: 'prod', status: 200, suspicious: true },
  { id: 'a2', ts: '14:28:42', user: 'system:node', verb: 'update', resource: 'nodes/status', name: 'k3s-worker1', namespace: '', status: 200, suspicious: false },
  { id: 'a3', ts: '14:22:15', user: 'kaushik', verb: 'delete', resource: 'deployments', name: 'app-v2', namespace: 'staging', status: 403, suspicious: true },
  { id: 'a4', ts: '14:19:03', user: 'system:serviceaccount:argus-system:argus', verb: 'get', resource: 'pods', name: '', namespace: 'prod', status: 200, suspicious: false },
  { id: 'a5', ts: '14:15:50', user: 'kaushik', verb: 'get', resource: 'secrets', name: 'db-password', namespace: 'prod', status: 200, suspicious: true },
  { id: 'a6', ts: '14:10:22', user: 'system:kube-controller-manager', verb: 'update', resource: 'deployments/status', name: 'nginx-prod', namespace: 'prod', status: 200, suspicious: false },
  { id: 'a7', ts: '14:07:11', user: 'kaushik', verb: 'create', resource: 'pods/exec', name: 'redis-master-0', namespace: 'prod', status: 201, suspicious: true },
  { id: 'a8', ts: '14:02:34', user: 'system:node', verb: 'patch', resource: 'nodes', name: 'k3s-worker2', namespace: '', status: 200, suspicious: false },
]

const MOCK_QUOTAS: QuotaRow[] = [
  { namespace: 'prod', cpuReq: '450m / 1000m', cpuLimit: '900m / 2000m', memReq: '512Mi / 2Gi', memLimit: '1Gi / 4Gi', pods: '8 / 20', pct: 45 },
  { namespace: 'staging', cpuReq: '200m / 500m', cpuLimit: '400m / 1000m', memReq: '256Mi / 1Gi', memLimit: '512Mi / 2Gi', pods: '5 / 10', pct: 40 },
  { namespace: 'monitoring', cpuReq: '820m / 1000m', cpuLimit: '1600m / 2000m', memReq: '1.8Gi / 2Gi', memLimit: '3.6Gi / 4Gi', pods: '9 / 10', pct: 88 },
  { namespace: 'argus-system', cpuReq: '120m / 500m', cpuLimit: '250m / 1000m', memReq: '128Mi / 512Mi', memLimit: '256Mi / 1Gi', pods: '2 / 5', pct: 24 },
]

const MOCK_PDBS: PdbRow[] = [
  { name: 'nginx-deployment', namespace: 'prod', hasPdb: true, minAvailable: 1, replicas: 3, risk: 'low' },
  { name: 'api-server', namespace: 'prod', hasPdb: false, minAvailable: null, replicas: 2, risk: 'high' },
  { name: 'redis-master', namespace: 'prod', hasPdb: true, minAvailable: 1, replicas: 2, risk: 'low' },
  { name: 'grafana', namespace: 'monitoring', hasPdb: false, minAvailable: null, replicas: 1, risk: 'medium' },
  { name: 'prometheus', namespace: 'monitoring', hasPdb: true, minAvailable: 1, replicas: 2, risk: 'low' },
  { name: 'app-staging', namespace: 'staging', hasPdb: false, minAvailable: null, replicas: 3, risk: 'high' },
  { name: 'loki', namespace: 'monitoring', hasPdb: false, minAvailable: null, replicas: 1, risk: 'medium' },
]

// ─── Topology Node positions ──────────────────────────────────────────────────

interface TopoNode {
  id: string; label: string; sublabel: string
  x: number; y: number; r: number; color: string; pods: string[]
}

const TOPO_NODES: TopoNode[] = [
  { id: 'master', label: 'k3s-master', sublabel: 'control plane · 192.168.139.42', x: 460, y: 100, r: 44, color: '#00d4ff', pods: ['kube-apiserver', 'coredns', 'kube-scheduler'] },
  { id: 'worker1', label: 'k3s-worker1', sublabel: 'worker · 192.168.139.77', x: 200, y: 300, r: 44, color: '#00ff9f', pods: ['nginx-prod', 'api-server', 'redis-master', 'argus-agent'] },
  { id: 'worker2', label: 'k3s-worker2', sublabel: 'worker · 192.168.139.45', x: 720, y: 300, r: 44, color: '#00ff9f', pods: ['prometheus-0', 'grafana', 'loki-0', 'promtail'] },
]

interface TopoEdge {
  x1: number; y1: number; x2: number; y2: number
  color: string; label: string; dashed: boolean
}

const TOPO_EDGES: TopoEdge[] = [
  { x1: 460, y1: 100, x2: 200, y2: 300, color: '#00ff9f', label: 'kubelet', dashed: false },
  { x1: 460, y1: 100, x2: 720, y2: 300, color: '#00ff9f', label: 'kubelet', dashed: false },
  { x1: 200, y1: 300, x2: 720, y2: 300, color: '#58a6ff', label: 'metrics scrape', dashed: false },
  { x1: 200, y1: 300, x2: 460, y2: 400, color: '#ff2d55', label: 'dropped egress', dashed: true },
]

const EXT = { x: 460, y: 400 }

interface Particle { id: number; edgeIdx: number; t: number }

function TopologyMap() {
  const [selectedNode, setSelectedNode] = useState<TopoNode | null>(null)
  const [particles, setParticles] = useState<Particle[]>([])
  const animRef = useRef<number>()
  const pidRef = useRef(0)
  const tickRef = useRef(0)

  useEffect(() => {
    const loop = () => {
      tickRef.current++
      setParticles(prev => {
        let next = prev.map(p => ({ ...p, t: p.t + 0.009 })).filter(p => p.t < 1)
        if (tickRef.current % 35 === 0) {
          next = [...next, { id: pidRef.current++, edgeIdx: Math.floor(Math.random() * TOPO_EDGES.length), t: 0 }]
        }
        return next.slice(-24)
      })
      animRef.current = requestAnimationFrame(loop)
    }
    animRef.current = requestAnimationFrame(loop)
    return () => { if (animRef.current) cancelAnimationFrame(animRef.current) }
  }, [])

  return (
    <div style={{ position: 'relative' }}>
      <svg width="100%" viewBox="0 0 920 430" style={{ display: 'block' }}>
        <defs>
          <filter id="topoGlow" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <radialGradient id="bgGrad" cx="50%" cy="40%" r="50%">
            <stop offset="0%" stopColor="rgba(0,212,255,0.04)" />
            <stop offset="100%" stopColor="rgba(0,0,0,0)" />
          </radialGradient>
        </defs>

        <rect x="0" y="0" width="920" height="430" fill="url(#bgGrad)" />

        {/* Edges */}
        {TOPO_EDGES.map((e, i) => (
          <g key={i}>
            <line x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2}
              stroke={e.color} strokeWidth={1.5} strokeOpacity={0.3}
              strokeDasharray={e.dashed ? '6 4' : 'none'} />
            <text x={(e.x1 + e.x2) / 2 + 6} y={(e.y1 + e.y2) / 2 - 6}
              fill={e.color} fontSize="9" opacity={0.65}
              fontFamily="JetBrains Mono, monospace">{e.label}</text>
          </g>
        ))}

        {/* Particles */}
        {particles.map(p => {
          const e = TOPO_EDGES[p.edgeIdx]
          const x = e.x1 + (e.x2 - e.x1) * p.t
          const y = e.y1 + (e.y2 - e.y1) * p.t
          const op = p.t < 0.1 ? p.t * 10 : p.t > 0.9 ? (1 - p.t) * 10 : 1
          return <circle key={p.id} cx={x} cy={y} r={3.5} fill={e.color} opacity={op} filter="url(#topoGlow)" />
        })}

        {/* External node */}
        <circle cx={EXT.x} cy={EXT.y} r={22} fill="rgba(255,45,85,0.1)" stroke="#ff2d55" strokeWidth={1.5} strokeOpacity={0.45} strokeDasharray="4 3" />
        <text x={EXT.x} y={EXT.y} textAnchor="middle" dominantBaseline="middle" fill="#ff2d55" fontSize="9" fontFamily="JetBrains Mono, monospace" fontWeight="700">external</text>
        <text x={EXT.x} y={EXT.y + 14} textAnchor="middle" fill="#ff2d55" fontSize="7" fontFamily="JetBrains Mono, monospace" opacity={0.6}>blocked</text>

        {/* Nodes */}
        {TOPO_NODES.map(node => (
          <g key={node.id} style={{ cursor: 'pointer' }} onClick={() => setSelectedNode(selectedNode?.id === node.id ? null : node)}>
            <circle cx={node.x} cy={node.y} r={node.r + 12} fill="none" stroke={node.color} strokeWidth={0.8} strokeOpacity={selectedNode?.id === node.id ? 0.45 : 0.1} />
            <circle cx={node.x} cy={node.y} r={node.r} fill={`${node.color}12`} stroke={node.color} strokeWidth={2} filter="url(#topoGlow)" />
            <text x={node.x} y={node.y - 5} textAnchor="middle" fill={node.color} fontSize="12" fontFamily="JetBrains Mono, monospace" fontWeight="700">{node.label}</text>
            <text x={node.x} y={node.y + 10} textAnchor="middle" fill={node.color} fontSize="8" fontFamily="Inter, sans-serif" opacity={0.6}>{node.pods.length} pods</text>
          </g>
        ))}
      </svg>

      {/* Selected node callout */}
      {selectedNode && (
        <div style={{
          position: 'absolute', top: 8, right: 8,
          background: '#0d1421', border: `1px solid ${selectedNode.color}60`,
          borderRadius: '10px', padding: '12px 14px', width: '196px',
          boxShadow: `0 8px 28px rgba(0,0,0,0.65), 0 0 0 1px ${selectedNode.color}12`,
        }}>
          <div style={{ fontSize: '10px', fontWeight: 700, color: selectedNode.color, fontFamily: 'JetBrains Mono, monospace', marginBottom: '2px' }}>{selectedNode.label}</div>
          <div style={{ fontSize: '8px', color: '#5a6478', marginBottom: '10px' }}>{selectedNode.sublabel}</div>
          <div style={{ fontSize: '8px', color: '#5a6478', marginBottom: '5px', textTransform: 'uppercase', letterSpacing: '1px' }}>Pods running</div>
          {selectedNode.pods.map(pod => (
            <div key={pod} style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '3px' }}>
              <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00ff9f', boxShadow: '0 0 4px #00ff9f', flexShrink: 0 }} />
              <span style={{ fontSize: '9px', color: '#d1d5db', fontFamily: 'JetBrains Mono, monospace' }}>{pod}</span>
            </div>
          ))}
          <div onClick={() => setSelectedNode(null)} style={{ marginTop: '10px', fontSize: '8px', color: '#5a6478', cursor: 'pointer', textAlign: 'right' }}>dismiss ×</div>
        </div>
      )}

      {/* Legend */}
      <div style={{ display: 'flex', gap: '20px', justifyContent: 'center', marginTop: '4px' }}>
        {[{ color: '#00ff9f', label: 'forwarded' }, { color: '#58a6ff', label: 'restricted' }, { color: '#ff2d55', label: 'dropped / suspicious' }].map(({ color, label }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <div style={{ width: '18px', height: '2px', background: color, opacity: 0.65 }} />
            <span style={{ fontSize: '8px', color: '#5a6478' }}>{label}</span>
          </div>
        ))}
        <span style={{ fontSize: '8px', color: '#5a6478', marginLeft: '8px' }}>Click a node to inspect pods</span>
      </div>
    </div>
  )
}

// ─── Hubble Flow Table ────────────────────────────────────────────────────────

function FlowTable() {
  const [filter, setFilter] = useState<'all' | 'dropped' | 'suspicious'>('all')
  const rows = filter === 'all' ? MOCK_FLOWS : MOCK_FLOWS.filter(f => f.verdict === filter)
  const vc = (v: string) => v === 'forwarded' ? '#00ff9f' : v === 'suspicious' ? '#ff9f0a' : '#ff2d55'

  return (
    <div>
      <div style={{ display: 'flex', gap: '6px', marginBottom: '10px', alignItems: 'center' }}>
        {(['all', 'dropped', 'suspicious'] as const).map(f => (
          <button key={f} onClick={() => setFilter(f)} style={{
            fontSize: '8px', padding: '3px 10px', borderRadius: '4px', border: 'none', cursor: 'pointer',
            background: filter === f ? 'rgba(0,212,255,0.12)' : 'rgba(255,255,255,0.04)',
            color: filter === f ? '#00d4ff' : '#5a6478',
            fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase', letterSpacing: '1px',
          }}>{f}</button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: '8px', color: '#4a5568' }}>20.6 flows/s via Hubble relay</span>
      </div>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            {['Source', 'Destination', 'Port / Proto', 'Throughput', 'Verdict'].map(h => (
              <th key={h} style={{ textAlign: 'left', fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', padding: '4px 8px', fontWeight: 400 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((flow, i) => (
            <tr key={flow.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', background: i % 2 === 1 ? 'rgba(255,255,255,0.01)' : 'transparent' }}>
              <td style={{ padding: '5px 8px' }}>
                <div style={{ fontSize: '10px', color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>{flow.srcPod}</div>
                {flow.srcNs && <div style={{ fontSize: '8px', color: '#58a6ff' }}>{flow.srcNs}</div>}
              </td>
              <td style={{ padding: '5px 8px' }}>
                <div style={{ fontSize: '10px', color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>{flow.dstPod}</div>
                {flow.dstNs && <div style={{ fontSize: '8px', color: '#58a6ff' }}>{flow.dstNs}</div>}
              </td>
              <td style={{ padding: '5px 8px', fontSize: '9px', color: '#8892a4', fontFamily: 'JetBrains Mono, monospace' }}>{flow.port}/{flow.protocol}</td>
              <td style={{ padding: '5px 8px', fontSize: '9px', color: flow.bytesPerSec > 0 ? '#8892a4' : '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>
                {flow.bytesPerSec > 0 ? `${(flow.bytesPerSec / 1000).toFixed(1)} KB/s` : '—'}
              </td>
              <td style={{ padding: '5px 8px' }}>
                <span style={{ fontSize: '8px', fontWeight: 700, color: vc(flow.verdict), background: `${vc(flow.verdict)}15`, border: `1px solid ${vc(flow.verdict)}30`, padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{flow.verdict}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── Audit Log ────────────────────────────────────────────────────────────────

function AuditLog() {
  const [onlySuspicious, setOnlySuspicious] = useState(false)
  const rows = onlySuspicious ? MOCK_AUDIT.filter(e => e.suspicious) : MOCK_AUDIT
  const vc = (v: string) => v === 'delete' ? '#ff2d55' : (v === 'exec' || v === 'create') ? '#ff9f0a' : v === 'update' || v === 'patch' ? '#58a6ff' : '#8892a4'
  const sc = (s: number) => s >= 400 ? '#ff2d55' : '#00ff9f'

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
        <span style={{ fontSize: '8px', color: '#4a5568' }}>K8s API server audit log · all kubectl operations across the cluster</span>
        <div onClick={() => setOnlySuspicious(!onlySuspicious)} style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
          <div style={{ width: '28px', height: '14px', borderRadius: '7px', background: onlySuspicious ? '#ff9f0a' : 'rgba(255,255,255,0.1)', position: 'relative', transition: 'background 0.2s' }}>
            <div style={{ position: 'absolute', top: '2px', left: onlySuspicious ? '16px' : '2px', width: '10px', height: '10px', borderRadius: '50%', background: '#fff', transition: 'left 0.2s' }} />
          </div>
          <span style={{ fontSize: '8px', color: onlySuspicious ? '#ff9f0a' : '#5a6478', fontFamily: 'JetBrains Mono, monospace' }}>suspicious only</span>
        </div>
      </div>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            {['Time', 'User', 'Verb', 'Resource', 'Name / NS', 'Status'].map(h => (
              <th key={h} style={{ textAlign: 'left', fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', padding: '4px 8px', fontWeight: 400 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((e, i) => (
            <tr key={e.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', background: e.suspicious ? 'rgba(255,159,10,0.04)' : i % 2 === 1 ? 'rgba(255,255,255,0.01)' : 'transparent' }}>
              <td style={{ padding: '5px 8px', fontSize: '9px', color: '#5a6478', fontFamily: 'JetBrains Mono, monospace' }}>{e.ts}</td>
              <td style={{ padding: '5px 8px', fontSize: '9px', color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace', maxWidth: '130px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.user}</td>
              <td style={{ padding: '5px 8px' }}>
                <span style={{ fontSize: '9px', fontWeight: 700, color: vc(e.verb), background: `${vc(e.verb)}15`, padding: '1px 6px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace' }}>{e.verb}</span>
              </td>
              <td style={{ padding: '5px 8px', fontSize: '9px', color: '#8892a4', fontFamily: 'JetBrains Mono, monospace' }}>{e.resource}</td>
              <td style={{ padding: '5px 8px' }}>
                <div style={{ fontSize: '9px', color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>{e.name || '—'}</div>
                {e.namespace && <div style={{ fontSize: '8px', color: '#58a6ff' }}>{e.namespace}</div>}
              </td>
              <td style={{ padding: '5px 8px' }}>
                <span style={{ fontSize: '9px', fontWeight: 700, color: sc(e.status), fontFamily: 'JetBrains Mono, monospace' }}>{e.status}</span>
                {e.suspicious && <span style={{ marginLeft: '5px', fontSize: '9px', color: '#ff9f0a' }}>⚠</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── Resource Quotas ──────────────────────────────────────────────────────────

function ResourceQuotas() {
  return (
    <div>
      <div style={{ fontSize: '8px', color: '#4a5568', marginBottom: '10px' }}>Namespace resource usage vs configured limits · rows highlighted at &gt;80% pressure</div>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            {['Namespace', 'CPU Req', 'CPU Limit', 'Mem Req', 'Mem Limit', 'Pods', 'Pressure'].map(h => (
              <th key={h} style={{ textAlign: 'left', fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', padding: '4px 8px', fontWeight: 400 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {MOCK_QUOTAS.map((row) => {
            const alert = row.pct >= 80, warn = row.pct >= 60
            const bc = alert ? '#ff2d55' : warn ? '#ff9f0a' : '#00ff9f'
            return (
              <tr key={row.namespace} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', background: alert ? 'rgba(255,45,85,0.04)' : 'transparent' }}>
                <td style={{ padding: '7px 8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                    {alert && <span style={{ fontSize: '9px', color: '#ff2d55' }}>●</span>}
                    <span style={{ fontSize: '10px', color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>{row.namespace}</span>
                  </div>
                </td>
                {[row.cpuReq, row.cpuLimit, row.memReq, row.memLimit, row.pods].map((v, i) => (
                  <td key={i} style={{ padding: '7px 8px', fontSize: '9px', color: '#8892a4', fontFamily: 'JetBrains Mono, monospace' }}>{v}</td>
                ))}
                <td style={{ padding: '7px 8px', minWidth: '100px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <div style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${row.pct}%`, background: bc, borderRadius: '2px' }} />
                    </div>
                    <span style={{ fontSize: '8px', color: bc, fontFamily: 'JetBrains Mono, monospace', width: '28px' }}>{row.pct}%</span>
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ─── PDB Coverage ─────────────────────────────────────────────────────────────

function PdbCoverage() {
  const unprotected = MOCK_PDBS.filter(p => !p.hasPdb).length
  const rc = (r: string) => r === 'high' ? '#ff2d55' : r === 'medium' ? '#ff9f0a' : '#00ff9f'
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: '10px' }}>
        <span style={{ fontSize: '8px', color: '#4a5568' }}>Pod disruption budgets · services without a PDB can be fully evicted during node drain</span>
        {unprotected > 0 && (
          <span style={{ marginLeft: 'auto', fontSize: '9px', color: '#ff9f0a', background: 'rgba(255,159,10,0.1)', border: '1px solid rgba(255,159,10,0.25)', padding: '2px 8px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>
            {unprotected} unprotected
          </span>
        )}
      </div>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            {['Service', 'Namespace', 'PDB', 'Min Available', 'Replicas', 'Risk'].map(h => (
              <th key={h} style={{ textAlign: 'left', fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', padding: '4px 8px', fontWeight: 400 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {MOCK_PDBS.map((row) => (
            <tr key={row.name} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', background: !row.hasPdb && row.risk === 'high' ? 'rgba(255,45,85,0.03)' : 'transparent' }}>
              <td style={{ padding: '6px 8px', fontSize: '10px', color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>{row.name}</td>
              <td style={{ padding: '6px 8px', fontSize: '9px', color: '#58a6ff', fontFamily: 'JetBrains Mono, monospace' }}>{row.namespace}</td>
              <td style={{ padding: '6px 8px' }}>
                {row.hasPdb
                  ? <span style={{ fontSize: '9px', color: '#00ff9f', fontFamily: 'JetBrains Mono, monospace' }}>✓ protected</span>
                  : <span style={{ fontSize: '9px', color: '#ff2d55', fontFamily: 'JetBrains Mono, monospace' }}>✗ none</span>}
              </td>
              <td style={{ padding: '6px 8px', fontSize: '9px', color: '#8892a4', fontFamily: 'JetBrains Mono, monospace' }}>{row.minAvailable ?? '—'}</td>
              <td style={{ padding: '6px 8px', fontSize: '9px', color: '#8892a4', fontFamily: 'JetBrains Mono, monospace' }}>{row.replicas}</td>
              <td style={{ padding: '6px 8px' }}>
                <span style={{ fontSize: '8px', fontWeight: 700, color: rc(row.risk), background: `${rc(row.risk)}15`, border: `1px solid ${rc(row.risk)}30`, padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{row.risk}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

type Tab = 'topology' | 'flows' | 'audit' | 'quotas' | 'pdbs'

export default function ClusterMap() {
  const [tab, setTab] = useState<Tab>('topology')

  const tabs: { id: Tab; label: string; badge?: string }[] = [
    { id: 'topology', label: 'Network Topology' },
    { id: 'flows', label: 'Hubble Flows' },
    { id: 'audit', label: 'Audit Log', badge: '4' },
    { id: 'quotas', label: 'Resource Quotas', badge: '!' },
    { id: 'pdbs', label: 'PDB Coverage', badge: '4' },
  ]

  return (
    <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <style>{`@keyframes glowpulse{0%,100%{opacity:1}50%{opacity:0.5}}`}</style>

      <div style={{ fontSize: '9px', color: '#00d4ff', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>◈ Cluster Map</div>

      {/* Summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '8px' }}>
        {[
          { label: 'Nodes', value: '3/3', color: '#00ff9f', sub: 'all healthy' },
          { label: 'Flows/s', value: '20.6', color: '#00d4ff', sub: 'via Hubble' },
          { label: 'Dropped', value: '2', color: '#ff2d55', sub: 'policy block' },
          { label: 'Suspicious', value: '1', color: '#ff9f0a', sub: 'under review' },
          { label: 'No PDB', value: '4', color: '#ff9f0a', sub: 'at risk' },
        ].map(({ label, value, color, sub }) => (
          <div key={label} style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '8px', padding: '10px 12px' }}>
            <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '4px' }}>{label}</div>
            <div style={{ fontSize: '22px', fontWeight: 700, color, letterSpacing: '-0.02em' }}>{value}</div>
            <div style={{ fontSize: '8px', color: '#5a6478', marginTop: '2px' }}>{sub}</div>
          </div>
        ))}
      </div>

      {/* Tabbed panel */}
      <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '12px', flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.06)', padding: '0 16px', flexShrink: 0 }}>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              fontSize: '9px', padding: '12px 14px', border: 'none', cursor: 'pointer',
              background: 'transparent', color: tab === t.id ? '#00d4ff' : '#5a6478',
              borderBottom: tab === t.id ? '2px solid #00d4ff' : '2px solid transparent',
              fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase', letterSpacing: '1px',
              display: 'flex', alignItems: 'center', gap: '5px', transition: 'color 0.15s',
            }}>
              {t.label}
              {t.badge && (
                <span style={{ fontSize: '7px', background: t.badge === '!' ? '#ff9f0a' : '#ff2d55', color: '#fff', width: '14px', height: '14px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700 }}>{t.badge}</span>
              )}
            </button>
          ))}
        </div>

        <div style={{ padding: '16px', overflow: 'auto' }}>
          {tab === 'topology' && <TopologyMap />}
          {tab === 'flows' && <FlowTable />}
          {tab === 'audit' && <AuditLog />}
          {tab === 'quotas' && <ResourceQuotas />}
          {tab === 'pdbs' && <PdbCoverage />}
        </div>
      </div>
    </div>
  )
}
