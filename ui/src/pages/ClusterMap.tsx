import { useState, useEffect } from 'react'

interface NetworkFlow {
  id: string
  source_namespace: string
  source_pod: string
  source_ip: string
  dest_namespace: string
  dest_pod: string
  dest_ip: string
  dest_port: number
  protocol: string
  verdict: 'FORWARDED' | 'DROPPED' | 'AUDIT'
  bytes: number
  packets: number
  timestamp: number
}

interface NamespaceNode {
  name: string
  pods: string[]
  color: string
}

export default function ClusterMap() {
  const [flows, setFlows] = useState<NetworkFlow[]>([])
  const [selectedNamespace, setSelectedNamespace] = useState<string | null>(null)
  const [flowRate, setFlowRate] = useState(20.6)

  useEffect(() => {
    // Simulate Hubble flow data
    const generateFlow = (): NetworkFlow => {
      const namespaces = ['default', 'kube-system', 'monitoring', 'security', 'production']
      const pods = ['nginx', 'api', 'db', 'redis', 'worker', 'frontend', 'backend']
      const protocols = ['TCP', 'UDP', 'ICMP']
      const verdicts: ('FORWARDED' | 'DROPPED' | 'AUDIT')[] = ['FORWARDED', 'FORWARDED', 'FORWARDED', 'FORWARDED', 'DROPPED', 'AUDIT']
      
      const srcNs = namespaces[Math.floor(Math.random() * namespaces.length)]
      const dstNs = namespaces[Math.floor(Math.random() * namespaces.length)]
      
      return {
        id: `flow-${Date.now()}-${Math.random()}`,
        source_namespace: srcNs,
        source_pod: `${pods[Math.floor(Math.random() * pods.length)]}-${Math.random().toString(36).substr(2, 5)}`,
        source_ip: `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        dest_namespace: dstNs,
        dest_pod: `${pods[Math.floor(Math.random() * pods.length)]}-${Math.random().toString(36).substr(2, 5)}`,
        dest_ip: `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        dest_port: [80, 443, 3000, 5432, 6379, 9090, 3100][Math.floor(Math.random() * 7)],
        protocol: protocols[Math.floor(Math.random() * protocols.length)],
        verdict: verdicts[Math.floor(Math.random() * verdicts.length)],
        bytes: Math.floor(Math.random() * 10000) + 100,
        packets: Math.floor(Math.random() * 100) + 1,
        timestamp: Date.now()
      }
    }

    const interval = setInterval(() => {
      setFlows(prev => {
        const newFlow = generateFlow()
        const updated = [newFlow, ...prev].slice(0, 100)
        return updated
      })
      setFlowRate(prev => prev + (Math.random() - 0.5) * 2)
    }, 500)

    return () => clearInterval(interval)
  }, [])

  const namespaces: NamespaceNode[] = [
    { name: 'default', pods: [], color: '#58a6ff' },
    { name: 'kube-system', pods: [], color: '#ff9f0a' },
    { name: 'monitoring', pods: [], color: '#bc8cff' },
    { name: 'security', pods: [], color: '#00ff9f' },
    { name: 'production', pods: [], color: '#ff6b9d' },
  ]

  const recentFlows = flows.slice(0, 20)
  const flowsByNamespace = flows.reduce((acc, flow) => {
    acc[flow.source_namespace] = (acc[flow.source_namespace] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  const droppedFlows = flows.filter(f => f.verdict === 'DROPPED').length
  const auditFlows = flows.filter(f => f.verdict === 'AUDIT').length

  return (
    <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <style>{`
        @keyframes flowPulse { 0%, 100% { opacity: 0.3; } 50% { opacity: 1; } }
        @keyframes slideIn { from { opacity: 0; transform: translateX(-10px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes travelDot{0%{left:0%;opacity:0}20%{opacity:1}80%{opacity:1}100%{left:100%;opacity:0}}
      `}</style>

      <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>🗺️ Network Topology Map</div>

      {/* Stats bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '8px' }}>
        {[
          { label: 'Flow Rate', value: `${flowRate.toFixed(1)}/s`, color: '#00d4ff' },
          { label: 'Active Flows', value: flows.length, color: '#58a6ff' },
          { label: 'Forwarded', value: flows.filter(f => f.verdict === 'FORWARDED').length, color: '#00ff9f' },
          { label: 'Dropped', value: droppedFlows, color: '#ff2d55' },
          { label: 'Audit', value: auditFlows, color: '#ff9f0a' },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '8px', padding: '10px 12px' }}>
            <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '4px' }}>{label}</div>
            <div style={{ fontSize: '20px', fontWeight: 700, color }}>{value}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '12px', flex: 1 }}>
        {/* Network topology visualization */}
        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>Namespace Topology</div>
          
          {/* Namespace nodes */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', padding: '20px' }}>
            {namespaces.map((ns, idx) => {
              const flowCount = flowsByNamespace[ns.name] || 0
              const isSelected = selectedNamespace === ns.name
              
              return (
                <div
                  key={ns.name}
                  onClick={() => setSelectedNamespace(isSelected ? null : ns.name)}
                  style={{
                    background: `linear-gradient(135deg, ${ns.color}15, ${ns.color}08)`,
                    border: `2px solid ${isSelected ? ns.color : ns.color + '40'}`,
                    borderRadius: '12px',
                    padding: '16px',
                    cursor: 'pointer',
                    transition: 'all 0.3s ease',
                    transform: isSelected ? 'scale(1.05)' : 'scale(1)',
                    boxShadow: isSelected ? `0 0 20px ${ns.color}40` : 'none',
                    position: 'relative'
                  }}
                >
                  {/* Activity indicator */}
                  <div style={{
                    position: 'absolute',
                    top: '12px',
                    right: '12px',
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    background: flowCount > 0 ? ns.color : '#4a5568',
                    boxShadow: flowCount > 0 ? `0 0 8px ${ns.color}` : 'none',
                    animation: flowCount > 0 ? 'flowPulse 2s infinite' : 'none'
                  }} />
                  
                  <div style={{ fontSize: '11px', fontWeight: 700, color: ns.color, fontFamily: 'JetBrains Mono, monospace', marginBottom: '8px' }}>
                    {ns.name}
                  </div>
                  
                  <div style={{ fontSize: '8px', color: '#8892a4', marginBottom: '4px' }}>
                    {flowCount} flows
                  </div>
                  
                  {/* Flow visualization bars */}
                  <div style={{ display: 'flex', gap: '2px', height: '20px', marginTop: '8px' }}>
                    {Array.from({ length: 10 }).map((_, i) => {
                      const hasFlow = i < Math.min(10, flowCount / 2)
                      return (
                        <div
                          key={i}
                          style={{
                            flex: 1,
                            background: hasFlow ? ns.color : 'rgba(255,255,255,0.05)',
                            borderRadius: '2px',
                            opacity: hasFlow ? 0.8 : 0.3,
                            transition: 'all 0.3s ease'
                          }}
                        />
                      )
                    })}
                  </div>
                </div>
              )
            })}
          </div>

          {/* Connection lines visualization */}
          <div style={{ 
            padding: '16px', 
            background: 'rgba(0,0,0,0.2)', 
            borderRadius: '8px',
            minHeight: '120px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            position: 'relative',
            overflow: 'hidden'
          }}>
            {recentFlows.slice(0, 5).map((flow, idx) => {
              const srcNs = namespaces.find(n => n.name === flow.source_namespace)
              const dstNs = namespaces.find(n => n.name === flow.dest_namespace)
              const color = flow.verdict === 'DROPPED' ? '#ff2d55' : flow.verdict === 'AUDIT' ? '#ff9f0a' : '#00ff9f'
              
              return (
                <div
                  key={flow.id}
                  style={{
                    position: 'absolute',
                    left: `${10 + idx * 15}%`,
                    top: '50%',
                    transform: 'translateY(-50%)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    animation: 'slideIn 0.5s ease-out',
                    opacity: 0.7
                  }}
                >
                  <div style={{
                    padding: '4px 8px',
                    background: `${srcNs?.color}20`,
                    border: `1px solid ${srcNs?.color}40`,
                    borderRadius: '4px',
                    fontSize: '8px',
                    color: srcNs?.color,
                    fontFamily: 'JetBrains Mono, monospace'
                  }}>
                    {flow.source_namespace}
                  </div>
                  
                  <div style={{
                    width: '40px',
                    height: '2px',
                    background: `linear-gradient(90deg, ${srcNs?.color}80, ${dstNs?.color}80)`,
                    position: 'relative'
                  }}>
                    <div style={{
                      position: 'absolute',
                      top: '-3px',
                      left: '0',
                      width: '8px',
                      height: '8px',
                      borderRadius: '50%',
                      background: color,
                      boxShadow: `0 0 8px ${color}`,
                      animation: 'travelDot 2s linear infinite'
                    }} />
                  </div>
                  
                  <div style={{
                    padding: '4px 8px',
                    background: `${dstNs?.color}20`,
                    border: `1px solid ${dstNs?.color}40`,
                    borderRadius: '4px',
                    fontSize: '8px',
                    color: dstNs?.color,
                    fontFamily: 'JetBrains Mono, monospace'
                  }}>
                    {flow.dest_namespace}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Live flow stream */}
        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', display: 'flex', alignItems: 'center', gap: '6px' }}>
            Live Flow Stream
            <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00ff9f', animation: 'flowPulse 1.5s infinite', boxShadow: '0 0 5px #00ff9f' }} />
          </div>

          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {recentFlows.map((flow, idx) => {
              const verdictColor = flow.verdict === 'DROPPED' ? '#ff2d55' : flow.verdict === 'AUDIT' ? '#ff9f0a' : '#00ff9f'
              const isFiltered = selectedNamespace && flow.source_namespace !== selectedNamespace && flow.dest_namespace !== selectedNamespace
              
              if (isFiltered) return null
              
              return (
                <div
                  key={flow.id}
                  style={{
                    padding: '8px',
                    background: idx === 0 ? 'rgba(0,255,159,0.05)' : 'rgba(0,0,0,0.2)',
                    borderRadius: '6px',
                    borderLeft: `3px solid ${verdictColor}`,
                    animation: idx === 0 ? 'slideIn 0.3s ease-out' : 'none',
                    fontSize: '9px',
                    fontFamily: 'JetBrains Mono, monospace'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{ color: '#58a6ff' }}>{flow.source_namespace}</span>
                    <span style={{ color: '#4a5568' }}>→</span>
                    <span style={{ color: '#bc8cff' }}>{flow.dest_namespace}</span>
                  </div>
                  
                  <div style={{ color: '#8892a4', fontSize: '8px', marginBottom: '2px' }}>
                    {flow.source_pod} → {flow.dest_pod}
                  </div>
                  
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '7px' }}>
                    <span style={{ color: '#4a5568' }}>:{flow.dest_port} {flow.protocol}</span>
                    <span style={{ color: verdictColor, fontWeight: 700 }}>{flow.verdict}</span>
                  </div>
                  
                  <div style={{ fontSize: '7px', color: '#4a5568', marginTop: '2px' }}>
                    {flow.bytes}B · {flow.packets}pkt
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}

// Made with Bob
