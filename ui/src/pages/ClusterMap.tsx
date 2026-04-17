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
  pods: number
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
    { name: 'default', pods: 12, color: '#58a6ff' },
    { name: 'kube-system', pods: 8, color: '#ff9f0a' },
    { name: 'monitoring', pods: 6, color: '#bc8cff' },
    { name: 'security', pods: 4, color: '#00ff9f' },
    { name: 'production', pods: 15, color: '#ff6b9d' },
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
        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>
            Namespace Topology • Click to filter flows
          </div>
          
          {/* Namespace nodes in a circular layout */}
          <div style={{ 
            position: 'relative',
            minHeight: '400px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            {namespaces.map((ns, idx) => {
              const flowCount = flowsByNamespace[ns.name] || 0
              const isSelected = selectedNamespace === ns.name
              const angle = (idx / namespaces.length) * 2 * Math.PI - Math.PI / 2
              const radius = 140
              const x = Math.cos(angle) * radius
              const y = Math.sin(angle) * radius
              
              return (
                <div
                  key={ns.name}
                  onClick={() => setSelectedNamespace(isSelected ? null : ns.name)}
                  style={{
                    position: 'absolute',
                    left: `calc(50% + ${x}px)`,
                    top: `calc(50% + ${y}px)`,
                    transform: 'translate(-50%, -50%)',
                    width: '140px',
                    background: `linear-gradient(135deg, ${ns.color}20, ${ns.color}10)`,
                    border: `2px solid ${isSelected ? ns.color : ns.color + '60'}`,
                    borderRadius: '12px',
                    padding: '16px',
                    cursor: 'pointer',
                    transition: 'all 0.3s ease',
                    boxShadow: isSelected ? `0 0 20px ${ns.color}60` : `0 2px 8px ${ns.color}20`,
                    zIndex: isSelected ? 10 : 1
                  }}
                >
                  {/* Activity pulse */}
                  <div style={{
                    position: 'absolute',
                    top: '12px',
                    right: '12px',
                    width: '10px',
                    height: '10px',
                    borderRadius: '50%',
                    background: flowCount > 0 ? ns.color : '#4a5568',
                    boxShadow: flowCount > 0 ? `0 0 10px ${ns.color}` : 'none',
                    animation: flowCount > 0 ? 'flowPulse 2s infinite' : 'none'
                  }} />
                  
                  {/* Namespace name */}
                  <div style={{ 
                    fontSize: '13px', 
                    fontWeight: 700, 
                    color: ns.color, 
                    fontFamily: 'JetBrains Mono, monospace', 
                    marginBottom: '8px',
                    textAlign: 'center'
                  }}>
                    {ns.name}
                  </div>
                  
                  {/* Stats */}
                  <div style={{ 
                    display: 'flex', 
                    flexDirection: 'column', 
                    gap: '4px',
                    fontSize: '9px',
                    color: '#8892a4',
                    textAlign: 'center'
                  }}>
                    <div>{ns.pods} pods</div>
                    <div style={{ color: flowCount > 0 ? ns.color : '#4a5568', fontWeight: 700 }}>
                      {flowCount} flows
                    </div>
                  </div>
                </div>
              )
            })}
            
            {/* Center hub */}
            <div style={{
              position: 'absolute',
              left: '50%',
              top: '50%',
              transform: 'translate(-50%, -50%)',
              width: '80px',
              height: '80px',
              borderRadius: '50%',
              background: 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,255,159,0.2))',
              border: '2px solid rgba(0,212,255,0.5)',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 20px rgba(0,212,255,0.3)'
            }}>
              <div style={{ fontSize: '20px' }}>🌐</div>
              <div style={{ fontSize: '8px', color: '#00d4ff', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
                CLUSTER
              </div>
            </div>
          </div>

          {/* Legend */}
          <div style={{ 
            display: 'flex', 
            gap: '16px', 
            justifyContent: 'center',
            padding: '12px',
            background: 'rgba(0,0,0,0.2)',
            borderRadius: '8px'
          }}>
            {[
              { label: 'Forwarded', color: '#00ff9f' },
              { label: 'Dropped', color: '#ff2d55' },
              { label: 'Audit', color: '#ff9f0a' }
            ].map(({ label, color }) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}` }} />
                <span style={{ fontSize: '9px', color: '#8892a4' }}>{label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Live flow stream */}
        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', display: 'flex', alignItems: 'center', gap: '6px' }}>
            Live Flow Stream
            <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00ff9f', animation: 'flowPulse 1.5s infinite', boxShadow: '0 0 5px #00ff9f' }} />
          </div>

          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {recentFlows.map((flow, idx) => {
              const verdictColor = flow.verdict === 'DROPPED' ? '#ff2d55' : flow.verdict === 'AUDIT' ? '#ff9f0a' : '#00ff9f'
              const isFiltered = selectedNamespace && flow.source_namespace !== selectedNamespace && flow.dest_namespace !== selectedNamespace
              
              if (isFiltered) return null
              
              return (
                <div
                  key={flow.id}
                  style={{
                    padding: '10px',
                    background: idx === 0 ? 'rgba(0,255,159,0.05)' : 'rgba(0,0,0,0.2)',
                    borderRadius: '6px',
                    borderLeft: `3px solid ${verdictColor}`,
                    animation: idx === 0 ? 'slideIn 0.3s ease-out' : 'none',
                    fontSize: '9px',
                    fontFamily: 'JetBrains Mono, monospace'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
                    <span style={{ 
                      padding: '2px 6px', 
                      background: `${namespaces.find(n => n.name === flow.source_namespace)?.color}20`,
                      border: `1px solid ${namespaces.find(n => n.name === flow.source_namespace)?.color}40`,
                      borderRadius: '4px',
                      color: namespaces.find(n => n.name === flow.source_namespace)?.color,
                      fontSize: '8px',
                      fontWeight: 700
                    }}>
                      {flow.source_namespace}
                    </span>
                    <span style={{ color: '#4a5568' }}>→</span>
                    <span style={{ 
                      padding: '2px 6px', 
                      background: `${namespaces.find(n => n.name === flow.dest_namespace)?.color}20`,
                      border: `1px solid ${namespaces.find(n => n.name === flow.dest_namespace)?.color}40`,
                      borderRadius: '4px',
                      color: namespaces.find(n => n.name === flow.dest_namespace)?.color,
                      fontSize: '8px',
                      fontWeight: 700
                    }}>
                      {flow.dest_namespace}
                    </span>
                  </div>
                  
                  <div style={{ color: '#8892a4', fontSize: '8px', marginBottom: '4px' }}>
                    {flow.source_pod} → {flow.dest_pod}
                  </div>
                  
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '7px', color: '#5a6478' }}>
                    <span>:{flow.dest_port} {flow.protocol}</span>
                    <span style={{ color: verdictColor, fontWeight: 700 }}>{flow.verdict}</span>
                  </div>
                  
                  <div style={{ fontSize: '7px', color: '#4a5568', marginTop: '4px' }}>
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
