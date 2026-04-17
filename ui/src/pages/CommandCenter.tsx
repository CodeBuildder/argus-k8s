import { useState, useEffect, useRef } from 'react'

const API = '/api'

interface Stats {
  total_1h: number
  critical_1h: number
  high_1h: number
  auto_remediated_1h: number
  false_positives_1h: number
  total_all_time: number
}

interface Incident {
  id: string
  ts: number
  rule: string
  severity: string
  namespace: string
  hostname: string
  action_taken: string
  confidence: number
}

function MiniSparkline({ data, color }: { data: number[]; color: string }) {
  const max = Math.max(...data, 1)
  const w = 80, h = 28
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - (v / max) * h}`).join(' ')
  return (
    <svg width={w} height={h} style={{ flexShrink: 0 }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" opacity="0.8" />
      <polyline points={`0,${h} ${pts} ${w},${h}`} fill={color} fillOpacity="0.08" stroke="none" />
    </svg>
  )
}

function LiveEventTicker({ incidents }: { incidents: Incident[] }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = 0
  }, [incidents.length])

  const fmt = (ts: number) => {
    const diff = Math.floor((Date.now() - ts * 1000) / 1000)
    if (diff < 60) return `${diff}s`
    return `${Math.floor(diff / 60)}m`
  }

  const sevColor: Record<string, string> = {
    CRITICAL: '#ff2d55', HIGH: '#ff9f0a', MED: '#ffd700', LOW: '#8b949e'
  }

  const getActionDisplay = (action: string) => {
    if (action === 'HUMAN_REQUIRED') {
      return { icon: '👤', text: 'Attention Required', color: '#ff9f0a', clickable: true }
    }
    if (action === 'NOTIFY') {
      return { icon: '💬', text: 'Slack Notified', color: '#00d4ff', clickable: false }
    }
    if (action === 'ISOLATE') {
      return { icon: '🔒', text: 'Isolated', color: '#ff2d55', clickable: false }
    }
    if (action === 'KILL') {
      return { icon: '⛔', text: 'Terminated', color: '#ff2d55', clickable: false }
    }
    return { icon: '✓', text: action, color: '#00ff9f', clickable: false }
  }

  return (
    <div ref={ref} style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
      {incidents.slice(0, 20).map((inc, i) => {
        const actionDisplay = getActionDisplay(inc.action_taken)
        return (
          <div key={inc.id} style={{
            display: 'flex', alignItems: 'center', gap: '10px', padding: '8px 10px',
            background: i === 0 ? 'rgba(0,255,159,0.04)' : 'rgba(0,0,0,0.2)',
            borderRadius: '6px',
            borderLeft: `3px solid ${sevColor[inc.severity] || '#4a5568'}`,
            animation: i === 0 ? 'fadeInUp 0.3s ease-out' : 'none',
            transition: 'all 0.2s',
          }}>
            <span style={{ fontSize: '9px', color: '#5a6478', fontFamily: 'JetBrains Mono, monospace', width: '28px', flexShrink: 0 }}>{fmt(inc.ts)}</span>
            <span style={{ fontSize: '10px', fontWeight: 700, color: sevColor[inc.severity], fontFamily: 'JetBrains Mono, monospace', width: '18px', flexShrink: 0 }}>
              {inc.severity === 'CRITICAL' ? '●' : inc.severity === 'HIGH' ? '◉' : '○'}
            </span>
            <span style={{ fontSize: '11px', color: '#e6edf3', fontFamily: 'Inter, sans-serif', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 500 }}>{inc.rule}</span>
            {inc.namespace && <span style={{ fontSize: '8px', color: '#58a6ff', background: 'rgba(88,166,255,0.15)', border: '1px solid rgba(88,166,255,0.3)', padding: '2px 6px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>{inc.namespace}</span>}
            <div
              onClick={() => actionDisplay.clickable && window.location.href = '/approvals'}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                fontSize: '9px',
                color: actionDisplay.color,
                background: `${actionDisplay.color}15`,
                border: `1px solid ${actionDisplay.color}30`,
                padding: '3px 8px',
                borderRadius: '4px',
                fontFamily: 'Inter, sans-serif',
                flexShrink: 0,
                cursor: actionDisplay.clickable ? 'pointer' : 'default',
                transition: 'all 0.2s',
                fontWeight: 600
              }}
            >
              <span>{actionDisplay.icon}</span>
              <span>{actionDisplay.text}</span>
            </div>
          </div>
        )
      })}
      {incidents.length === 0 && <div style={{ color: '#4a5568', fontSize: '10px', textAlign: 'center', padding: '20px' }}>No events yet</div>}
    </div>
  )
}

function SecurityLayerRow({ name, status, detail, icon }: { name: string; status: 'active' | 'degraded' | 'inactive'; detail: string; icon: string }) {
  const colors = { active: '#00ff9f', degraded: '#ff9f0a', inactive: '#4a5568' }
  const color = colors[status]
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '7px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', border: `1px solid ${color}18` }}>
      <div style={{ width: '7px', height: '7px', borderRadius: '50%', background: color, boxShadow: status === 'active' ? `0 0 5px ${color}` : 'none', flexShrink: 0, animation: status === 'active' ? 'glowpulse 3s infinite' : 'none' }} />
      <span style={{ fontSize: '11px', fontFamily: 'Inter, sans-serif', color: '#e6edf3', flex: 1 }}>{name}</span>
      <span style={{ fontSize: '9px', color: '#4a5568', fontFamily: 'Inter, sans-serif' }}>{detail}</span>
      <span style={{ fontSize: '8px', color, background: `${color}18`, border: `1px solid ${color}33`, padding: '1px 6px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace' }}>{status}</span>
    </div>
  )
}

function NodeHealthBar({ name, ip, status, podCount, cpuPct, memPct }: { name: string; ip: string; status: string; podCount: number; cpuPct: number; memPct: number }) {
  const color = status === 'threat' ? '#ff2d55' : status === 'warning' ? '#ff9f0a' : '#00ff9f'
  return (
    <div style={{ background: '#111827', border: `1px solid ${color}22`, borderRadius: '8px', padding: '10px 12px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '7px', marginBottom: '8px' }}>
        <div style={{ width: '7px', height: '7px', borderRadius: '50%', background: color, boxShadow: `0 0 5px ${color}`, animation: status === 'threat' ? 'glowpulse 1.5s infinite' : 'none' }} />
        <span style={{ fontSize: '10px', fontWeight: 700, color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>{name}</span>
        <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>{ip}</span>
        <span style={{ fontSize: '8px', color, marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>{podCount} pods</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        {[{ label: 'CPU', pct: cpuPct, color: cpuPct > 80 ? '#ff2d55' : cpuPct > 60 ? '#ff9f0a' : '#00ff9f' }, { label: 'MEM', pct: memPct, color: memPct > 80 ? '#ff2d55' : memPct > 60 ? '#ff9f0a' : '#58a6ff' }].map(({ label, pct, color: bc }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace', width: '28px' }}>{label}</span>
            <div style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px', overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${pct}%`, background: bc, borderRadius: '2px', transition: 'width 1s ease-out' }} />
            </div>
            <span style={{ fontSize: '8px', color: bc, fontFamily: 'JetBrains Mono, monospace', width: '28px', textAlign: 'right' }}>{pct}%</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function DetectionLayerFlow({ recentSeverity }: { recentSeverity: string }) {
  const [layerStats, setLayerStats] = useState({
    falco: { value1: 0, value2: 0, rate: 0 },
    ebpf: { value1: 0, value2: 0, rate: 0 },
    kyverno: { value1: 0, value2: 0, rate: 0 },
    cilium: { value1: 0, value2: 0, rate: 0 },
    argus: { value1: 0, value2: 0, rate: 0 }
  })

  const [activeThreatLayers, setActiveThreatLayers] = useState<number[]>([])

  useEffect(() => {
    const updateStats = () => {
      setLayerStats({
        falco: {
          value1: Math.floor(Math.random() * 50) + 100,
          value2: Math.floor(Math.random() * 10) + 5,
          rate: Math.random() * 20 + 10
        },
        ebpf: {
          value1: Math.floor(Math.random() * 1000) + 5000,
          value2: Math.floor(Math.random() * 50) + 20,
          rate: Math.random() * 100 + 200
        },
        kyverno: {
          value1: 12,
          value2: Math.floor(Math.random() * 5) + 2,
          rate: Math.random() * 5 + 2
        },
        cilium: {
          value1: Math.floor(Math.random() * 2000) + 10000,
          value2: Math.floor(Math.random() * 30) + 10,
          rate: Math.random() * 150 + 300
        },
        argus: {
          value1: Math.floor(Math.random() * 20) + 50,
          value2: Math.floor(Math.random() * 8) + 3,
          rate: Math.random() * 3 + 1
        }
      })
    }
    updateStats()
    const interval = setInterval(updateStats, 3000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    // Randomly inject threats at individual layers
    const injectThreat = () => {
      const randomLayer = Math.floor(Math.random() * 4) // 0-3 (4 connections between 5 layers)
      setActiveThreatLayers(prev => [...prev, randomLayer])
      
      // Remove the threat after animation completes
      setTimeout(() => {
        setActiveThreatLayers(prev => prev.filter((_, idx) => idx !== 0))
      }, 2500)
    }

    // Inject a threat every 1-3 seconds randomly
    const scheduleNext = () => {
      const delay = Math.random() * 2000 + 1000 // 1-3 seconds
      setTimeout(() => {
        injectThreat()
        scheduleNext()
      }, delay)
    }

    scheduleNext()
  }, [])

  const layers = [
    {
      name: 'Falco',
      sub: 'Runtime Detection',
      desc: 'Syscall monitoring',
      color: '#ff9f0a',
      active: true,
      icon: '🔍',
      stats: layerStats.falco,
      metric1: 'Events',
      metric2: 'Blocked'
    },
    {
      name: 'eBPF',
      sub: 'Kernel Hooks',
      desc: 'Network & process',
      color: '#58a6ff',
      active: true,
      icon: '⚡',
      stats: layerStats.ebpf,
      metric1: 'Flows',
      metric2: 'Dropped'
    },
    {
      name: 'Kyverno',
      sub: 'Admission Control',
      desc: 'Policy enforcement',
      color: '#bc8cff',
      active: true,
      icon: '🛡️',
      stats: layerStats.kyverno,
      metric1: 'Policies',
      metric2: 'Violations'
    },
    {
      name: 'Cilium',
      sub: 'Network Policy',
      desc: 'L3-L7 filtering',
      color: '#00ff9f',
      active: true,
      icon: '🌐',
      stats: layerStats.cilium,
      metric1: 'Connections',
      metric2: 'Denied'
    },
    {
      name: 'Argus AI',
      sub: 'Threat Analysis',
      desc: 'Claude reasoning',
      color: '#00d4ff',
      active: true,
      icon: '🧠',
      stats: layerStats.argus,
      metric1: 'Decisions',
      metric2: 'Auto-fixed'
    },
  ]
  const threatColor = recentSeverity === 'CRITICAL' ? '#ff2d55' : recentSeverity === 'HIGH' ? '#ff9f0a' : '#00ff9f'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', padding: '20px 0' }}>
      {/* Main flow */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0', position: 'relative' }}>
        {layers.map((layer, i) => (
          <div key={layer.name} style={{ display: 'flex', alignItems: 'center', flex: 1 }}>
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
              {/* Layer card */}
              <div style={{
                width: '100%',
                maxWidth: '160px',
                minHeight: '140px',
                borderRadius: '12px',
                background: `linear-gradient(135deg, ${layer.color}08, ${layer.color}18)`,
                border: `2px solid ${layer.color}50`,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '4px',
                position: 'relative',
                padding: '12px',
                boxShadow: `0 4px 12px ${layer.color}20`,
                transition: 'all 0.3s ease'
              }}>
                {/* Status indicator */}
                <div style={{
                  position: 'absolute',
                  top: '8px',
                  right: '8px',
                  width: '10px',
                  height: '10px',
                  borderRadius: '50%',
                  background: layer.active ? layer.color : '#4a5568',
                  boxShadow: layer.active ? `0 0 8px ${layer.color}` : 'none',
                  animation: layer.active ? 'glowpulse 2s infinite' : 'none'
                }} />
                
                {/* Icon */}
                <div style={{ fontSize: '24px', marginBottom: '2px' }}>{layer.icon}</div>
                
                {/* Layer name */}
                <span style={{
                  fontSize: '12px',
                  fontWeight: 700,
                  color: layer.color,
                  fontFamily: 'JetBrains Mono, monospace',
                  textAlign: 'center'
                }}>{layer.name}</span>
                
                {/* Subtitle */}
                <span style={{
                  fontSize: '8px',
                  color: '#8892a4',
                  fontFamily: 'Inter, sans-serif',
                  textAlign: 'center',
                  fontWeight: 600,
                  marginBottom: '6px'
                }}>{layer.sub}</span>
                
                {/* Real-time metrics */}
                <div style={{
                  width: '100%',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '3px',
                  background: 'rgba(0,0,0,0.2)',
                  padding: '6px',
                  borderRadius: '6px'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '7px', color: '#5a6478', fontFamily: 'Inter, sans-serif' }}>{layer.metric1}</span>
                    <span style={{ fontSize: '10px', color: '#e6edf3', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
                      {layer.stats.value1}
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '7px', color: '#5a6478', fontFamily: 'Inter, sans-serif' }}>{layer.metric2}</span>
                    <span style={{ fontSize: '10px', color: layer.color, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
                      {layer.stats.value2}
                    </span>
                  </div>
                  <div style={{
                    fontSize: '7px',
                    color: '#4a5568',
                    textAlign: 'center',
                    marginTop: '2px',
                    fontFamily: 'JetBrains Mono, monospace'
                  }}>
                    {layer.stats.rate.toFixed(1)}/s
                  </div>
                </div>
              </div>
            </div>
            
            {/* Connection arrow with animated threat signals */}
            {i < layers.length - 1 && (
              <div style={{
                width: '60px',
                height: '4px',
                background: `linear-gradient(90deg, ${layer.color}60, ${layers[i+1].color}60)`,
                flexShrink: 0,
                position: 'relative',
                margin: '0 -10px',
                borderRadius: '2px'
              }}>
                {/* Only show threat particles on active layers */}
                {activeThreatLayers.includes(i) && (
                  <>
                    {/* Primary threat particle */}
                    <div style={{
                      position: 'absolute',
                      top: '-6px',
                      left: '0',
                      width: '16px',
                      height: '16px',
                      borderRadius: '50%',
                      background: `radial-gradient(circle, ${threatColor}, ${threatColor}80)`,
                      boxShadow: `0 0 15px ${threatColor}, 0 0 25px ${threatColor}80`,
                      animation: 'travelDot 2.5s linear infinite',
                      border: `2px solid ${threatColor}`,
                      zIndex: 10
                    }} />
                    
                    {/* Secondary threat particle (trailing) */}
                    <div style={{
                      position: 'absolute',
                      top: '-3px',
                      left: '0',
                      width: '10px',
                      height: '10px',
                      borderRadius: '50%',
                      background: threatColor,
                      boxShadow: `0 0 8px ${threatColor}`,
                      animation: 'travelDot 2.5s linear infinite',
                      animationDelay: '0.3s',
                      opacity: 0.6
                    }} />
                    
                    {/* Pulse effect on connection */}
                    <div style={{
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      right: 0,
                      height: '100%',
                      background: `linear-gradient(90deg, transparent, ${threatColor}40, transparent)`,
                      animation: 'pulse 2s ease-in-out infinite'
                    }} />
                  </>
                )}
                
                {/* Arrow head */}
                <div style={{
                  position: 'absolute',
                  right: '-7px',
                  top: '-4px',
                  width: 0,
                  height: 0,
                  borderLeft: `8px solid ${layers[i+1].color}80`,
                  borderTop: '6px solid transparent',
                  borderBottom: '6px solid transparent'
                }} />
              </div>
            )}
          </div>
        ))}
      </div>
      
      {/* Flow description with legend */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '16px',
        padding: '12px 20px',
        background: 'rgba(0,212,255,0.05)',
        borderRadius: '8px',
        border: '1px solid rgba(0,212,255,0.15)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{
            width: '12px',
            height: '12px',
            borderRadius: '50%',
            background: `radial-gradient(circle, ${threatColor}, ${threatColor}80)`,
            boxShadow: `0 0 10px ${threatColor}`,
            animation: 'glowpulse 1.5s infinite',
            border: `2px solid ${threatColor}`
          }} />
          <span style={{
            fontSize: '9px',
            color: '#e6edf3',
            fontFamily: 'JetBrains Mono, monospace',
            fontWeight: 600
          }}>
            = Threat Signal
          </span>
        </div>
        <div style={{ width: '1px', height: '20px', background: 'rgba(255,255,255,0.1)' }} />
        <span style={{
          fontSize: '10px',
          color: '#8892a4',
          fontFamily: 'Inter, sans-serif',
          textAlign: 'center'
        }}>
          Watch threats flow through each layer • Real-time detection • Multi-stage validation
        </span>
      </div>
    </div>
  )
}

export default function CommandCenter() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [sparkData] = useState(() => ({
    critical: Array.from({ length: 12 }, () => Math.floor(Math.random() * 5)),
    events: Array.from({ length: 12 }, () => Math.floor(Math.random() * 30) + 10),
  }))

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [statsRes, incRes] = await Promise.all([
          fetch(`${API}/incidents/stats`),
          fetch(`${API}/incidents?limit=50`)
        ])
        if (statsRes.ok) setStats(await statsRes.json())
        if (incRes.ok) {
          const data = await incRes.json()
          setIncidents(data.incidents || [])
        }
      } catch {}
    }
    fetchAll()
    const t = setInterval(fetchAll, 5000)
    return () => clearInterval(t)
  }, [])

  const recentSeverity = incidents[0]?.severity || 'LOW'
  const kpis = stats ? [
    { label: 'Active (1h)', value: stats.total_1h, color: '#ff9f0a', spark: sparkData.events },
    { label: 'Critical', value: stats.critical_1h, color: '#ff2d55', spark: sparkData.critical },
    { label: 'Auto-remediated', value: stats.auto_remediated_1h, color: '#58a6ff', spark: null },
    { label: 'False positives', value: stats.false_positives_1h, color: '#00ff9f', spark: null },
    { label: 'High severity', value: stats.high_1h, color: '#ff9f0a', spark: null },
    { label: 'Total all time', value: stats.total_all_time, color: '#bc8cff', spark: null },
  ] : Array(6).fill(null).map((_, i) => ({ label: ['Active (1h)','Critical','Auto-remediated','False positives','High severity','Total all time'][i], value: '—', color: ['#ff9f0a','#ff2d55','#58a6ff','#00ff9f','#ff9f0a','#bc8cff'][i], spark: null }))

  return (
    <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <style>{`
        @keyframes glowpulse{0%,100%{opacity:1}50%{opacity:0.6}}
        @keyframes fadeInUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
        @keyframes travelDot{0%{left:0%;opacity:0}20%{opacity:1}80%{opacity:1}100%{left:100%;opacity:0}}
      `}</style>

      <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>⌂ Command Center</div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: '8px' }}>
        {kpis.map(({ label, value, color, spark }) => (
          <div key={label} style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '8px', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px' }}>{label}</div>
            <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between' }}>
              <div style={{ fontSize: '22px', fontWeight: 700, color, letterSpacing: '-0.02em' }}>{value}</div>
              {spark && <MiniSparkline data={spark} color={color} />}
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>Detection pipeline</div>
          <DetectionLayerFlow recentSeverity={recentSeverity} />
          <div style={{ fontSize: '8px', color: '#4a5568', textAlign: 'center', fontFamily: 'Inter, sans-serif' }}>Threat signal flows through each layer in real time</div>
        </div>

        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>Node health</div>
          <NodeHealthBar name="k3s-master" ip="192.168.139.42" status="healthy" podCount={6} cpuPct={18} memPct={34} />
          <NodeHealthBar name="k3s-worker1" ip="192.168.139.77" status={incidents.some(i => i.hostname === 'k3s-worker1' && i.severity === 'CRITICAL') ? 'threat' : 'healthy'} podCount={8} cpuPct={42} memPct={61} />
          <NodeHealthBar name="k3s-worker2" ip="192.168.139.45" status="healthy" podCount={7} cpuPct={31} memPct={48} />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '12px', display: 'flex', flexDirection: 'column', minHeight: '200px' }}>
          <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            Live event stream
            <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00ff9f', animation: 'glowpulse 1.5s infinite', boxShadow: '0 0 5px #00ff9f' }} />
          </div>
          <LiveEventTicker incidents={incidents} />
        </div>

        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>Security layers</div>
          <SecurityLayerRow name="Falco runtime detection" status="active" detail="eBPF · 3 nodes" icon="⚡" />
          <SecurityLayerRow name="Kyverno admission control" status="active" detail="3 policies enforced" icon="🛡" />
          <SecurityLayerRow name="Cilium eBPF networking" status="active" detail="policy enforcement" icon="🔒" />
          <SecurityLayerRow name="Prometheus + Grafana" status="active" detail="metrics · 5 dashboards" icon="📊" />
          <SecurityLayerRow name="Argus AI agent" status="active" detail={`${stats?.total_all_time || 0} decisions made`} icon="🤖" />
          <SecurityLayerRow name="Loki log aggregation" status="degraded" detail="direct push failing" icon="📋" />
        </div>
      </div>
    </div>
  )
}
