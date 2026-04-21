import React from 'react'
import { Routes, Route, NavLink } from 'react-router-dom'
import { AlertTriangle, CheckSquare, MessageSquare, Activity, Map, Shield, GitBranch, Search, BarChart3, Info } from 'lucide-react'
import ArgusLogo from './components/ArgusLogo'
import ThreatFeed from './pages/ThreatFeed'
import ApprovalQueue from './pages/ApprovalQueue'
import AgentChat from './pages/AgentChat'
import CommandCenter from './pages/CommandCenter'
import ClusterMap from './pages/ClusterMap'
import SecurityPosture from './pages/SecurityPosture'
import AttackChains from './pages/AttackChains'
import ThreatHunting from './pages/ThreatHunting'
import InfraObservability from './pages/InfraObservability'
import About from './pages/About'

const NAV_ITEMS = [
  { path: '/', icon: Activity, label: 'Command Center', exact: true },
  { path: '/threats', icon: AlertTriangle, label: 'Threat Feed' },
  { path: '/hunt', icon: Search, label: 'Threat Hunting' },
  { path: '/approvals', icon: CheckSquare, label: 'Approvals' },
  { path: '/chains', icon: GitBranch, label: 'Attack Chains' },
  { path: '/cluster', icon: Map, label: 'Cluster Map' },
  { path: '/posture', icon: Shield, label: 'Security Posture' },
  { path: '/infra', icon: BarChart3, label: 'Infrastructure' },
  { path: '/chat', icon: MessageSquare, label: 'Agent Chat' },
  { path: '/about', icon: Info, label: 'About Argus' },
]

export default function App() {
  return (
    <div className="flex flex-col h-screen bg-[#060912]" style={{ fontFamily: "'Inter', sans-serif" }}>
      <TopBar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-auto">
          <Routes>
            <Route path="/" element={<CommandCenter />} />
            <Route path="/threats" element={<ThreatFeed />} />
            <Route path="/hunt" element={<ThreatHunting />} />
            <Route path="/approvals" element={<ApprovalQueue />} />
            <Route path="/chains" element={<AttackChains />} />
            <Route path="/cluster" element={<ClusterMap />} />
            <Route path="/posture" element={<SecurityPosture />} />
            <Route path="/infra" element={<InfraObservability />} />
            <Route path="/chat" element={<AgentChat />} />
            <Route path="/about" element={<About />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

type ClusterOverview = {
  generated_at: string
  incident_source: string
  cluster_source: string
  critical_1h: number
  warnings_1h: number
  events_1h: number
  auto_remediated_1h: number
  last_ingest_age_seconds: number
  mttr_seconds: number
  nodes_ready: number
  nodes_total: number
  pods_running: number
  namespaces_total: number
}

function TopBar() {
  const [overview, setOverview] = React.useState<ClusterOverview | null>(null)
  const [history, setHistory] = React.useState<Record<string, number[]>>({
    critical: [],
    warnings: [],
    events: [],
    nodes: [],
    mttr: [],
  })

  React.useEffect(() => {
    let active = true
    const sample = async () => {
      try {
        const res = await fetch('/api/cluster-overview')
        if (!res.ok) return
        const data: ClusterOverview = await res.json()
        if (!active) return
        setOverview(data)
        setHistory(prev => ({
          critical: [...prev.critical.slice(-17), data.critical_1h],
          warnings: [...prev.warnings.slice(-17), data.warnings_1h],
          events: [...prev.events.slice(-17), data.events_1h],
          nodes: [...prev.nodes.slice(-17), data.nodes_total ? Math.round((data.nodes_ready / data.nodes_total) * 100) : 0],
          mttr: [...prev.mttr.slice(-17), data.mttr_seconds],
        }))
      } catch {}
    }
    sample()
    const t = setInterval(sample, 4000)
    return () => {
      active = false
      clearInterval(t)
    }
  }, [])

  const nodeValue = overview ? `${overview.nodes_ready}/${overview.nodes_total}` : '--'
  const mttrValue = overview ? `${overview.mttr_seconds || 0}s` : '--'

  return (
    <div className="flex items-center gap-3 px-5 h-[72px] bg-[#0a0f1e] border-b border-[rgba(99,179,237,0.12)] flex-shrink-0" style={{ position: 'relative', zIndex: 50 }}>
      <style>{`@keyframes argusGlow { 0%,100%{text-shadow:0 0 8px rgba(0,212,255,0.45),0 0 16px rgba(0,212,255,0.15)} 50%{text-shadow:0 0 18px rgba(0,212,255,0.85),0 0 36px rgba(0,212,255,0.3),0 0 60px rgba(0,212,255,0.1)} }`}</style>
      <div className="flex items-center gap-3 flex-shrink-0 min-w-[210px]">
        <div className="relative flex h-9 w-9 items-center justify-center rounded-[10px] border border-[rgba(0,212,255,0.26)] bg-[radial-gradient(circle_at_50%_45%,rgba(0,212,255,0.18),rgba(0,0,0,0))] shadow-[0_0_22px_rgba(0,212,255,0.12)]">
          <ArgusLogo size={28} />
        </div>
        <div className="flex flex-col justify-center leading-none gap-[3px]">
          <span
            className="text-[#00d4ff] font-bold tracking-[0.18em] text-[17px] uppercase"
            style={{ animation: 'argusGlow 3s ease-in-out infinite' }}
          >
            Argus
          </span>
          <div className="flex flex-col gap-[1px]">
            <span className="text-[#5a6478] text-[9px] tracking-[0.22em] uppercase font-medium">Security Console</span>
            <span style={{ fontSize: '8px', color: '#2d4a5f', fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.08em' }}>AI-native threat detection</span>
          </div>
        </div>
      </div>
      <div className="flex-1 grid grid-cols-5 gap-4 px-4 min-w-0">
        <KPI label="Critical" value={overview ? String(overview.critical_1h) : '...'} color="#ff4757" sublabel="last 60m" history={history.critical} />
        <KPI label="Warnings" value={overview ? String(overview.warnings_1h) : '...'} color="#ff9f0a" sublabel="last 60m" history={history.warnings} />
        <KPI label="Events/hr" value={overview ? String(overview.events_1h) : '...'} color="#00d4ff" sublabel={overview?.incident_source || 'backend'} history={history.events} />
        <KPI label="Nodes" value={nodeValue} color="#00ff88" sublabel={`${overview?.pods_running ?? '--'} pods`} history={history.nodes} />
        <KPI label="MTTR" value={mttrValue} color="#7dd3fc" sublabel={`${overview?.auto_remediated_1h ?? '--'} actions`} history={history.mttr} />
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        <div className="w-2 h-2 rounded-full bg-[#00ff88] shadow-[0_0_6px_#00ff88] animate-pulse" />
        <Clock />
      </div>
    </div>
  )
}

function KPI({ label, value, color, sublabel, history }: { label: string; value: string; color: string; sublabel: string; history: number[] }) {
  const max = Math.max(...history, 1)
  const latest = history[history.length - 1] ?? 0
  const previous = history[history.length - 2] ?? latest
  const delta = latest - previous
  const trendText = delta === 0
    ? 'stable'
    : `${delta > 0 ? '+' : '-'}${Math.abs(delta)}`

  return (
    <div className="flex flex-col justify-center min-w-0 overflow-hidden">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[9px] text-[#5a6478] uppercase tracking-wider whitespace-nowrap">{label}</span>
        <span className="text-[8px] whitespace-nowrap" style={{ color: delta > 0 ? '#ff9f0a' : delta < 0 ? '#00ff88' : '#8b949e' }}>{trendText}</span>
      </div>
      <div className="mt-[2px] flex items-end gap-1 leading-none">
        <span className="text-[18px] font-bold" style={{ color }}>{value}</span>
      </div>
      <div className="mt-[4px] flex items-center gap-[2px] h-[10px]">
        {history.length === 0
          ? Array.from({ length: 18 }).map((_, idx) => (
              <span key={idx} className="flex-1 rounded-sm bg-[rgba(255,255,255,0.04)]" style={{ height: '3px' }} />
            ))
          : history.map((point, idx) => (
              <span
                key={`${label}-${idx}`}
                className="flex-1 rounded-sm transition-all duration-500"
                style={{
                  height: point <= 0 ? '0px' : `${Math.max(1, Math.round((point / max) * 10))}px`,
                  background: idx === history.length - 1 ? color : `${color}66`,
                  boxShadow: idx === history.length - 1 ? `0 0 8px ${color}44` : 'none',
                }}
              />
            ))}
      </div>
      <div className="mt-[3px] flex items-center justify-between gap-2">
        <span className="text-[8px] text-[#5a6478] tracking-wide truncate">{sublabel}</span>
        <span className="text-[7px] text-[#4a5568] whitespace-nowrap">oldest left · newest right</span>
      </div>
    </div>
  )
}

function Clock() {
  const [time, setTime] = React.useState(new Date().toTimeString().slice(0, 8))
  React.useEffect(() => {
    const t = setInterval(() => setTime(new Date().toTimeString().slice(0, 8)), 1000)
    return () => clearInterval(t)
  }, [])
  return <span className="text-[11px] text-[#00ff88] font-mono">{`live ${time}`}</span>
}

function Sidebar() {
  return (
    <div className="w-12 bg-[#0a0f1e] border-r border-[rgba(99,179,237,0.12)] flex flex-col items-center py-3 gap-1 flex-shrink-0">
      <style>{`
        .argus-nav-item { position: relative; }
        .argus-nav-item::before {
          content: '';
          position: absolute;
          left: 43px;
          top: 50%;
          width: 8px;
          height: 8px;
          transform: translateY(-50%) rotate(45deg) scale(0.8);
          background: #111827;
          border-left: 1px solid rgba(0,212,255,0.28);
          border-bottom: 1px solid rgba(0,212,255,0.28);
          opacity: 0;
          transition: opacity 0.14s ease, transform 0.14s ease;
          pointer-events: none;
          z-index: 60;
        }
        .argus-nav-label {
          position: absolute;
          left: 48px;
          top: 50%;
          transform: translateY(-50%) translateX(-4px);
          min-width: max-content;
          background: linear-gradient(135deg, #111827, #0b1220);
          border: 1px solid rgba(0,212,255,0.28);
          border-radius: 6px;
          color: #e6edf3;
          font-size: 12px;
          font-weight: 600;
          line-height: 1;
          padding: 8px 10px;
          box-shadow: 0 12px 32px rgba(0,0,0,0.45), 0 0 18px rgba(0,212,255,0.08);
          opacity: 0;
          pointer-events: none;
          transition: opacity 0.14s ease, transform 0.14s ease;
          z-index: 61;
        }
        .argus-nav-label span {
          display: block;
          color: #00d4ff;
          font-family: 'JetBrains Mono', monospace;
          font-size: 8px;
          font-weight: 700;
          letter-spacing: 1px;
          margin-bottom: 5px;
          text-transform: uppercase;
        }
        .argus-nav-item:hover::before,
        .argus-nav-item:hover .argus-nav-label {
          opacity: 1;
          transform: translateY(-50%) translateX(0);
        }
        .argus-nav-item:hover::before {
          transform: translateY(-50%) rotate(45deg) scale(1);
        }
      `}</style>
      {NAV_ITEMS.map(({ path, icon: Icon, label }) => (
        <NavLink
          key={path}
          to={path}
          end={path === '/'}
          className={({ isActive }) =>
            `argus-nav-item w-9 h-9 rounded-lg flex items-center justify-center transition-all cursor-pointer
            ${isActive
              ? 'bg-[rgba(0,212,255,0.1)] text-[#00d4ff] border border-[rgba(0,212,255,0.25)]'
              : 'text-[#5a6478] hover:bg-[#111827] hover:text-[#00d4ff]'
            }`
          }
        >
          <Icon size={14} />
          <span className="argus-nav-label"><span>Menu</span>{label}</span>
        </NavLink>
      ))}
    </div>
  )
}
