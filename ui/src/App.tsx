import React from 'react'
import { Routes, Route, NavLink } from 'react-router-dom'
import { AlertTriangle, CheckSquare, MessageSquare, Activity, Map, Shield, GitBranch, Search, BarChart3 } from 'lucide-react'
import ThreatFeed from './pages/ThreatFeed'
import ApprovalQueue from './pages/ApprovalQueue'
import AgentChat from './pages/AgentChat'
import CommandCenter from './pages/CommandCenter'
import ClusterMap from './pages/ClusterMap'
import SecurityPosture from './pages/SecurityPosture'
import AttackChains from './pages/AttackChains'
import ThreatHunting from './pages/ThreatHunting'
import InfraObservability from './pages/InfraObservability'

const NAV_ITEMS = [
  { path: '/', icon: Activity, label: 'Command Center', desc: 'Live threat dashboard, detection pipeline & node health' },
  { path: '/threats', icon: AlertTriangle, label: 'Threat Feed', desc: 'Stream of active security incidents with full context' },
  { path: '/hunt', icon: Search, label: 'Threat Hunting', desc: 'AI-powered natural language search across cluster telemetry' },
  { path: '/approvals', icon: CheckSquare, label: 'Approvals', desc: 'Human-in-the-loop queue for high-risk remediation actions' },
  { path: '/chains', icon: GitBranch, label: 'Attack Chains', desc: 'Correlated multi-step intrusion sequences' },
  { path: '/cluster', icon: Map, label: 'Cluster Map', desc: 'Network topology, Hubble flows & pod connectivity' },
  { path: '/posture', icon: Shield, label: 'Security Posture', desc: 'CVE dashboard, drift detection, secrets & CIS compliance' },
  { path: '/infra', icon: BarChart3, label: 'Infrastructure', desc: 'Resource quotas, PDB coverage & infra health' },
  { path: '/chat', icon: MessageSquare, label: 'Agent Chat', desc: 'AI incident summaries, risk forecasting & threat reports' },
]

export default function App() {
  return (
    <div className="flex flex-col h-screen bg-[#060912]" style={{ fontFamily: "'Inter', sans-serif" }}>
      <TopBar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main style={{ flex: 1, overflow: 'hidden', height: 'calc(100vh - 56px)', minWidth: 0 }}>
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
          </Routes>
        </main>
      </div>
    </div>
  )
}

function TopBar() {
  return (
    <div className="flex items-center gap-4 px-6 h-[56px] bg-[#0a0f1e] border-b border-[rgba(99,179,237,0.12)] flex-shrink-0" style={{ position: 'relative', zIndex: 50 }}>
      <div className="flex items-center gap-2">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" style={{ filter: 'drop-shadow(0 0 6px rgba(0,212,255,0.45))' }}>
          {/* Hexagon shell — Kubernetes reference */}
          <path d="M12 2L20.8 7V17L12 22L3.2 17V7Z" stroke="#00d4ff" strokeWidth="1.3" fill="rgba(0,212,255,0.07)" strokeLinejoin="round"/>
          {/* Eye lozenge — Argus the watcher */}
          <path d="M6 12C6 12 8.5 8.6 12 8.6C15.5 8.6 18 12 18 12C18 12 15.5 15.4 12 15.4C8.5 15.4 6 12 6 12Z" stroke="#00d4ff" strokeWidth="1" fill="none"/>
          {/* Iris ring */}
          <circle cx="12" cy="12" r="2.4" stroke="#00d4ff" strokeWidth="0.9" fill="rgba(0,212,255,0.14)"/>
          {/* Threat dot — red pupil */}
          <circle cx="12" cy="12" r="1.15" fill="#ff2d55"/>
          {/* Vertex dots — cluster nodes */}
          <circle cx="12" cy="2.3" r="0.65" fill="#00d4ff"/>
          <circle cx="20.5" cy="7.2" r="0.65" fill="#00d4ff"/>
          <circle cx="20.5" cy="16.8" r="0.65" fill="#00d4ff"/>
          <circle cx="12" cy="21.7" r="0.65" fill="#00d4ff"/>
          <circle cx="3.5" cy="16.8" r="0.65" fill="#00d4ff"/>
          <circle cx="3.5" cy="7.2" r="0.65" fill="#00d4ff"/>
        </svg>
        <span className="text-[#00d4ff] font-bold tracking-widest text-[15px] uppercase" style={{ letterSpacing: '0.2em' }}>Argus</span>
        <span className="text-[#5a6478] text-[10px] tracking-widest uppercase">Security Console</span>
      </div>
      <div className="flex-1 flex gap-16 px-6">
        <KPI label="Critical" value="3" color="text-[#ff4757]" />
        <KPI label="Warnings" value="7" color="text-[#ff6b35]" />
        <KPI label="Events/hr" value="142" color="text-[#00d4ff]" />
        <KPI label="Nodes" value="3/3" color="text-[#00ff88]" />
        <KPI label="MTTR" value="28s" color="text-[#00d4ff]" />
      </div>
      <div className="flex items-center gap-2">
        <div className="w-2 h-2 rounded-full bg-[#00ff88] shadow-[0_0_6px_#00ff88] animate-pulse" />
        <Clock />
      </div>
    </div>
  )
}

function KPI({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="flex flex-col items-center gap-0">
      <span className={`text-[18px] font-bold ${color}`}>{value}</span>
      <span className="text-[10px] text-[#5a6478] uppercase tracking-wider">{label}</span>
    </div>
  )
}

function Clock() {
  const [time, setTime] = React.useState(new Date().toTimeString().slice(0, 8))
  React.useEffect(() => {
    const t = setInterval(() => setTime(new Date().toTimeString().slice(0, 8)), 1000)
    return () => clearInterval(t)
  }, [])
  return <span className="text-[11px] text-[#8892a4] font-mono">{time}</span>
}

function SidebarTooltip({ label, desc }: { label: string; desc: string }) {
  return (
    <div
      className="absolute left-full ml-2 top-1/2 -translate-y-1/2 z-50 pointer-events-none"
      style={{ whiteSpace: 'nowrap' }}
    >
      <div className="bg-[#0d1425] border border-[rgba(0,212,255,0.25)] rounded-lg px-3 py-2 shadow-xl"
        style={{ boxShadow: '0 8px 32px rgba(0,0,0,0.7), 0 0 0 1px rgba(0,212,255,0.08)' }}>
        <div className="text-[12px] font-semibold text-[#e2e8f0] mb-0.5">{label}</div>
        <div className="text-[10px] text-[#5a6478] max-w-[200px]" style={{ whiteSpace: 'normal' }}>{desc}</div>
      </div>
      {/* Arrow */}
      <div className="absolute right-full top-1/2 -translate-y-1/2 -mr-px"
        style={{ width: 0, height: 0, borderTop: '5px solid transparent', borderBottom: '5px solid transparent', borderRight: '6px solid rgba(0,212,255,0.25)' }} />
    </div>
  )
}

function Sidebar() {
  const [hovered, setHovered] = React.useState<string | null>(null)
  return (
    <div className="w-12 bg-[#0a0f1e] border-r border-[rgba(99,179,237,0.12)] flex flex-col items-center py-3 gap-1 flex-shrink-0" style={{ position: 'relative', zIndex: 40 }}>
      {NAV_ITEMS.map(({ path, icon: Icon, label, desc }) => (
        <div key={path} className="relative" onMouseEnter={() => setHovered(path)} onMouseLeave={() => setHovered(null)}>
          <NavLink
            to={path}
            end={path === '/'}
            className={({ isActive }) =>
              `w-9 h-9 rounded-lg flex items-center justify-center transition-all cursor-pointer
              ${isActive
                ? 'bg-[rgba(0,212,255,0.1)] text-[#00d4ff] border border-[rgba(0,212,255,0.25)]'
                : 'text-[#5a6478] hover:bg-[#111827] hover:text-[#00d4ff]'
              }`
            }
          >
            <Icon size={14} />
          </NavLink>
          {hovered === path && <SidebarTooltip label={label} desc={desc} />}
        </div>
      ))}
    </div>
  )
}
