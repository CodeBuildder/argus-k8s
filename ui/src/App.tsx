import React from 'react'
import { Routes, Route, NavLink } from 'react-router-dom'
import { AlertTriangle, CheckSquare, MessageSquare, Activity, Map, Shield } from 'lucide-react'
import ThreatFeed from './pages/ThreatFeed'
import ApprovalQueue from './pages/ApprovalQueue'
import AgentChat from './pages/AgentChat'
import CommandCenter from './pages/CommandCenter'
import ClusterMap from './pages/ClusterMap'
import SecurityPosture from './pages/SecurityPosture'

const NAV_ITEMS = [
  { path: '/', icon: Activity, label: 'Command Center', exact: true },
  { path: '/threats', icon: AlertTriangle, label: 'Threat Feed' },
  { path: '/approvals', icon: CheckSquare, label: 'Approvals' },
  { path: '/cluster', icon: Map, label: 'Cluster Map' },
  { path: '/posture', icon: Shield, label: 'Security Posture' },
  { path: '/chat', icon: MessageSquare, label: 'Agent Chat' },
]

export default function App() {
  return (
    <div className="flex flex-col h-screen bg-[#060912]">
      <TopBar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-auto">
          <Routes>
            <Route path="/" element={<CommandCenter />} />
            <Route path="/threats" element={<ThreatFeed />} />
            <Route path="/approvals" element={<ApprovalQueue />} />
            <Route path="/cluster" element={<ClusterMap />} />
            <Route path="/posture" element={<SecurityPosture />} />
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
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
          <polygon points="12,2 22,20 2,20" fill="none" stroke="#00d4ff" strokeWidth="1.5"/>
          <circle cx="12" cy="14" r="3" fill="none" stroke="#00d4ff" strokeWidth="1.2"/>
          <line x1="12" y1="7" x2="12" y2="11" stroke="#00d4ff" strokeWidth="1.2"/>
        </svg>
        <span className="text-[#00d4ff] font-bold tracking-widest text-[15px] uppercase">Argus</span>
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

function Sidebar() {
  return (
    <div className="w-12 bg-[#0a0f1e] border-r border-[rgba(99,179,237,0.12)] flex flex-col items-center py-3 gap-1 flex-shrink-0">
      {NAV_ITEMS.map(({ path, icon: Icon, label }) => (
        <NavLink
          key={path}
          to={path}
          end={path === '/'}
          title={label}
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
      ))}
    </div>
  )
}
