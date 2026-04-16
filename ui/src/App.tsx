// Argus Console — Command & Control UI
// Copyright (c) 2026 Kaushikkumaran
// Module 5 — implementation in progress
//
// Tech stack: React + TypeScript + Tailwind + shadcn/ui
// Design: cyber-themed dark mode threat console
// Views: Command Center, Threat Feed, Cluster Map,
//        Security Posture, Incident History, Agent Chat

export default function App() {
  return (
    <div className="min-h-screen bg-[#0a0e1a] text-slate-200 font-mono">
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="text-cyan-400 text-2xl font-bold tracking-widest mb-2">ARGUS</div>
          <div className="text-slate-500 text-xs tracking-widest uppercase">Security Console — initializing</div>
        </div>
      </div>
    </div>
  )
}
