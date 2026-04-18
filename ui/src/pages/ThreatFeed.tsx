import React, { useState, useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'

const API = '/api'

const SEV_CONFIG: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  CRITICAL: { color: '#ff2d55', bg: 'rgba(255,45,85,0.08)', border: 'rgba(255,45,85,0.3)', dot: '#ff2d55' },
  HIGH:     { color: '#ff9f0a', bg: 'rgba(255,159,10,0.08)', border: 'rgba(255,159,10,0.3)', dot: '#ff9f0a' },
  MED:      { color: '#ffd700', bg: 'rgba(255,215,0,0.06)', border: 'rgba(255,215,0,0.25)', dot: '#ffd700' },
  LOW:      { color: '#8b949e', bg: 'rgba(139,148,158,0.06)', border: 'rgba(139,148,158,0.2)', dot: '#8b949e' },
}

const ACTION_CONFIG: Record<string, { color: string; label: string }> = {
  ISOLATE:        { color: '#ff2d55', label: '⊘ Isolated' },
  KILL:           { color: '#ff2d55', label: '✕ Killed' },
  NOTIFY:         { color: '#ff9f0a', label: '⚑ Notified' },
  HUMAN_REQUIRED: { color: '#bc8cff', label: '◎ Needs review' },
  LOG:            { color: '#8b949e', label: '▪ Logged' },
}

interface Incident {
  id: string
  ts: number
  rule: string
  priority: string
  severity: string
  pod: string
  namespace: string
  hostname: string
  assessment: string
  what_happened?: string[]
  blast_radius_bullets?: string[]
  action_steps?: string[]
  blast_radius: string
  recommended_action: string
  action_taken: string
  action_status: string
  confidence: number
  likely_false_positive: boolean
  mitre_tags: string[]
  enrichment_sources: string[]
  enrichment_duration_ms: number
}

const NODES = [
  { name: 'k3s-master', ip: '192.168.139.42' },
  { name: 'k3s-worker1', ip: '192.168.139.77' },
  { name: 'k3s-worker2', ip: '192.168.139.45' },
]

type PodStatus = 'threat' | 'risk' | 'safe' | 'isolated'
type NodeStatus = 'threat' | 'risk' | 'safe'

function PodStatusIcon({ status }: { status: PodStatus }) {
  if (status === 'threat') {
    return (
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
        <polygon points="7,1 13,13 1,13" stroke="#ff2d55" strokeWidth="1.2" fill="rgba(255,45,85,0.2)" />
        <line x1="7" y1="5" x2="7" y2="9" stroke="#ff2d55" strokeWidth="1.2" strokeLinecap="round" />
        <circle cx="7" cy="11" r="0.7" fill="#ff2d55" />
      </svg>
    )
  }

  if (status === 'risk') {
    return (
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
        <rect x="1" y="1" width="12" height="12" rx="2" stroke="#ff9f0a" strokeWidth="1.2" fill="rgba(255,159,10,0.1)" />
        <line x1="7" y1="4" x2="7" y2="8" stroke="#ff9f0a" strokeWidth="1.2" strokeLinecap="round" />
        <circle cx="7" cy="10.5" r="0.7" fill="#ff9f0a" />
      </svg>
    )
  }

  if (status === 'isolated') {
    return (
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
        <circle cx="7" cy="7" r="6" stroke="#4a5568" strokeWidth="1.2" fill="rgba(75,85,99,0.1)" />
        <line x1="4" y1="4" x2="10" y2="10" stroke="#4a5568" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="10" y1="4" x2="4" y2="10" stroke="#4a5568" strokeWidth="1.2" strokeLinecap="round" />
      </svg>
    )
  }

  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
      <circle cx="7" cy="7" r="6" stroke="#00ff9f" strokeWidth="1.2" fill="rgba(0,255,159,0.08)" />
      <polyline points="4,7 6.5,9.5 10,5" stroke="#00ff9f" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function NodeStatusIcon({ status }: { status: NodeStatus }) {
  if (status === 'threat') {
    return (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <path d="M8 2L14 13H2L8 2Z" stroke="#ff2d55" strokeWidth="1.2" fill="rgba(255,45,85,0.15)" />
        <line x1="8" y1="6" x2="8" y2="10" stroke="#ff2d55" strokeWidth="1.2" />
        <circle cx="8" cy="11.5" r="0.8" fill="#ff2d55" />
      </svg>
    )
  }

  if (status === 'risk') {
    return (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <rect x="2" y="2" width="12" height="12" rx="2" stroke="#ff9f0a" strokeWidth="1.2" fill="rgba(255,159,10,0.1)" />
        <line x1="8" y1="5" x2="8" y2="9" stroke="#ff9f0a" strokeWidth="1.2" />
        <circle cx="8" cy="11" r="0.8" fill="#ff9f0a" />
      </svg>
    )
  }

  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 2L13 5V9C13 11.5 10.5 13.5 8 14C5.5 13.5 3 11.5 3 9V5L8 2Z" stroke="#00ff9f" strokeWidth="1.2" fill="rgba(0,255,159,0.08)" />
      <polyline points="6,8 7.5,9.5 10,7" stroke="#00ff9f" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function ImpactDiagram({ incident }: { incident: any }) {
  const [scanPos, setScanPos] = React.useState(0)
  const [barsAnimated, setBarsAnimated] = React.useState(false)

  React.useEffect(() => {
    const t = setInterval(() => setScanPos(p => (p + 1) % 100), 30)
    return () => clearInterval(t)
  }, [])

  React.useEffect(() => {
    setBarsAnimated(false)
    const t = setTimeout(() => setBarsAnimated(true), 200)
    return () => clearTimeout(t)
  }, [incident.id])

  const threatNode = incident.hostname || 'k3s-worker1'
  const threatPod = incident.pod
  const threatNs = incident.namespace

  const riskBars = [
    { label: 'Data exposure', width: incident.severity === 'CRITICAL' ? 82 : incident.severity === 'HIGH' ? 60 : 35, color: '#ff2d55' },
    { label: 'Lateral movement', width: incident.severity === 'CRITICAL' ? 54 : incident.severity === 'HIGH' ? 40 : 20, color: '#ff9f0a' },
    { label: 'Service disruption', width: incident.severity === 'CRITICAL' ? 48 : incident.severity === 'HIGH' ? 35 : 15, color: '#ff9f0a' },
    { label: 'Node compromise', width: incident.severity === 'CRITICAL' ? 22 : 10, color: '#ffd700' },
    { label: 'Cluster takeover', width: incident.severity === 'CRITICAL' ? 12 : 5, color: '#4a5568' },
  ]

  const getNodeStatus = (nodeName: string) => {
    if (nodeName === threatNode) return 'threat'
    if (incident.severity === 'CRITICAL') return 'risk'
    return 'safe'
  }

  const nodeColors = { threat: '#ff2d55', risk: '#ff9f0a', safe: '#00ff9f' }
  const nodeBgs = { threat: 'rgba(255,45,85,0.12)', risk: 'rgba(255,159,10,0.08)', safe: 'rgba(0,255,159,0.05)' }
  const nodeBorders = { threat: 'rgba(255,45,85,0.4)', risk: 'rgba(255,159,10,0.3)', safe: 'rgba(0,255,159,0.2)' }
  const nodeLabels = { threat: 'THREAT', risk: 'AT RISK', safe: 'CLEAN' }

  return (
    <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.1)', borderRadius: '10px', padding: '12px', marginBottom: '10px', position: 'relative', overflow: 'hidden' }}>
      <div style={{ position: 'absolute', left: 0, right: 0, height: '1px', background: 'linear-gradient(90deg,transparent,rgba(0,255,159,0.4),transparent)', top: `${scanPos}%`, transition: 'top 0.03s linear', pointerEvents: 'none' }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', paddingBottom: '8px', borderBottom: '1px solid rgba(0,255,159,0.06)' }}>
        <span style={{ fontSize: '8px', background: 'rgba(0,255,159,0.08)', border: '1px solid rgba(0,255,159,0.2)', color: '#00ff9f', padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>argus-k8s</span>
        <span style={{ fontSize: '11px', fontWeight: 600, color: '#f0f6fc' }}>Production cluster</span>
        <span style={{ fontSize: '8px', color: '#4a5568', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>3 nodes · 4 namespaces</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '10px' }}>
        {NODES.map(node => {
          const status = getNodeStatus(node.name) as 'threat' | 'risk' | 'safe'
          const isThreat = status === 'threat'
          const isRisk = status === 'risk'

          const threatPods = isThreat && threatPod ? [
            { name: threatPod, status: 'threat' as PodStatus, ns: threatNs },
            { name: 'api-gateway (isolated)', status: 'isolated' as PodStatus, ns: null },
          ] : []

          const riskPods = isRisk ? [
            { name: 'postgres-0', status: 'risk' as PodStatus, ns: 'prod' },
            { name: 'auth-service', status: 'risk' as PodStatus, ns: 'prod' },
            { name: 'prometheus', status: 'safe' as PodStatus, ns: 'monitoring' },
          ] : []

          const safePods = !isThreat && !isRisk ? [
            { name: 'argus-agent', status: 'safe' as PodStatus, ns: 'argus-system' },
            { name: 'kyverno', status: 'safe' as PodStatus, ns: 'kyverno' },
            { name: 'cilium', status: 'safe' as PodStatus, ns: 'kube-system' },
          ] : []

          const allPods = [...threatPods, ...riskPods, ...safePods]

          return (
            <div key={node.name} style={{ background: nodeBgs[status], border: `1px solid ${nodeBorders[status]}`, borderRadius: '7px', padding: '8px 10px', animation: 'fadeInUp 0.2s ease-out both' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
                <div style={{ width: '18px', height: '18px', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, animation: isThreat ? 'pulse 1.5s infinite' : 'none' }}>
                  <NodeStatusIcon status={status} />
                </div>
                <span style={{ fontSize: '10px', fontWeight: 700, color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>{node.name}</span>
                <span style={{ fontSize: '8px', color: nodeColors[status], fontFamily: 'JetBrains Mono, monospace', marginLeft: '2px' }}>{nodeLabels[status]}</span>
                <span style={{ fontSize: '8px', color: '#4a5568', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>{node.ip}</span>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                {allPods.map((pod, i) => (
                  <span key={`${pod.name}-${i}`} style={{
                    fontSize: '9px',
                    padding: '2px 7px',
                    borderRadius: '4px',
                    fontFamily: 'JetBrains Mono, monospace',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    background: pod.status === 'threat' ? 'rgba(255,45,85,0.12)' :
                               pod.status === 'risk' ? 'rgba(255,159,10,0.08)' :
                               pod.status === 'isolated' ? 'rgba(75,85,99,0.15)' :
                               'rgba(0,255,159,0.05)',
                    border: `1px solid ${pod.status === 'threat' ? 'rgba(255,45,85,0.35)' :
                            pod.status === 'risk' ? 'rgba(255,159,10,0.25)' :
                            pod.status === 'isolated' ? 'rgba(75,85,99,0.3)' :
                            'rgba(0,255,159,0.15)'}`,
                    color: pod.status === 'threat' ? '#ff2d55' :
                           pod.status === 'risk' ? '#ff9f0a' :
                           pod.status === 'isolated' ? '#4a5568' : '#00ff9f',
                  }}>
                    <PodStatusIcon status={pod.status} />
                    {pod.name}
                    {pod.ns && <span style={{ fontSize: '7px', padding: '0 3px', background: 'rgba(88,166,255,0.12)', borderRadius: '2px', color: '#58a6ff' }}>{pod.ns}</span>}
                  </span>
                ))}
              </div>
            </div>
          )
        })}
      </div>

      <div style={{ borderTop: '1px solid rgba(0,255,159,0.05)', paddingTop: '8px' }}>
        {riskBars.map(({ label, width, color }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span style={{ fontSize: '8px', color: '#6b7280', width: '110px', flexShrink: 0, fontFamily: 'JetBrains Mono, monospace' }}>{label}</span>
            <div style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.04)', borderRadius: '2px', overflow: 'hidden' }}>
              <div style={{ height: '100%', borderRadius: '2px', background: color, width: barsAnimated ? `${width}%` : '0%', transition: 'width 1.2s ease-out' }} />
            </div>
            <span style={{ fontSize: '8px', fontWeight: 700, color, width: '28px', textAlign: 'right', fontFamily: 'JetBrains Mono, monospace' }}>{width}%</span>
          </div>
        ))}
      </div>

      <style>{`@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(255,45,85,0.5)}50%{box-shadow:0 0 0 4px rgba(255,45,85,0)}}`}</style>
    </div>
  )
}

// ─── Inline Incident Chat ─────────────────────────────────────────────────────

interface ChatMsg { role: 'user' | 'assistant'; content: string }

function renderMsg(text: string) {
  return text.split('\n').map((line, i) => {
    // Heading
    if (line.startsWith('## ')) {
      return <div key={i} style={{ fontSize: '12px', fontWeight: 700, color: '#e6edf3', marginTop: i > 0 ? '10px' : 0, marginBottom: '4px', letterSpacing: '-0.01em' }}>{line.slice(3)}</div>
    }
    // Bold section header (standalone **text**)
    if (/^\*\*(.+)\*\*$/.test(line.trim())) {
      return <div key={i} style={{ fontSize: '11px', fontWeight: 700, color: '#00d4ff', marginTop: i > 0 ? '10px' : 0, marginBottom: '3px', letterSpacing: '0.02em' }}>{line.trim().slice(2, -2)}</div>
    }
    // Bullet
    if (line.startsWith('- ')) {
      return (
        <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '3px', alignItems: 'flex-start' }}>
          <span style={{ color: '#00d4ff', fontSize: '10px', marginTop: '3px', flexShrink: 0 }}>▸</span>
          <span style={{ lineHeight: 1.6 }}>{parseBold(line.slice(2))}</span>
        </div>
      )
    }
    // Numbered list
    if (/^\d+\. /.test(line)) {
      const num = line.match(/^\d+/)?.[0]
      return (
        <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '3px', alignItems: 'flex-start' }}>
          <span style={{ color: '#58a6ff', fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0, minWidth: '14px', marginTop: '2px' }}>{num}.</span>
          <span style={{ lineHeight: 1.6 }}>{parseBold(line.replace(/^\d+\. /, ''))}</span>
        </div>
      )
    }
    // Empty line → spacing
    if (!line.trim()) return <div key={i} style={{ height: '6px' }} />
    // Normal paragraph
    return <div key={i} style={{ marginBottom: '2px', lineHeight: 1.65 }}>{parseBold(line)}</div>
  })
}

function parseBold(text: string): React.ReactNode {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/)
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i} style={{ color: '#e6edf3', fontWeight: 600 }}>{part.slice(2, -2)}</strong>
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={i} style={{ background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', borderRadius: '3px', padding: '1px 5px', fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: '#00d4ff' }}>{part.slice(1, -1)}</code>
    }
    return part
  })
}

const MOCK_AI_RESPONSE = `Here's what I'd prioritize based on this incident:

**Immediate (next 5 min)**
The memfd_create syscall is a classic fileless execution technique — the attacker is running code entirely in memory to avoid detection by file-based scanners. Since the pod is still running, the malicious process may still be active.

1. Run \`crictl inspect <container-id>\` to check the live process list before it disappears
2. Capture network flows via Hubble — check for any outbound C2 connections

**Short-term (next 30 min)**
- Treat the node as suspect until you can correlate whether runc itself was exploited or an application inside the container spawned this
- If isolation hasn't fired yet, apply a CiliumNetworkPolicy deny-all egress now

**Key risk to watch**
If the attacker already exfiltrated env vars (common next step after memfd_create), rotate all secrets mounted into this pod — especially service account tokens and database credentials.`

function IncidentChat({ incident }: { incident: Incident }) {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState<ChatMsg[]>([])
  const [input, setInput] = useState('')
  const [streaming, setStreaming] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const seededRef = useRef<string | null>(null)

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [messages])

  useEffect(() => {
    setMessages([])
    setInput('')
    setOpen(false)
    seededRef.current = null
  }, [incident.id])

  // Clean up empty assistant bubble if streaming ended with no content
  useEffect(() => {
    if (!streaming) {
      setMessages(prev => {
        const last = prev[prev.length - 1]
        if (last?.role === 'assistant' && last.content === '') return prev.slice(0, -1)
        return prev
      })
    }
  }, [streaming])

  const streamMock = (text: string) => {
    let idx = 0
    const tick = () => {
      const chunk = text.slice(idx, idx + 14)
      idx += 14
      setMessages(prev => {
        const msgs = [...prev]
        const last = msgs[msgs.length - 1]
        if (last?.role === 'assistant') msgs[msgs.length - 1] = { ...last, content: last.content + chunk }
        return msgs
      })
      if (idx < text.length) setTimeout(tick, 16)
      else setStreaming(false)
    }
    setTimeout(tick, 120)
  }

  const send = async (text: string, history: ChatMsg[] = messages) => {
    const q = text.trim()
    if (!q || streaming) return
    setInput('')
    const userMsg: ChatMsg = { role: 'user', content: q }
    setMessages(prev => [...prev, userMsg, { role: 'assistant', content: '' }])
    setStreaming(true)

    let gotContent = false
    try {
      const res = await fetch(`${API}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: q, history: history.map(m => ({ role: m.role, content: m.content })) }),
      })
      if (!res.ok || !res.body) throw new Error()
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n'); buf = lines.pop() ?? ''
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          try {
            const data = JSON.parse(line.slice(6).trim())
            if (data.type === 'text') {
              gotContent = true
              setMessages(prev => {
                const msgs = [...prev]
                const last = msgs[msgs.length - 1]
                if (last?.role === 'assistant') msgs[msgs.length - 1] = { ...last, content: last.content + data.text }
                return msgs
              })
            } else if (data.type === 'done') {
              setStreaming(false)
            } else if (data.type === 'error') {
              setStreaming(false)
            }
          } catch { /* ignore */ }
        }
      }
    } catch { /* backend offline */ }

    if (!gotContent) streamMock(MOCK_AI_RESPONSE)
    else setStreaming(false)
  }

  const openAndSeed = () => {
    setOpen(true)
    setTimeout(() => inputRef.current?.focus(), 320)
    if (seededRef.current === incident.id) return
    seededRef.current = incident.id
    const steps = (incident as any).action_steps?.join('; ') || ''
    const seed = `Investigate incident "${incident.rule}" on ${incident.pod || 'host'} in namespace ${incident.namespace}. Assessment: ${incident.assessment}. Blast radius: ${incident.blast_radius}. ${steps ? `Recommended steps: ${steps}.` : ''} What should I prioritize?`
    send(seed, [])
  }

  return (
    <div style={{ marginTop: '12px' }}>
      <button
        onClick={() => open ? setOpen(false) : openAndSeed()}
        style={{
          width: '100%', padding: '9px 14px', borderRadius: '8px', cursor: 'pointer',
          background: open ? 'rgba(0,212,255,0.1)' : 'rgba(0,212,255,0.05)',
          border: `1px solid ${open ? 'rgba(0,212,255,0.35)' : 'rgba(0,212,255,0.18)'}`,
          color: '#00d4ff', fontSize: '10px', fontFamily: 'JetBrains Mono, monospace',
          fontWeight: 700, letterSpacing: '0.5px', display: 'flex', alignItems: 'center', gap: '8px',
          transition: 'all 0.2s',
        }}
        onMouseEnter={e => { if (!open) { e.currentTarget.style.background = 'rgba(0,212,255,0.1)'; e.currentTarget.style.borderColor = 'rgba(0,212,255,0.35)' } }}
        onMouseLeave={e => { if (!open) { e.currentTarget.style.background = 'rgba(0,212,255,0.05)'; e.currentTarget.style.borderColor = 'rgba(0,212,255,0.18)' } }}
      >
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="#00d4ff" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
          <path d="M10 7.5C10 8.05 9.55 8.5 9 8.5H3.5L1.5 10.5V3C1.5 2.45 1.95 2 2.5 2H9C9.55 2 10 2.45 10 3V7.5Z"/>
        </svg>
        {open ? 'Close AI chat' : 'Ask Argus AI about this incident'}
        <span style={{ marginLeft: 'auto', fontSize: '8px', color: '#00d4ff60' }}>claude-sonnet-4-6</span>
        <span style={{ fontSize: '9px', color: '#00d4ff80', transition: 'transform 0.2s', transform: open ? 'rotate(180deg)' : 'rotate(0deg)', display: 'inline-block' }}>▾</span>
      </button>

      {/* Animated expand — grid-template-rows trick animates to real height, no max-height timing issues */}
      <div style={{
        display: 'grid',
        gridTemplateRows: open ? '1fr' : '0fr',
        transition: 'grid-template-rows 0.38s cubic-bezier(0.4,0,0.2,1)',
        marginTop: open ? '8px' : '0px',
      } as React.CSSProperties}>
        <div style={{ overflow: 'hidden', opacity: open ? 1 : 0, transition: 'opacity 0.25s ease-out' }}>
        <div style={{ background: '#070c12', border: '1px solid rgba(0,212,255,0.14)', borderRadius: '10px', overflow: 'hidden' }}>
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '9px 14px', borderBottom: '1px solid rgba(0,212,255,0.07)', background: 'rgba(0,212,255,0.03)' }}>
            <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00d4ff', boxShadow: '0 0 6px #00d4ff', animation: streaming ? 'glowpulse 0.8s infinite' : 'glowpulse 2.5s infinite', flexShrink: 0 }} />
            <span style={{ fontSize: '9px', color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, letterSpacing: '0.5px' }}>
              ARGUS AI {streaming ? '· thinking...' : '· incident context loaded'}
            </span>
          </div>

          {/* Messages */}
          <div ref={scrollRef} style={{ maxHeight: '290px', overflowY: 'auto', padding: '14px 14px 8px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {messages.map((msg, i) => (
              <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: msg.role === 'user' ? 'flex-end' : 'flex-start' }}>
                <div style={{ fontSize: '8px', color: msg.role === 'user' ? '#00d4ff60' : '#4a5568', fontFamily: 'JetBrains Mono, monospace', marginBottom: '3px' }}>
                  {msg.role === 'user' ? 'you' : '⬡ argus'}
                </div>
                <div style={{
                  maxWidth: '92%', padding: '10px 13px',
                  borderRadius: msg.role === 'user' ? '12px 12px 3px 12px' : '12px 12px 12px 3px',
                  background: msg.role === 'user' ? 'rgba(0,212,255,0.08)' : 'rgba(255,255,255,0.035)',
                  border: msg.role === 'user' ? '1px solid rgba(0,212,255,0.18)' : '1px solid rgba(255,255,255,0.07)',
                  fontSize: '12px', color: msg.role === 'user' ? '#a8d8e8' : '#c9d1d9',
                  fontFamily: "'Inter', -apple-system, sans-serif",
                  letterSpacing: '-0.005em',
                }}>
                  {msg.content === '' && streaming && i === messages.length - 1
                    ? <span style={{ color: '#00d4ff', animation: 'glowpulse 0.8s infinite' }}>▋</span>
                    : msg.role === 'assistant'
                      ? renderMsg(msg.content)
                      : <span style={{ lineHeight: 1.6 }}>{msg.content}</span>
                  }
                  {msg.role === 'assistant' && streaming && i === messages.length - 1 && msg.content !== '' && (
                    <span style={{ color: '#00d4ff', marginLeft: '2px' }}>▋</span>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* Input */}
          <div style={{ padding: '10px 14px 12px', borderTop: '1px solid rgba(0,212,255,0.07)', display: 'flex', gap: '8px', alignItems: 'center' }}>
            <input
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(input) } }}
              placeholder="Ask a follow-up question..."
              disabled={streaming}
              style={{
                flex: 1, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(0,212,255,0.14)',
                borderRadius: '8px', color: '#e6edf3', fontSize: '11px', padding: '8px 12px',
                fontFamily: 'Inter, sans-serif', outline: 'none', transition: 'border-color 0.15s',
              }}
              onFocus={e => { e.currentTarget.style.borderColor = 'rgba(0,212,255,0.35)' }}
              onBlur={e => { e.currentTarget.style.borderColor = 'rgba(0,212,255,0.14)' }}
            />
            <button
              onClick={() => send(input)}
              disabled={streaming || !input.trim()}
              style={{
                width: '34px', height: '34px', borderRadius: '8px', flexShrink: 0,
                border: '1px solid rgba(0,212,255,0.25)',
                background: streaming || !input.trim() ? 'rgba(0,0,0,0.2)' : 'rgba(0,212,255,0.12)',
                color: streaming || !input.trim() ? '#3d4a5f' : '#00d4ff',
                cursor: streaming || !input.trim() ? 'not-allowed' : 'pointer',
                fontSize: '14px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                transition: 'all 0.15s',
              }}
            >↑</button>
          </div>
        </div>
        </div>
      </div>
    </div>
  )
}

export default function ThreatFeed() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [selected, setSelected] = useState<Incident | null>(null)
  const [filter, setFilter] = useState<string>('ALL')
  const [nsFilter, setNsFilter] = useState<string>('ALL')
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = React.useState<string>('')
  const prevCount = useRef(0)
  const newIds = useRef<Set<string>>(new Set())
  const rowRefs = useRef<Record<string, HTMLDivElement | null>>({})
  const deepLinkId = searchParams.get('id')

  const fetchIncidents = async () => {
    try {
      const r = await fetch(`${API}/incidents?limit=100`)
      if (!r.ok) return
      const data = await r.json()
      const fresh = data.incidents as Incident[]
      if (fresh.length > prevCount.current) {
        const newOnes = fresh.slice(0, fresh.length - prevCount.current)
        newOnes.forEach(i => newIds.current.add(i.id))
        setTimeout(() => {
          newOnes.forEach(i => newIds.current.delete(i.id))
        }, 2000)
      }
      prevCount.current = fresh.length
      setIncidents(fresh)
      setLastUpdated(new Date().toTimeString().slice(0, 8))
      setLoading(false)
    } catch {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchIncidents()
    const t = setInterval(fetchIncidents, 3000)
    return () => clearInterval(t)
  }, [])

  // Auto-select and scroll to incident when navigated from pipeline particle click
  useEffect(() => {
    if (!deepLinkId || !incidents.length) return
    const match = incidents.find(i => i.id === deepLinkId)
    if (match) {
      setSelected(match)
      setTimeout(() => {
        rowRefs.current[deepLinkId]?.scrollIntoView({ behavior: 'smooth', block: 'center' })
      }, 80)
      setSearchParams({}, { replace: true })
    }
  }, [deepLinkId, incidents])

  const namespaces = ['ALL', ...Array.from(new Set(incidents.map(i => i.namespace).filter(Boolean)))]
  const filtered = incidents.filter(i => {
    if (filter !== 'ALL' && i.severity !== filter) return false
    if (nsFilter !== 'ALL' && i.namespace !== nsFilter) return false
    return true
  })

  const fmt = (ts: number) => {
    const d = new Date(ts * 1000)
    const diff = Math.floor((Date.now() - ts * 1000) / 1000)
    if (diff < 60) return `${diff}s ago`
    if (diff < 3600) return `${Math.floor(diff/60)}m ago`
    return d.toTimeString().slice(0,5)
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 440px' : '1fr', height: '100%', overflow: 'hidden' }}>
      <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ padding: '12px 18px', borderBottom: '1px solid rgba(0,255,159,0.1)', display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>
          <span style={{ fontSize: '9px', color: '#8b949e', textTransform: 'uppercase', letterSpacing: '2px' }}>
            ⚡ Live threat feed
          </span>
          <span style={{ fontSize: '9px', color: '#4a5568', marginLeft: 'auto' }}>
            {filtered.length} incidents
          </span>
          {(['ALL','CRITICAL','HIGH','MED','LOW'] as const).map(s => (
            <button key={s} onClick={() => setFilter(s)} style={{
              fontSize: '9px', padding: '3px 10px', borderRadius: '10px', cursor: 'pointer', fontWeight: 700,
              background: filter === s ? (SEV_CONFIG[s]?.bg || 'rgba(0,255,159,0.1)') : 'transparent',
              border: `1px solid ${filter === s ? (SEV_CONFIG[s]?.border || 'rgba(0,255,159,0.2)') : 'rgba(75,85,99,0.3)'}`,
              color: filter === s ? (SEV_CONFIG[s]?.color || '#00ff9f') : '#4a5568',
            }}>{s}</button>
          ))}
          <select value={nsFilter} onChange={e => setNsFilter(e.target.value)} style={{
            fontSize: '8px', background: '#161b22', border: '1px solid rgba(0,255,159,0.1)',
            color: '#8b949e', padding: '2px 6px', borderRadius: '4px', cursor: 'pointer',
          }}>
            {namespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
          </select>
          <button
            onClick={() => { fetchIncidents() }}
            title="Refresh feed"
            style={{
              background: 'transparent',
              border: '1px solid rgba(0,255,159,0.2)',
              borderRadius: '6px',
              color: '#00ff9f',
              cursor: 'pointer',
              padding: '3px 10px',
              fontSize: '10px',
              fontFamily: 'JetBrains Mono, monospace',
              display: 'flex',
              alignItems: 'center',
              gap: '5px',
              transition: 'all 0.15s',
            }}
            onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0,255,159,0.08)')}
            onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
          >
            ↻ Refresh
          </button>
          <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>
            {lastUpdated ? `updated ${lastUpdated}` : ''}
          </span>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '18px 18px 48px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {loading && (
            <div style={{ color: '#4a5568', fontSize: '10px', textAlign: 'center', padding: '20px' }}>
              Connecting to agent...
            </div>
          )}
          {!loading && filtered.length === 0 && (
            <div style={{ color: '#4a5568', fontSize: '10px', textAlign: 'center', padding: '20px' }}>
              No incidents. Cluster is clean.
            </div>
          )}
          {filtered.map(inc => {
            const sev = SEV_CONFIG[inc.severity] || SEV_CONFIG.LOW
            const act = ACTION_CONFIG[inc.action_taken] || ACTION_CONFIG.LOG
            const isNew = newIds.current.has(inc.id)
            return (
              <div key={inc.id} ref={el => { rowRefs.current[inc.id] = el }} onClick={() => setSelected(selected?.id === inc.id ? null : inc)}
                style={{
                  borderRadius: '6px', border: `1px solid ${selected?.id === inc.id ? 'rgba(0,255,159,0.3)' : sev.border}`,
                  background: selected?.id === inc.id ? '#1c2433' : inc.severity === 'CRITICAL' ? 'rgba(255,45,85,0.05)' : '#1a2233',
                  padding: '14px 20px 32px', minHeight: '96px', cursor: 'pointer', position: 'relative', overflow: 'hidden',
                  fontFamily: 'Inter, sans-serif',
                  transition: 'all 0.12s',
                  animation: isNew ? 'slideIn 0.3s ease-out' : undefined,
                }}
              >
                <div style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: '4px', background: sev.dot, borderRadius: '3px 0 0 3px' }} />
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ fontSize: '10px', fontWeight: 700, padding: '3px 8px', borderRadius: '3px', background: sev.bg, color: sev.color, border: `1px solid ${sev.border}`, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      ● {inc.severity}
                    </span>
                    <span style={{ fontSize: '10px', color: `${act.color}`, background: `${act.color}22`, padding: '2px 8px', borderRadius: '3px', border: `1px solid ${act.color}44` }}>
                      {act.label}
                    </span>
                  </div>
                  <span style={{ fontSize: '10px', color: '#6b7280', fontFamily: 'JetBrains Mono, monospace' }}>{fmt(inc.ts)} · {inc.hostname}</span>
                </div>
                <div style={{ fontSize: '14px', fontWeight: 600, color: '#f0f6fc', fontFamily: 'Inter, sans-serif', letterSpacing: '-0.01em', marginBottom: '10px', lineHeight: 1.3 }}>{inc.rule}</div>
                <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
                  {inc.namespace && <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'rgba(88,166,255,0.8)', background: 'rgba(88,166,255,0.08)', padding: '2px 7px', borderRadius: '3px', border: '1px solid rgba(88,166,255,0.2)' }}>{inc.namespace}</span>}
                  {inc.pod && <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: '#4a5568', background: '#0d1117', padding: '2px 7px', borderRadius: '3px', border: '1px solid rgba(0,255,159,0.08)' }}>{inc.pod}</span>}
                  {inc.mitre_tags?.map(t => <span key={t} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'rgba(188,140,255,0.8)', background: 'rgba(188,140,255,0.06)', padding: '2px 7px', borderRadius: '3px', border: '1px solid rgba(188,140,255,0.2)' }}>{t}</span>)}
                  <span style={{ fontSize: '10px', color: '#4a5568', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>
                    {Math.round(inc.confidence * 100)}% confidence
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {selected && (
        <div key={selected.id} style={{ borderLeft: '1px solid rgba(0,255,159,0.1)', display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#0d1117', animation: 'slideInRight 0.2s ease-out' }}>
          <div style={{ padding: '14px 20px', borderBottom: '1px solid rgba(0,255,159,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
            <span style={{ fontSize: '11px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px' }}>Incident detail</span>
            <button onClick={() => setSelected(null)} style={{ fontSize: '12px', color: '#4a5568', background: 'transparent', border: 'none', cursor: 'pointer' }}>✕</button>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: '18px 20px', fontFamily: 'Inter, sans-serif' }}>
            <DetailSection title="Alert" animationDelay="0.05s">
              <Row label="Rule" value={selected.rule} />
              <Row label="Priority" value={selected.priority} />
              <Row label="Severity" value={selected.severity} color={SEV_CONFIG[selected.severity]?.color} />
              <Row label="Hostname" value={selected.hostname} />
            </DetailSection>
            <DetailSection title="Target" animationDelay="0.1s">
              <Row label="Pod" value={selected.pod || '— host level'} color={!selected.pod ? '#4a5568' : undefined} />
              <Row label="Namespace" value={selected.namespace || '— host level'} color={!selected.namespace ? '#4a5568' : undefined} />
              <Row label="MITRE" value={selected.mitre_tags?.join(', ') || 'none'} />
            </DetailSection>
            <div style={{ marginBottom: '14px', animation: 'fadeInUp 0.2s ease-out both', animationDelay: '0.15s' }}>
              <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '10px', paddingBottom: '4px', borderBottom: '1px solid rgba(0,255,159,0.08)', fontFamily: 'JetBrains Mono, monospace' }}>AI Assessment</div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#00ff9f', boxShadow: '0 0 6px #00ff9f', flexShrink: 0, animation: 'glowpulse 2s infinite' }} />
                <span style={{ fontSize: '9px', color: '#00ff9f', fontFamily: 'JetBrains Mono, monospace' }}>ARGUS AI · claude-sonnet-4-6</span>
                <div style={{ flex: 1, height: '1px', background: 'rgba(0,255,159,0.1)' }} />
                <span style={{ fontSize: '9px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>{Math.round(selected.confidence * 100)}% confidence</span>
              </div>

              <div style={{ background: 'rgba(255,45,85,0.05)', border: '1px solid rgba(255,45,85,0.12)', borderRadius: '8px', padding: '10px 12px', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '7px' }}>
                  <span style={{ fontSize: '9px', fontWeight: 700, color: '#ff2d55', textTransform: 'uppercase', letterSpacing: '1px', fontFamily: 'JetBrains Mono, monospace' }}>What happened</span>
                </div>
                {((selected as any).what_happened?.length > 0 ? (selected as any).what_happened : [selected.assessment]).map((bullet: string, i: number) => (
                  <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '5px', alignItems: 'flex-start' }}>
                    <span style={{ color: '#ff2d55', fontSize: '10px', marginTop: '2px', flexShrink: 0 }}>▸</span>
                    <span style={{ fontSize: '11px', color: '#d1d5db', lineHeight: 1.6, fontFamily: 'Inter, sans-serif' }}>{bullet}</span>
                  </div>
                ))}
              </div>

              <ImpactDiagram incident={selected} />

              <div style={{ background: 'rgba(88,166,255,0.04)', border: '1px solid rgba(88,166,255,0.12)', borderRadius: '8px', padding: '10px 12px', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '7px' }}>
                  <span style={{ fontSize: '9px', fontWeight: 700, color: '#58a6ff', textTransform: 'uppercase', letterSpacing: '1px', fontFamily: 'JetBrains Mono, monospace' }}>Recommended actions</span>
                </div>
                {((selected as any).action_steps?.length > 0 ? (selected as any).action_steps : [`Take action: ${selected.recommended_action}`]).map((step: string, i: number) => (
                  <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '7px', alignItems: 'flex-start' }}>
                    <div style={{ width: '18px', height: '18px', borderRadius: '50%', background: 'rgba(88,166,255,0.12)', border: '1px solid rgba(88,166,255,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '8px', color: '#58a6ff', fontWeight: 700, flexShrink: 0, marginTop: '1px', fontFamily: 'JetBrains Mono, monospace' }}>{i + 1}</div>
                    <span style={{ fontSize: '11px', color: '#d1d5db', lineHeight: 1.6, fontFamily: 'Inter, sans-serif' }}>{step}</span>
                  </div>
                ))}
                <IncidentChat incident={selected} />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
                <div style={{ background: selected.likely_false_positive ? 'rgba(0,255,159,0.06)' : 'rgba(255,45,85,0.06)', border: `1px solid ${selected.likely_false_positive ? 'rgba(0,255,159,0.2)' : 'rgba(255,45,85,0.2)'}`, borderRadius: '8px', padding: '10px', textAlign: 'center' }}>
                  <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '5px', fontFamily: 'Inter, sans-serif', fontWeight: 600 }}>False positive</div>
                  <div style={{ fontSize: '20px', fontWeight: 700, color: selected.likely_false_positive ? '#00ff9f' : '#ff2d55', fontFamily: 'Inter, sans-serif' }}>{selected.likely_false_positive ? 'Yes' : 'No'}</div>
                </div>
                <div style={{ background: 'rgba(88,166,255,0.06)', border: '1px solid rgba(88,166,255,0.2)', borderRadius: '8px', padding: '10px', textAlign: 'center' }}>
                  <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '5px', fontFamily: 'Inter, sans-serif', fontWeight: 600 }}>Confidence</div>
                  <div style={{ fontSize: '20px', fontWeight: 700, color: '#58a6ff', fontFamily: 'Inter, sans-serif' }}>{Math.round(selected.confidence * 100)}%</div>
                </div>
              </div>
              <style>{`@keyframes glowpulse{0%,100%{box-shadow:0 0 4px #00ff9f}50%{box-shadow:0 0 10px #00ff9f,0 0 20px rgba(0,255,159,0.3)}}`}</style>
            </div>
            <div style={{ marginBottom: '14px', animation: 'fadeInUp 0.2s ease-out both', animationDelay: '0.2s' }}>
              <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '8px', paddingBottom: '4px', borderBottom: '1px solid rgba(0,255,159,0.08)', fontFamily: 'JetBrains Mono, monospace' }}>Response</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 10px', background: `${(ACTION_CONFIG[selected.action_taken] || ACTION_CONFIG.LOG).color}11`, border: `1px solid ${(ACTION_CONFIG[selected.action_taken] || ACTION_CONFIG.LOG).color}33`, borderRadius: '7px' }}>
                  <div>
                    <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '3px', fontFamily: 'Inter, sans-serif' }}>Action taken</div>
                    <div style={{ fontSize: '14px', fontWeight: 700, color: (ACTION_CONFIG[selected.action_taken] || ACTION_CONFIG.LOG).color, fontFamily: 'Inter, sans-serif', letterSpacing: '-0.01em' }}>{(ACTION_CONFIG[selected.action_taken] || ACTION_CONFIG.LOG).label}</div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '3px', fontFamily: 'Inter, sans-serif' }}>Status</div>
                    <div style={{ fontSize: '11px', fontWeight: 600, color: selected.action_status === 'completed' ? '#00ff9f' : selected.action_status === 'failed' ? '#ff2d55' : '#ff9f0a', fontFamily: 'JetBrains Mono, monospace' }}>● {selected.action_status}</div>
                  </div>
                </div>
              </div>
            </div>

            <div style={{ marginBottom: '14px', animation: 'fadeInUp 0.2s ease-out both', animationDelay: '0.25s' }}>
              <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '8px', paddingBottom: '4px', borderBottom: '1px solid rgba(0,255,159,0.08)', fontFamily: 'JetBrains Mono, monospace' }}>Enrichment</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginBottom: '8px' }}>
                {(['kubernetes', 'loki', 'hubble', 'kyverno', 'trivy'] as const).map(src => {
                  const active = selected.enrichment_sources?.includes(src)
                  return (
                    <div key={src} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '5px 8px', background: active ? 'rgba(0,255,159,0.04)' : 'rgba(255,255,255,0.02)', border: `1px solid ${active ? 'rgba(0,255,159,0.15)' : 'rgba(255,255,255,0.04)'}`, borderRadius: '5px' }}>
                      <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: active ? '#00ff9f' : '#1f2937', border: `1px solid ${active ? 'rgba(0,255,159,0.5)' : 'rgba(255,255,255,0.1)'}`, flexShrink: 0, boxShadow: active ? '0 0 4px #00ff9f' : 'none' }} />
                      <span style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: active ? '#e6edf3' : '#374151', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{src}</span>
                      <span style={{ marginLeft: 'auto', fontSize: '8px', fontFamily: 'JetBrains Mono, monospace', color: active ? '#00ff9f' : '#374151' }}>{active ? '✓ active' : '○ unavailable'}</span>
                    </div>
                  )
                })}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '5px 8px', background: 'rgba(88,166,255,0.04)', border: '1px solid rgba(88,166,255,0.1)', borderRadius: '5px' }}>
                <span style={{ fontSize: '9px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>Enrichment time</span>
                <span style={{ marginLeft: 'auto', fontSize: '10px', fontWeight: 700, color: selected.enrichment_duration_ms > 3000 ? '#ff9f0a' : '#00ff9f', fontFamily: 'JetBrains Mono, monospace' }}>{selected.enrichment_duration_ms}ms</span>
                <div style={{ width: '60px', height: '3px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px', overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${Math.min(100, (selected.enrichment_duration_ms / 5000) * 100)}%`, background: selected.enrichment_duration_ms > 3000 ? '#ff9f0a' : '#00ff9f', borderRadius: '2px' }} />
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes slideIn { from { opacity: 0; transform: translateX(20px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes slideInRight { from { opacity: 0; transform: translateX(20px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        ::-webkit-scrollbar { width: 2px; }
        ::-webkit-scrollbar-thumb { background: rgba(0,255,159,0.15); border-radius: 1px; }
      `}</style>
    </div>
  )
}

function DetailSection({ title, children, animationDelay }: { title: string; children: React.ReactNode; animationDelay?: string }) {
  return (
    <div style={{ marginBottom: '14px', animation: 'fadeInUp 0.2s ease-out both', animationDelay }}>
      <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '6px', paddingBottom: '4px', borderBottom: '1px solid rgba(0,255,159,0.08)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 500 }}>{title}</div>
      {children}
    </div>
  )
}

function Row({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '2px 0', gap: '8px' }}>
      <span style={{ fontSize: '11px', fontFamily: 'Inter, sans-serif', color: '#6b7280', fontWeight: 500, flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: '11px', fontFamily: 'Inter, sans-serif', color: color || '#e2e8f5', fontWeight: 500, textAlign: 'right', wordBreak: 'break-all' }}>{value}</span>
    </div>
  )
}
