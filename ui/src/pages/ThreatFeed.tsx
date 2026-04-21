import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import FormattedAssistantContent from '../components/FormattedAssistantContent'

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
  what_happened?: string[] | string
  blast_radius_bullets?: string[]
  action_steps?: string[]
  blast_radius: string
  recommended_action: string
  action_taken: string
  action_status: string
  confidence: number
  likely_false_positive: boolean
  kyverno_blocked?: boolean
  mitre_tags: string[]
  enrichment_sources: string[]
  enrichment_duration_ms: number
}

function toArray(v: string[] | string | undefined): string[] {
  if (!v) return []
  if (Array.isArray(v)) return v
  return [v]
}

function getContextualActionSteps(inc: Incident): string[] {
  const steps = toArray(inc.action_steps)
  if (steps.length > 0 && !steps.every(s => s === 'Review incident' || s === 'Verify legitimacy')) {
    return steps
  }
  const rule = inc.rule.toLowerCase()
  const action = inc.recommended_action || inc.action_taken
  if (inc.kyverno_blocked) {
    return [
      'Workload was blocked at admission — cluster remains safe',
      'Identify who submitted this workload via kubectl get events',
      'Fix the policy violation in the deployment spec and re-deploy',
      'Run: kubectl get policyreport -A to see full Kyverno violations',
    ]
  }
  if (action === 'KILL') return [
    'Container automatically terminated by Argus — workload is offline',
    'Rotate all secrets and tokens mounted in the affected pod',
    'Review pod logs and kubectl exec audit trail for root cause',
    'Redeploy from a verified clean image after investigation',
  ]
  if (action === 'ISOLATE') return [
    'Pod network isolated — threat contained, workload still running',
    'Collect forensic data: kubectl debug, log capture before deleting',
    'Identify the attack vector and patch before re-enabling network',
    'Review Hubble flows for lateral movement attempts',
  ]
  if (action === 'HUMAN_REQUIRED') return [
    'AI confidence below auto-remediation threshold — human review required',
    'Check Approval Queue (/approvals) to approve or reject the action',
    'Review incident timeline in the Enrichment section below',
    'Examine MITRE tags to understand attacker objective',
    'Correlate with other incidents in the same namespace/node',
  ]
  if (rule.includes('kyverno')) return [
    'Kyverno blocked this workload at admission control',
    'No runtime risk — pod was never scheduled',
    'Fix the violated policy in the deployment manifest',
    'Re-deploy after correcting the security policy violations',
  ]
  return [
    'Review the full incident timeline in the enrichment panel',
    'Correlate with other recent incidents on the same node',
    'Check Hubble flows for unusual network activity',
    'Escalate to security team if pattern persists',
  ]
}

interface ChatMessage { role: 'user' | 'assistant'; content: string; ts: number }

function AskArgusPanel({ incident }: { incident: Incident }) {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    setMessages([])
    setInput('')
  }, [incident.id])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const send = useCallback(async () => {
    const text = input.trim()
    if (!text || loading) return
    const userMsg: ChatMessage = { role: 'user', content: text, ts: Date.now() }
    const next = [...messages, userMsg]
    setMessages(next)
    setInput('')
    setLoading(true)
    try {
      const res = await fetch(`${API}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: next.map(m => ({ role: m.role, content: m.content })),
          incident_id: incident.id,
        }),
      })
      const data = await res.json()
      setMessages(prev => [...prev, { role: 'assistant', content: data.response || 'No response', ts: Date.now() }])
    } catch {
      setMessages(prev => [...prev, { role: 'assistant', content: 'Failed to reach Argus AI. Check agent status.', ts: Date.now() }])
    }
    setLoading(false)
  }, [input, loading, messages, incident.id])

  const SUGGESTIONS = [
    'What happened?',
    'How do I remediate this?',
    'Is this a false positive?',
    'What MITRE technique is this?',
  ]

  return (
    <div style={{ marginBottom: 0, animation: 'fadeInUp 0.2s ease-out both', animationDelay: '0.3s' }}>
      <div style={{ fontSize: '10px', color: '#00d4ff', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '8px', paddingBottom: '4px', borderBottom: '1px solid rgba(0,212,255,0.08)', fontFamily: 'JetBrains Mono, monospace' }}>
        ◎ Ask Argus AI
      </div>

      {/* Chat history */}
      {messages.length > 0 && (
        <div style={{ maxHeight: '220px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '8px' }}>
          {messages.map((m, i) => (
            <div key={i} style={{ display: 'flex', flexDirection: m.role === 'user' ? 'row-reverse' : 'row', gap: '6px', alignItems: 'flex-start' }}>
              <div style={{
                padding: '7px 10px', borderRadius: m.role === 'user' ? '10px 3px 10px 10px' : '3px 10px 10px 10px',
                background: m.role === 'user' ? 'rgba(88,166,255,0.1)' : 'rgba(0,212,255,0.05)',
                border: `1px solid ${m.role === 'user' ? 'rgba(88,166,255,0.25)' : 'rgba(0,212,255,0.12)'}`,
                borderLeft: m.role === 'assistant' ? '2px solid rgba(0,212,255,0.4)' : undefined,
                fontSize: '11px', color: '#d1d5db', lineHeight: 1.55, maxWidth: '90%',
                fontFamily: 'Inter, sans-serif',
              }}>
                {m.role === 'assistant' ? <FormattedAssistantContent content={m.content} compact /> : m.content}
              </div>
            </div>
          ))}
          {loading && (
            <div style={{ display: 'flex', gap: '4px', padding: '8px 10px' }}>
              {[0,1,2].map(i => (
                <div key={i} style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00d4ff', animation: `typingDot 1.2s ease-in-out ${i*0.2}s infinite` }} />
              ))}
            </div>
          )}
          <div ref={bottomRef} />
        </div>
      )}

      {/* Suggestion chips (only when no messages yet) */}
      {messages.length === 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginBottom: '8px' }}>
          {SUGGESTIONS.map(s => (
            <button key={s} onClick={() => { setInput(s); }} style={{
              background: 'rgba(0,212,255,0.05)', border: '1px solid rgba(0,212,255,0.15)',
              borderRadius: '20px', color: '#5a7fa8', cursor: 'pointer',
              padding: '3px 10px', fontSize: '9px', fontFamily: 'JetBrains Mono, monospace',
              transition: 'all 0.15s',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(0,212,255,0.12)'; e.currentTarget.style.color = '#00d4ff' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'rgba(0,212,255,0.05)'; e.currentTarget.style.color = '#5a7fa8' }}
            >{s}</button>
          ))}
        </div>
      )}

      {/* Input */}
      <div style={{ display: 'flex', gap: '6px', alignItems: 'center', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(0,212,255,0.15)', borderRadius: '7px', padding: '6px 10px' }}>
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && send()}
          placeholder="Ask about this incident..."
          disabled={loading}
          style={{
            flex: 1, background: 'transparent', border: 'none', color: '#e2e8f5',
            fontSize: '11px', fontFamily: 'Inter, sans-serif', outline: 'none',
          }}
        />
        <button
          onClick={send}
          disabled={!input.trim() || loading}
          style={{
            background: input.trim() && !loading ? 'rgba(0,212,255,0.15)' : 'transparent',
            border: `1px solid ${input.trim() && !loading ? 'rgba(0,212,255,0.4)' : 'rgba(255,255,255,0.06)'}`,
            borderRadius: '5px', color: input.trim() && !loading ? '#00d4ff' : '#3d4a5f',
            cursor: input.trim() && !loading ? 'pointer' : 'not-allowed',
            padding: '3px 10px', fontSize: '9px', fontFamily: 'JetBrains Mono, monospace',
          }}
        >
          {loading ? '...' : 'Ask'}
        </button>
      </div>
      <style>{`@keyframes typingDot { 0%,60%,100%{transform:translateY(0)} 30%{transform:translateY(-3px)} }`}</style>
    </div>
  )
}

interface NodeTelemetry {
  name: string
  ip: string
  pods: number
  recent_incidents?: number
}

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

function ImpactDiagram({ incident, nodes }: { incident: any; nodes: NodeTelemetry[] }) {
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

  const threatNode = incident.hostname || nodes[0]?.name || ''
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
        <span style={{ fontSize: '8px', color: '#4a5568', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace' }}>{nodes.length} nodes · live /api/node-telemetry</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '10px' }}>
        {nodes.length === 0 && (
          <div style={{ padding: '14px', textAlign: 'center', color: '#4a5568', fontSize: '10px', border: '1px dashed rgba(0,255,159,0.12)', borderRadius: '7px' }}>
            Waiting for backend node telemetry.
          </div>
        )}
        {nodes.map(node => {
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
            { name: `${node.pods} pods`, status: 'safe' as PodStatus, ns: 'live' },
            { name: `${node.recent_incidents || 0} events`, status: 'safe' as PodStatus, ns: '1m' },
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

export default function ThreatFeed() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [selected, setSelected] = useState<Incident | null>(null)
  const [filter, setFilter] = useState<string>('ALL')
  const [nsFilter, setNsFilter] = useState<string>('ALL')
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [lastUpdated, setLastUpdated] = React.useState<string>('')
  const [nodes, setNodes] = useState<NodeTelemetry[]>([])
  const prevCount = useRef(0)
  const newIds = useRef<Set<string>>(new Set())

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

  const fetchNodes = async () => {
    try {
      const r = await fetch(`${API}/node-telemetry`)
      if (!r.ok) return
      const data = await r.json()
      setNodes(data.nodes || [])
    } catch {}
  }

  useEffect(() => {
    fetchIncidents()
    fetchNodes()
    const incidentTimer = setInterval(fetchIncidents, 3000)
    const nodeTimer = setInterval(fetchNodes, 5000)
    return () => {
      clearInterval(incidentTimer)
      clearInterval(nodeTimer)
    }
  }, [])

  useEffect(() => {
    const selectedId = searchParams.get('id')
    if (!selectedId) return
    const match = incidents.find(i => i.id === selectedId)
    if (match && selected?.id !== match.id) {
      setSelected(match)
    }
  }, [incidents, searchParams, selected?.id])

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
        <div style={{ padding: '10px 14px', borderBottom: '1px solid rgba(0,255,159,0.1)', display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>
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
            onClick={async () => {
              setRefreshing(true)
              await fetchIncidents()
              setRefreshing(false)
            }}
            disabled={refreshing}
            title="Refresh feed"
            style={{
              background: refreshing ? 'rgba(0,255,159,0.06)' : 'transparent',
              border: '1px solid rgba(0,255,159,0.2)',
              borderRadius: '6px',
              color: '#00ff9f',
              cursor: refreshing ? 'not-allowed' : 'pointer',
              padding: '3px 10px',
              fontSize: '10px',
              fontFamily: 'JetBrains Mono, monospace',
              display: 'flex',
              alignItems: 'center',
              gap: '5px',
              transition: 'all 0.15s',
              opacity: refreshing ? 0.7 : 1,
            }}
            onMouseEnter={e => !refreshing && (e.currentTarget.style.background = 'rgba(0,255,159,0.08)')}
            onMouseLeave={e => !refreshing && (e.currentTarget.style.background = 'transparent')}
          >
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#00ff9f" strokeWidth="2.5" strokeLinecap="round"
              style={{ animation: refreshing ? 'spin 0.7s linear infinite' : 'none', flexShrink: 0 }}>
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
          <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>
            {lastUpdated ? `updated ${lastUpdated}` : ''}
          </span>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '10px 12px 28px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
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
              <div key={inc.id} onClick={() => {
                if (selected?.id === inc.id) {
                  setSelected(null)
                  setSearchParams({})
                } else {
                  setSelected(inc)
                  setSearchParams({ id: inc.id })
                }
              }}
                style={{
                  borderRadius: '6px', border: `1px solid ${selected?.id === inc.id ? 'rgba(0,255,159,0.3)' : sev.border}`,
                  background: selected?.id === inc.id ? '#1c2433' : inc.severity === 'CRITICAL' ? 'rgba(255,45,85,0.05)' : '#1a2233',
                  padding: '14px 16px 14px 20px', minHeight: '100px', cursor: 'pointer', position: 'relative', overflow: 'visible',
                  fontFamily: 'Inter, sans-serif',
                  transition: 'border-color 0.12s, background 0.12s, transform 0.12s',
                  animation: isNew ? 'slideIn 0.3s ease-out' : undefined,
                }}
                onMouseEnter={e => {
                  e.currentTarget.style.background = selected?.id === inc.id ? '#1f2a3c' : inc.severity === 'CRITICAL' ? 'rgba(255,45,85,0.075)' : '#1d2738'
                  e.currentTarget.style.transform = 'translateX(2px)'
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.background = selected?.id === inc.id ? '#1c2433' : inc.severity === 'CRITICAL' ? 'rgba(255,45,85,0.05)' : '#1a2233'
                  e.currentTarget.style.transform = 'translateX(0)'
                }}
              >
                <div style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: '4px', background: sev.dot, borderRadius: '3px 0 0 3px' }} />
                <div style={{ minHeight: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', alignItems: 'center', gap: '14px', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                      <span style={{ fontSize: '10px', fontWeight: 700, padding: '3px 8px', borderRadius: '3px', background: sev.bg, color: sev.color, border: `1px solid ${sev.border}`, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                        ● {inc.severity}
                      </span>
                      <span style={{ fontSize: '10px', color: `${act.color}`, background: `${act.color}22`, padding: '2px 8px', borderRadius: '3px', border: `1px solid ${act.color}44` }}>
                        {act.label}
                      </span>
                    </div>
                    <span style={{ fontSize: '10px', color: '#6b7280', fontFamily: 'JetBrains Mono, monospace', whiteSpace: 'nowrap' }}>{fmt(inc.ts)} · {inc.hostname}</span>
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: '#f0f6fc', fontFamily: 'Inter, sans-serif', letterSpacing: '0', marginBottom: '8px', lineHeight: 1.35 }}>{inc.rule}</div>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
                    {inc.kyverno_blocked && (
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', fontWeight: 700, color: '#bc8cff', background: 'rgba(188,140,255,0.1)', padding: '2px 7px', borderRadius: '3px', border: '1px solid rgba(188,140,255,0.35)' }}>
                        KYVERNO BLOCKED
                      </span>
                    )}
                    {inc.namespace && <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'rgba(88,166,255,0.8)', background: 'rgba(88,166,255,0.08)', padding: '2px 7px', borderRadius: '3px', border: '1px solid rgba(88,166,255,0.2)' }}>{inc.namespace}</span>}
                    {inc.pod && <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: '#4a5568', background: '#0d1117', padding: '2px 7px', borderRadius: '3px', border: '1px solid rgba(0,255,159,0.08)' }}>{inc.pod}</span>}
                    {inc.mitre_tags?.map(t => <span key={t} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '9px', color: 'rgba(188,140,255,0.8)', background: 'rgba(188,140,255,0.06)', padding: '2px 7px', borderRadius: '3px', border: '1px solid rgba(188,140,255,0.2)' }}>{t}</span>)}
                    <span style={{ fontSize: '10px', color: '#4a5568', marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace', paddingLeft: '8px' }}>
                      {Math.round(inc.confidence * 100)}% confidence
                    </span>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {selected && (
        <div key={selected.id} style={{ borderLeft: '1px solid rgba(0,255,159,0.1)', display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#0d1117', animation: 'slideInRight 0.2s ease-out' }}>
          <div style={{ padding: '10px 14px', borderBottom: '1px solid rgba(0,255,159,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
            <span style={{ fontSize: '11px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px' }}>Incident detail</span>
            <button onClick={() => { setSelected(null); setSearchParams({}) }} style={{ fontSize: '12px', color: '#4a5568', background: 'transparent', border: 'none', cursor: 'pointer' }}>✕</button>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: '12px', fontFamily: 'Inter, sans-serif' }}>
            <DetailSection title="Alert" animationDelay="0.05s">
              <Row label="Rule" value={selected.rule} />
              <Row label="Priority" value={selected.priority} />
              <Row label="Severity" value={selected.severity} color={SEV_CONFIG[selected.severity]?.color} />
              <Row label="Hostname" value={selected.hostname} />
              {selected.kyverno_blocked && (
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0', marginTop: '4px', background: 'rgba(188,140,255,0.08)', borderRadius: '5px', border: '1px solid rgba(188,140,255,0.25)', paddingLeft: '8px', paddingRight: '8px' }}>
                  <span style={{ fontSize: '10px', color: '#bc8cff', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>⛔ Blocked by Kyverno</span>
                  <span style={{ fontSize: '9px', color: '#6b4fa8' }}>Pod never ran</span>
                </div>
              )}
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
                <span style={{ fontSize: '9px', color: '#00ff9f', fontFamily: 'JetBrains Mono, monospace' }}>ARGUS AI · reasoning model</span>
                <div style={{ flex: 1, height: '1px', background: 'rgba(0,255,159,0.1)' }} />
                <span style={{ fontSize: '9px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>{Math.round(selected.confidence * 100)}% confidence</span>
              </div>

              <div style={{ background: 'rgba(255,45,85,0.05)', border: '1px solid rgba(255,45,85,0.12)', borderRadius: '8px', padding: '10px 12px', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '7px' }}>
                  <span style={{ fontSize: '9px', fontWeight: 700, color: '#ff2d55', textTransform: 'uppercase', letterSpacing: '1px', fontFamily: 'JetBrains Mono, monospace' }}>What happened</span>
                </div>
                {toArray((selected as any).what_happened).length > 0
                  ? toArray((selected as any).what_happened).map((bullet: string, i: number) => (
                    <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '5px', alignItems: 'flex-start' }}>
                      <span style={{ color: '#ff2d55', fontSize: '10px', marginTop: '2px', flexShrink: 0 }}>•</span>
                      <span style={{ fontSize: '11px', color: '#d1d5db', lineHeight: 1.6, fontFamily: 'Inter, sans-serif' }}>{bullet}</span>
                    </div>
                  ))
                  : (
                    <div style={{ display: 'flex', gap: '8px', marginBottom: '5px', alignItems: 'flex-start' }}>
                      <span style={{ color: '#ff2d55', fontSize: '10px', marginTop: '2px', flexShrink: 0 }}>•</span>
                      <span style={{ fontSize: '11px', color: '#d1d5db', lineHeight: 1.6, fontFamily: 'Inter, sans-serif' }}>{selected.assessment}</span>
                    </div>
                  )
                }
              </div>

              <ImpactDiagram incident={selected} nodes={nodes} />

              <div style={{ background: 'rgba(88,166,255,0.04)', border: '1px solid rgba(88,166,255,0.12)', borderRadius: '8px', padding: '10px 12px', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '7px' }}>
                  <span style={{ fontSize: '9px', fontWeight: 700, color: '#58a6ff', textTransform: 'uppercase', letterSpacing: '1px', fontFamily: 'JetBrains Mono, monospace' }}>Recommended actions</span>
                </div>
                {getContextualActionSteps(selected).map((step: string, i: number) => (
                  <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '7px', alignItems: 'flex-start' }}>
                    <div style={{ width: '18px', height: '18px', borderRadius: '50%', background: 'rgba(88,166,255,0.12)', border: '1px solid rgba(88,166,255,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '8px', color: '#58a6ff', fontWeight: 700, flexShrink: 0, marginTop: '1px', fontFamily: 'JetBrains Mono, monospace' }}>{i + 1}</div>
                    <span style={{ fontSize: '11px', color: '#d1d5db', lineHeight: 1.6, fontFamily: 'Inter, sans-serif' }}>{step}</span>
                  </div>
                ))}
                <div style={{ marginTop: '12px', paddingTop: '10px', borderTop: '1px solid rgba(88,166,255,0.12)' }}>
                  <AskArgusPanel incident={selected} />
                </div>
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
                <button
                  type="button"
                  onClick={() => {
                    if (selected.action_taken === 'HUMAN_REQUIRED') {
                      navigate(`/approvals?incident_id=${encodeURIComponent(selected.id)}`)
                    }
                  }}
                  style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 10px', background: `${(ACTION_CONFIG[selected.action_taken] || ACTION_CONFIG.LOG).color}11`, border: `1px solid ${(ACTION_CONFIG[selected.action_taken] || ACTION_CONFIG.LOG).color}33`, borderRadius: '7px', cursor: selected.action_taken === 'HUMAN_REQUIRED' ? 'pointer' : 'default', textAlign: 'left' }}
                >
                  <div>
                    <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '3px', fontFamily: 'Inter, sans-serif' }}>Action taken</div>
                    <div style={{ fontSize: '14px', fontWeight: 700, color: (ACTION_CONFIG[selected.action_taken] || ACTION_CONFIG.LOG).color, fontFamily: 'Inter, sans-serif', letterSpacing: '-0.01em' }}>{(ACTION_CONFIG[selected.action_taken] || ACTION_CONFIG.LOG).label}</div>
                    {selected.action_taken === 'HUMAN_REQUIRED' && (
                      <div style={{ marginTop: '5px', fontSize: '9px', color: '#58a6ff', fontFamily: 'JetBrains Mono, monospace' }}>
                        Open human approval request →
                      </div>
                    )}
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '3px', fontFamily: 'Inter, sans-serif' }}>Status</div>
                    <div style={{ fontSize: '11px', fontWeight: 600, color: selected.action_status === 'completed' ? '#00ff9f' : selected.action_status === 'failed' ? '#ff2d55' : '#ff9f0a', fontFamily: 'JetBrains Mono, monospace' }}>● {selected.action_status}</div>
                  </div>
                </button>
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
        @keyframes spin { to { transform: rotate(360deg) } }
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
