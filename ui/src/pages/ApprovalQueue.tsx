import { useState, useEffect, useRef } from 'react'
import { CheckCircle, XCircle, ChevronDown, ChevronUp, Clock, AlertTriangle, Shield, Cpu, RefreshCw, MessageSquare } from 'lucide-react'

const API = import.meta.env.VITE_AGENT_URL ?? 'http://localhost:8000'

interface QueueEntry {
  id: string
  timestamp: string
  status: 'pending' | 'approved' | 'rejected'
  pod: string
  namespace: string
  alert: {
    rule: string
    priority?: string
    output?: string
    fields?: Record<string, string>
  }
  decision: {
    severity: string
    confidence: number
    assessment: string
    blast_radius?: string
    recommended_action: string
  }
}

const MOCK_PENDING: QueueEntry[] = [
  {
    id: '1713340800-payment-api',
    timestamp: new Date(Date.now() - 4 * 60000).toISOString(),
    status: 'pending',
    pod: 'payment-api-7d4b9c-xzp2k',
    namespace: 'production',
    alert: {
      rule: 'Sensitive File Read by Unexpected Process',
      priority: 'WARNING',
      output: 'cat reading /etc/shadow (user=root command=cat /etc/shadow container=payment-api)',
      fields: { k8s_pod_name: 'payment-api-7d4b9c-xzp2k', k8s_ns_name: 'production', proc_name: 'cat', fd_name: '/etc/shadow' },
    },
    decision: {
      severity: 'HIGH',
      confidence: 0.72,
      assessment: 'Suspicious read of /etc/shadow by cat process inside payment-api container. Pattern matches credential harvesting; however confidence is below KILL threshold due to possible misconfigured init script.',
      blast_radius: 'High — payment service handles 400 rps; kill would cause 503s until controller restarts pod (~30s).',
      recommended_action: 'KILL',
    },
  },
  {
    id: '1713340920-redis-cache',
    timestamp: new Date(Date.now() - 9 * 60000).toISOString(),
    status: 'pending',
    pod: 'redis-cache-0',
    namespace: 'staging',
    alert: {
      rule: 'Outbound Connection to Rare External IP',
      priority: 'WARNING',
      output: 'redis-server connecting to 45.33.32.156:4444 (command=redis-server container=redis)',
      fields: { k8s_pod_name: 'redis-cache-0', k8s_ns_name: 'staging', fd_sip: '45.33.32.156', fd_sport: '4444' },
    },
    decision: {
      severity: 'HIGH',
      confidence: 0.68,
      assessment: 'Redis process establishing outbound connection to external IP on port 4444 — common C2 callback port. Likely compromise via SSRF or misconfigured Redis AUTH. Staging namespace reduces immediate blast radius.',
      blast_radius: 'Medium — staging only; no PII. Isolation preferred over kill to preserve forensic state.',
      recommended_action: 'ISOLATE',
    },
  },
]

const MOCK_HISTORY: QueueEntry[] = [
  {
    id: '1713337200-nginx-ingress',
    timestamp: new Date(Date.now() - 62 * 60000).toISOString(),
    status: 'approved',
    pod: 'nginx-ingress-6b7f4-ql9nv',
    namespace: 'kube-system',
    alert: { rule: 'Shell Spawned in Container', priority: 'ERROR', output: 'bash spawned in nginx container' },
    decision: { severity: 'CRITICAL', confidence: 0.91, assessment: 'Interactive shell in ingress controller — confirmed compromise.', recommended_action: 'KILL' },
  },
  {
    id: '1713335400-auth-svc',
    timestamp: new Date(Date.now() - 88 * 60000).toISOString(),
    status: 'rejected',
    pod: 'auth-svc-5f9b8d-pqr1x',
    namespace: 'production',
    alert: { rule: 'Unexpected Outbound DNS', priority: 'NOTICE', output: 'Unusual DNS query from auth-svc' },
    decision: { severity: 'MEDIUM', confidence: 0.55, assessment: 'Unusual DNS pattern but may be legitimate service discovery after rolling update.', recommended_action: 'ISOLATE' },
  },
]

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff4757',
  HIGH: '#ff6b35',
  MEDIUM: '#ffd32a',
  LOW: '#00ff88',
}

function timeAgo(ts: string): string {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  return `${Math.floor(diff / 3600)}h ago`
}

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span className="text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-wider border"
      style={{ color, borderColor: `${color}44`, background: `${color}14` }}>
      {label}
    </span>
  )
}

function ConfidenceMeter({ value }: { value: number }) {
  const pct = Math.round(value * 100)
  const col = pct >= 85 ? '#ff4757' : pct >= 65 ? '#ff6b35' : '#ffd32a'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-[#1a2035] overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: col }} />
      </div>
      <span className="text-[11px] font-bold font-mono" style={{ color: col }}>{pct}%</span>
    </div>
  )
}

function EntryCard({
  entry,
  onApprove,
  onReject,
  acting,
}: {
  entry: QueueEntry
  onApprove: (id: string, note?: string) => void
  onReject: (id: string, note?: string) => void
  acting: string | null
}) {
  const [expanded, setExpanded] = useState(false)
  const [rejectOpen, setRejectOpen] = useState(false)
  const [note, setNote] = useState('')
  const sevColor = SEV_COLOR[entry.decision.severity] ?? '#8892a4'
  const isActing = acting === entry.id

  const handleRejectConfirm = (e: React.MouseEvent) => {
    e.stopPropagation()
    onReject(entry.id, note || undefined)
    setRejectOpen(false)
    setNote('')
  }

  return (
    <div className="border rounded-lg overflow-hidden transition-all"
      style={{ borderColor: `${sevColor}33`, background: 'rgba(10,15,30,0.8)' }}>
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 cursor-pointer select-none"
        onClick={() => { if (!rejectOpen) setExpanded(e => !e) }}>
        <div className="w-2 h-2 rounded-full flex-shrink-0 animate-pulse" style={{ background: sevColor }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[13px] font-semibold text-[#e2e8f0] truncate">{entry.alert.rule}</span>
            <Badge label={entry.decision.severity} color={sevColor} />
            <Badge label={entry.decision.recommended_action} color="#00d4ff" />
          </div>
          <div className="flex items-center gap-3 mt-0.5">
            <span className="text-[11px] text-[#5a6478] font-mono">{entry.namespace}/{entry.pod}</span>
            <span className="text-[10px] text-[#3d4a5f] flex items-center gap-1">
              <Clock size={9} />{timeAgo(entry.timestamp)}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            disabled={isActing || rejectOpen}
            onClick={e => { e.stopPropagation(); onApprove(entry.id) }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[12px] font-semibold text-[#00ff88] border border-[rgba(0,255,136,0.25)] bg-[rgba(0,255,136,0.06)] hover:bg-[rgba(0,255,136,0.14)] transition-all disabled:opacity-40 disabled:cursor-not-allowed">
            <CheckCircle size={12} /> Approve
          </button>
          <button
            disabled={isActing}
            onClick={e => { e.stopPropagation(); setRejectOpen(r => !r) }}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-[12px] font-semibold text-[#ff4757] border transition-all disabled:opacity-40 disabled:cursor-not-allowed ${rejectOpen ? 'bg-[rgba(255,71,87,0.12)] border-[rgba(255,71,87,0.4)]' : 'border-[rgba(255,71,87,0.25)] bg-[rgba(255,71,87,0.06)] hover:bg-[rgba(255,71,87,0.14)]'}`}>
            <XCircle size={12} /> Reject
          </button>
          {expanded ? <ChevronUp size={14} className="text-[#5a6478]" /> : <ChevronDown size={14} className="text-[#5a6478]" />}
        </div>
      </div>

      {/* Reject reason panel */}
      {rejectOpen && (
        <div className="border-t border-[rgba(255,71,87,0.15)] px-4 py-3 bg-[rgba(255,71,87,0.04)]" onClick={e => e.stopPropagation()}>
          <div className="text-[10px] uppercase tracking-widest text-[#ff4757] mb-2 flex items-center gap-1.5">
            <MessageSquare size={10} /> Reason for rejection <span className="text-[#3d4a5f] normal-case tracking-normal">(optional)</span>
          </div>
          <textarea
            value={note}
            onChange={e => setNote(e.target.value)}
            placeholder="False positive — this is a scheduled maintenance script. Suppress for 2h."
            rows={2}
            className="w-full bg-[#060912] border border-[rgba(255,71,87,0.2)] rounded px-3 py-2 text-[11px] text-[#a0aec0] font-mono resize-none outline-none focus:border-[rgba(255,71,87,0.5)] placeholder:text-[#3d4a5f] transition-colors"
            autoFocus
          />
          <div className="flex items-center gap-2 mt-2 justify-end">
            <button onClick={e => { e.stopPropagation(); setRejectOpen(false); setNote('') }}
              className="px-3 py-1.5 rounded text-[11px] text-[#5a6478] border border-[rgba(99,179,237,0.15)] hover:text-[#8892a4] transition-all">
              Cancel
            </button>
            <button onClick={handleRejectConfirm}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] font-semibold text-[#ff4757] border border-[rgba(255,71,87,0.35)] bg-[rgba(255,71,87,0.1)] hover:bg-[rgba(255,71,87,0.18)] transition-all">
              <XCircle size={11} /> Confirm Rejection
            </button>
          </div>
        </div>
      )}

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-[rgba(99,179,237,0.08)] px-4 py-4 grid grid-cols-2 gap-4">
          {/* Claude assessment */}
          <div className="col-span-2">
            <div className="text-[10px] uppercase tracking-widest text-[#5a6478] mb-1.5 flex items-center gap-1.5">
              <Shield size={10} /> Claude Assessment
            </div>
            <p className="text-[12px] text-[#a0aec0] leading-relaxed">{entry.decision.assessment}</p>
          </div>

          {/* Confidence */}
          <div>
            <div className="text-[10px] uppercase tracking-widest text-[#5a6478] mb-1.5">Confidence</div>
            <ConfidenceMeter value={entry.decision.confidence} />
          </div>

          {/* Blast radius */}
          {entry.decision.blast_radius && (
            <div>
              <div className="text-[10px] uppercase tracking-widest text-[#5a6478] mb-1.5 flex items-center gap-1.5">
                <AlertTriangle size={10} /> Blast Radius
              </div>
              <p className="text-[12px] text-[#a0aec0] leading-relaxed">{entry.decision.blast_radius}</p>
            </div>
          )}

          {/* Raw alert output */}
          {entry.alert.output && (
            <div className="col-span-2">
              <div className="text-[10px] uppercase tracking-widest text-[#5a6478] mb-1.5 flex items-center gap-1.5">
                <Cpu size={10} /> Falco Alert
              </div>
              <div className="bg-[#060912] border border-[rgba(99,179,237,0.1)] rounded px-3 py-2">
                <code className="text-[11px] text-[#8892a4] font-mono break-all">{entry.alert.output}</code>
              </div>
            </div>
          )}

          {/* Fields */}
          {entry.alert.fields && Object.keys(entry.alert.fields).length > 0 && (
            <div className="col-span-2">
              <div className="text-[10px] uppercase tracking-widest text-[#5a6478] mb-1.5">Context Fields</div>
              <div className="flex flex-wrap gap-2">
                {Object.entries(entry.alert.fields).map(([k, v]) => (
                  <span key={k} className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#0d1425] border border-[rgba(99,179,237,0.1)] text-[#8892a4]">
                    <span className="text-[#5a6478]">{k}=</span>{v}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function HistoryRow({ entry }: { entry: QueueEntry }) {
  const approved = entry.status === 'approved'
  const sevColor = SEV_COLOR[entry.decision.severity] ?? '#8892a4'
  return (
    <div className="flex items-center gap-3 px-4 py-3 border-b border-[rgba(99,179,237,0.06)] last:border-0 hover:bg-[rgba(255,255,255,0.02)] transition-colors">
      {approved
        ? <CheckCircle size={14} className="text-[#00ff88] flex-shrink-0" />
        : <XCircle size={14} className="text-[#ff4757] flex-shrink-0" />}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-[12px] text-[#a0aec0] truncate">{entry.alert.rule}</span>
          <Badge label={entry.decision.severity} color={sevColor} />
        </div>
        <span className="text-[10px] text-[#3d4a5f] font-mono">{entry.namespace}/{entry.pod}</span>
      </div>
      <div className="text-right flex-shrink-0">
        <div className="text-[11px] font-bold" style={{ color: approved ? '#00ff88' : '#ff4757' }}>
          {approved ? 'APPROVED' : 'REJECTED'}
        </div>
        <div className="text-[10px] text-[#3d4a5f]">{timeAgo(entry.timestamp)}</div>
      </div>
    </div>
  )
}

export default function ApprovalQueue() {
  const [pending, setPending] = useState<QueueEntry[]>(MOCK_PENDING)
  const [history, setHistory] = useState<QueueEntry[]>(MOCK_HISTORY)
  const [acting, setActing] = useState<string | null>(null)
  const [tab, setTab] = useState<'queue' | 'history'>('queue')
  const [lastPoll, setLastPoll] = useState<Date>(new Date())
  const [liveConnected, setLiveConnected] = useState(false)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const fetchQueue = async () => {
    try {
      const res = await fetch(`${API}/approvals`)
      if (!res.ok) return
      const data = await res.json()
      if (Array.isArray(data.pending)) {
        setPending(data.pending)
        setLiveConnected(true)
        setLastPoll(new Date())
      }
    } catch {
      // backend not reachable — keep mock data
    }
  }

  useEffect(() => {
    fetchQueue()
    pollRef.current = setInterval(fetchQueue, 5000)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [])

  const handleApprove = async (id: string) => {
    setActing(id)
    try {
      await fetch(`${API}/approvals/${id}/approve`, { method: 'POST' })
    } catch { /* offline */ }
    const entry = pending.find(e => e.id === id)
    if (entry) setHistory(h => [{ ...entry, status: 'approved' as const }, ...h].slice(0, 50))
    setPending(p => p.filter(e => e.id !== id))
    setActing(null)
  }

  const handleReject = async (id: string, note?: string) => {
    setActing(id)
    try {
      await fetch(`${API}/approvals/${id}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: note }),
      })
    } catch { /* offline */ }
    const entry = pending.find(e => e.id === id)
    if (entry) setHistory(h => [{ ...entry, status: 'rejected' as const }, ...h].slice(0, 50))
    setPending(p => p.filter(e => e.id !== id))
    setActing(null)
  }

  return (
    <div className="p-6 font-mono max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="text-[#00d4ff] text-xs uppercase tracking-widest mb-1">Human-in-the-Loop</div>
          <h1 className="text-[20px] font-bold text-[#e2e8f0]">Approval Queue</h1>
          <p className="text-[12px] text-[#5a6478] mt-0.5">
            Actions requiring human authorization before execution
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-[11px]">
            <div className={`w-2 h-2 rounded-full ${liveConnected ? 'bg-[#00ff88] shadow-[0_0_6px_#00ff88]' : 'bg-[#3d4a5f]'} animate-pulse`} />
            <span className="text-[#5a6478]">{liveConnected ? 'Live' : 'Demo mode'}</span>
          </div>
          <button onClick={fetchQueue}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] text-[#5a6478] border border-[rgba(99,179,237,0.15)] hover:border-[rgba(0,212,255,0.3)] hover:text-[#00d4ff] transition-all">
            <RefreshCw size={11} />
            {lastPoll.toTimeString().slice(0, 8)}
          </button>
        </div>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        {[
          { label: 'Pending', value: pending.length, color: '#ff6b35' },
          { label: 'Approved today', value: history.filter(e => e.status === 'approved').length, color: '#00ff88' },
          { label: 'Rejected today', value: history.filter(e => e.status === 'rejected').length, color: '#ff4757' },
          { label: 'Avg wait', value: '4m 12s', color: '#00d4ff' },
        ].map(stat => (
          <div key={stat.label} className="rounded-lg border border-[rgba(99,179,237,0.12)] bg-[rgba(10,15,30,0.6)] px-4 py-3">
            <div className="text-[22px] font-bold" style={{ color: stat.color }}>{stat.value}</div>
            <div className="text-[10px] text-[#5a6478] uppercase tracking-wider mt-0.5">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b border-[rgba(99,179,237,0.1)]">
        {(['queue', 'history'] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-2 text-[12px] uppercase tracking-wider transition-all border-b-2 -mb-px ${
              tab === t
                ? 'text-[#00d4ff] border-[#00d4ff]'
                : 'text-[#5a6478] border-transparent hover:text-[#8892a4]'
            }`}>
            {t === 'queue' ? `Pending (${pending.length})` : `History (${history.length})`}
          </button>
        ))}
      </div>

      {/* Queue */}
      {tab === 'queue' && (
        <div className="space-y-3">
          {pending.length === 0 ? (
            <div className="text-center py-16">
              <CheckCircle size={36} className="text-[#00ff88] mx-auto mb-3 opacity-50" />
              <p className="text-[14px] text-[#5a6478]">No pending approvals</p>
              <p className="text-[11px] text-[#3d4a5f] mt-1">The agent is handling all incidents autonomously</p>
            </div>
          ) : (
            pending.map(entry => (
              <EntryCard key={entry.id} entry={entry} onApprove={handleApprove} onReject={handleReject} acting={acting} />
            ))
          )}
        </div>
      )}

      {/* History */}
      {tab === 'history' && (
        <div className="rounded-lg border border-[rgba(99,179,237,0.12)] overflow-hidden">
          {history.length === 0 ? (
            <div className="text-center py-12 text-[#5a6478] text-[12px]">No resolved approvals yet</div>
          ) : (
            history.map(entry => <HistoryRow key={entry.id} entry={entry} />)
          )}
        </div>
      )}
    </div>
  )
}
