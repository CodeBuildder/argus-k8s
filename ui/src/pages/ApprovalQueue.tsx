import React, { useState, useEffect, useMemo } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'

const API = '/api'

interface ApprovalEntry {
  id: string
  incident_id?: string
  rule?: string
  severity?: string
  namespace?: string
  pod?: string
  action_type?: string
  action_detail?: string
  confidence?: number
  timestamp?: string
  status: 'pending' | 'approved' | 'rejected'
}

const SEV_CONFIG: Record<string, { color: string; bg: string; border: string }> = {
  CRITICAL: { color: '#ff2d55', bg: 'rgba(255,45,85,0.08)', border: 'rgba(255,45,85,0.3)' },
  HIGH:     { color: '#ff9f0a', bg: 'rgba(255,159,10,0.08)', border: 'rgba(255,159,10,0.3)' },
  MED:      { color: '#ffd700', bg: 'rgba(255,215,0,0.06)', border: 'rgba(255,215,0,0.25)' },
  LOW:      { color: '#8b949e', bg: 'rgba(139,148,158,0.06)', border: 'rgba(139,148,158,0.2)' },
}

function ActionIcon({ type }: { type?: string }) {
  if (type === 'KILL') return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="#ff2d55" strokeWidth="1.5" strokeLinecap="round">
      <line x1="2" y1="2" x2="12" y2="12"/><line x1="12" y1="2" x2="2" y2="12"/>
    </svg>
  )
  if (type === 'ISOLATE') return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="#ff9f0a" strokeWidth="1.4">
      <rect x="2" y="7" width="10" height="6" rx="1"/>
      <path d="M4.5 7V5a2.5 2.5 0 0 1 5 0v2" strokeLinecap="round"/>
    </svg>
  )
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="#bc8cff" strokeWidth="1.5">
      <circle cx="7" cy="5" r="2.5"/><path d="M2 13c0-2.8 2.2-5 5-5s5 2.2 5 5" strokeLinecap="round"/>
    </svg>
  )
}

function EmptyState() {
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '16px', padding: '60px 20px' }}>
      <div style={{ width: '60px', height: '60px', borderRadius: '50%', background: 'rgba(0,255,159,0.06)', border: '1px solid rgba(0,255,159,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#00ff9f" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="20 6 9 17 4 12"/>
        </svg>
      </div>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: '14px', fontWeight: 600, color: '#00ff9f', marginBottom: '6px' }}>All clear</div>
        <div style={{ fontSize: '11px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>No pending human approvals</div>
        <div style={{ fontSize: '10px', color: '#2a3349', marginTop: '4px' }}>Argus AI is handling automated remediations</div>
      </div>
    </div>
  )
}

export default function ApprovalQueue() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [pending, setPending] = useState<ApprovalEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [acting, setActing] = useState<Record<string, 'approving' | 'rejecting'>>({})
  const [done, setDone] = useState<Record<string, 'approved' | 'rejected'>>({})
  const [lastRefresh, setLastRefresh] = useState('')
  const [simulating, setSimulating] = useState(false)

  const fetchQueue = async () => {
    try {
      const res = await fetch(`${API}/approvals`)
      if (res.ok) {
        const data = await res.json()
        setPending(data.pending || [])
        setLastRefresh(new Date().toTimeString().slice(0, 8))
      }
    } catch {}
    setLoading(false)
  }

  const manualRefresh = async () => {
    setRefreshing(true)
    await fetchQueue()
    setRefreshing(false)
  }

  useEffect(() => {
    fetchQueue()
    const t = setInterval(fetchQueue, 5000)
    return () => clearInterval(t)
  }, [])

  const act = async (id: string, action: 'approve' | 'reject') => {
    setActing(prev => ({ ...prev, [id]: action === 'approve' ? 'approving' : 'rejecting' }))
    try {
      await fetch(`${API}/approvals/${id}/${action}`, { method: 'POST' })
      setDone(prev => ({ ...prev, [id]: action === 'approve' ? 'approved' : 'rejected' }))
      setTimeout(() => {
        setPending(prev => prev.filter(e => e.id !== id))
        setDone(prev => { const n = { ...prev }; delete n[id]; return n })
      }, 1200)
    } catch {}
    setActing(prev => { const n = { ...prev }; delete n[id]; return n })
  }

  const simulateApproval = async () => {
    setSimulating(true)
    // Fire the simulation without blocking — poll the queue while it runs
    fetch(`${API}/simulate-threats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: 'human_approval', count: 3 }),
    }).catch(() => {})
    // Poll 3 times over 3 seconds to catch when items appear
    for (let i = 0; i < 3; i++) {
      await new Promise(r => setTimeout(r, 1000))
      await fetchQueue()
    }
    setSimulating(false)
  }

  const fmtTs = (ts?: string) => {
    if (!ts) return ''
    const d = new Date(ts)
    const diff = Math.floor((Date.now() - d.getTime()) / 1000)
    if (diff < 60) return `${diff}s ago`
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    return d.toTimeString().slice(0, 5)
  }

  const visible = pending.filter(e => !done[e.id])
  const focusedIncidentId = searchParams.get('incident_id')
  const focusedApprovalId = searchParams.get('approval_id')
  const focusedEntry = useMemo(
    () => visible.find(entry => (
      (focusedApprovalId && entry.id === focusedApprovalId) ||
      (focusedIncidentId && entry.incident_id === focusedIncidentId)
    )),
    [visible, focusedApprovalId, focusedIncidentId]
  )
  const actionColor = (t?: string) => t === 'KILL' ? '#ff2d55' : t === 'ISOLATE' ? '#ff9f0a' : '#bc8cff'

  useEffect(() => {
    if (!focusedEntry) return
    const el = document.getElementById(`approval-${focusedEntry.id}`)
    el?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [focusedEntry])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: '#0d1117', fontFamily: 'Inter, sans-serif' }}>
      <style>{`
        @keyframes fadeInUp { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
        @keyframes glowpulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes spin { to { transform: rotate(360deg) } }
        @keyframes approveExit {
          0% { opacity: 1; max-height: 220px; transform: translateX(0) scale(1); }
          35% { background: rgba(0,255,159,0.1); }
          100% { opacity: 0; max-height: 0; transform: translateX(12px) scale(0.98); margin: 0; padding-top: 0; padding-bottom: 0; }
        }
        @keyframes rejectExit {
          0% { opacity: 1; max-height: 220px; transform: translateX(0) scale(1); }
          20% { background: rgba(255,45,85,0.12); box-shadow: 0 0 0 1px rgba(255,45,85,0.25), 0 0 18px rgba(255,45,85,0.14); }
          50% { transform: translateX(-10px) scale(0.995); }
          100% { opacity: 0; max-height: 0; transform: translateX(26px) scale(0.96); margin: 0; padding-top: 0; padding-bottom: 0; }
        }
      `}</style>

      {/* Header */}
      <div style={{ padding: '12px 20px', borderBottom: '1px solid rgba(0,255,159,0.08)', display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>
        <span style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>✓ Approval Queue</span>
        {visible.length > 0 && (
          <span style={{ fontSize: '9px', fontWeight: 700, color: '#ff9f0a', background: 'rgba(255,159,10,0.15)', border: '1px solid rgba(255,159,10,0.3)', padding: '2px 8px', borderRadius: '10px', fontFamily: 'JetBrains Mono, monospace' }}>
            {visible.length} pending
          </span>
        )}
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: '8px', color: '#3d4a5f', fontFamily: 'JetBrains Mono, monospace' }}>
          {lastRefresh ? `refreshed ${lastRefresh}` : ''}
        </span>
        <button
          onClick={simulateApproval}
          disabled={simulating}
          style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', background: simulating ? 'rgba(188,140,255,0.14)' : 'rgba(188,140,255,0.08)', border: '1px solid rgba(188,140,255,0.25)', borderRadius: '6px', color: '#bc8cff', cursor: simulating ? 'not-allowed' : 'pointer', padding: '3px 10px', fontSize: '9px', fontFamily: 'JetBrains Mono, monospace', transition: 'all 0.15s' }}
        >
          {simulating ? (
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#bc8cff" strokeWidth="2.5" strokeLinecap="round" style={{ animation: 'spin 0.7s linear infinite', flexShrink: 0 }}><path d="M21 12a9 9 0 1 1-6.219-8.56" /></svg>
          ) : (
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#bc8cff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 5v4l3-3m-3 3-3-3"/><circle cx="12" cy="12" r="9" strokeDasharray="4 2"/></svg>
          )}
          {simulating ? 'Queuing...' : 'Simulate approval'}
        </button>
        <button
          onClick={manualRefresh}
          disabled={refreshing}
          style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', background: refreshing ? 'rgba(0,255,159,0.06)' : 'transparent', border: '1px solid rgba(0,255,159,0.2)', borderRadius: '6px', color: '#00ff9f', cursor: refreshing ? 'not-allowed' : 'pointer', padding: '3px 10px', fontSize: '9px', fontFamily: 'JetBrains Mono, monospace', transition: 'all 0.15s', opacity: refreshing ? 0.7 : 1 }}
        >
          <RefreshCw size={11} style={{ animation: refreshing ? 'spin 0.7s linear infinite' : 'none' } as React.CSSProperties} />
          {refreshing ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {/* Context banner */}
      <div style={{ padding: '8px 20px', borderBottom: '1px solid rgba(0,255,159,0.04)', background: 'rgba(188,140,255,0.04)', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#bc8cff', boxShadow: '0 0 6px #bc8cff', animation: 'glowpulse 2s infinite', flexShrink: 0 }} />
        <span style={{ fontSize: '10px', color: '#bc8cff', fontFamily: 'JetBrains Mono, monospace' }}>Human-in-the-loop</span>
        <span style={{ fontSize: '10px', color: '#5a6478' }}>— Argus AI escalates threats that require human judgment. Review and approve or reject each proposed action.</span>
      </div>

      {focusedIncidentId && (
        <div style={{ padding: '10px 20px', borderBottom: '1px solid rgba(88,166,255,0.08)', background: focusedEntry ? 'rgba(88,166,255,0.05)' : 'rgba(255,159,10,0.06)', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '9px', color: focusedEntry ? '#58a6ff' : '#ff9f0a', fontFamily: 'JetBrains Mono, monospace' }}>
            {focusedEntry ? 'Focused approval request' : 'Approval request not currently pending'}
          </span>
          <span style={{ fontSize: '9px', color: '#5a6478', fontFamily: 'JetBrains Mono, monospace' }}>
            {focusedIncidentId}
          </span>
          <button
            onClick={() => setSearchParams({})}
            style={{ marginLeft: 'auto', background: 'transparent', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px', color: '#8b949e', cursor: 'pointer', padding: '3px 8px', fontSize: '8px', fontFamily: 'JetBrains Mono, monospace' }}
          >
            Clear focus
          </button>
        </div>
      )}

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '18px 20px 28px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
        {loading && (
          <div style={{ color: '#4a5568', fontSize: '10px', textAlign: 'center', padding: '40px', fontFamily: 'JetBrains Mono, monospace' }}>
            Loading approval queue...
          </div>
        )}

        {!loading && visible.length === 0 && <EmptyState />}

        {visible.map(entry => {
          const sev = SEV_CONFIG[entry.severity || 'LOW'] || SEV_CONFIG.LOW
          const isDone = done[entry.id]
          const isActing = acting[entry.id]
          const isFocused = (
            (focusedApprovalId && entry.id === focusedApprovalId) ||
            (focusedIncidentId && entry.incident_id === focusedIncidentId)
          )

          return (
            <div
              key={entry.id}
              id={`approval-${entry.id}`}
              style={{
                background: isDone === 'approved' ? 'rgba(0,255,159,0.06)' : isDone === 'rejected' ? 'rgba(255,45,85,0.06)' : isFocused ? 'rgba(88,166,255,0.08)' : '#111827',
                border: `1px solid ${isDone === 'approved' ? 'rgba(0,255,159,0.3)' : isDone === 'rejected' ? 'rgba(255,45,85,0.3)' : isFocused ? 'rgba(88,166,255,0.42)' : sev.border}`,
                borderRadius: '10px',
                padding: '14px 16px 18px',
                animation: isDone === 'approved'
                  ? 'approveExit 0.55s ease-out 0.5s forwards'
                  : isDone === 'rejected'
                    ? 'rejectExit 0.65s ease-out 0.3s forwards'
                    : 'fadeInUp 0.3s ease-out',
                transition: 'all 0.3s',
                position: 'relative',
                overflow: 'visible',
                boxShadow: isFocused ? '0 0 0 1px rgba(88,166,255,0.14), 0 10px 24px rgba(0,0,0,0.22)' : 'none',
                transformOrigin: 'top',
                minHeight: '138px',
              }}
            >
              {/* Severity stripe */}
              <div style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: '3px', background: sev.color, borderRadius: '3px 0 0 3px' }} />

              <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 180px', alignItems: 'center', gap: '16px', minHeight: '104px' }}>
                <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                  {/* Top row */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '9px', fontWeight: 700, padding: '2px 8px', borderRadius: '3px', background: sev.bg, color: sev.color, border: `1px solid ${sev.border}`, fontFamily: 'JetBrains Mono, monospace' }}>
                      ● {entry.severity || 'UNKNOWN'}
                    </span>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', padding: '2px 8px', borderRadius: '4px', background: `${actionColor(entry.action_type)}18`, border: `1px solid ${actionColor(entry.action_type)}40`, fontSize: '9px', fontWeight: 700, color: actionColor(entry.action_type), fontFamily: 'JetBrains Mono, monospace' }}>
                      <ActionIcon type={entry.action_type} />
                      {entry.action_type || 'REVIEW'}
                    </span>
                    {entry.namespace && (
                      <span style={{ fontSize: '8px', color: '#58a6ff', background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.2)', padding: '2px 6px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace' }}>
                        {entry.namespace}
                      </span>
                    )}
                  </div>

                  {/* Rule */}
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#f0f6fc', marginBottom: '7px', lineHeight: 1.32 }}>
                    {entry.rule || 'Security Action Requires Review'}
                  </div>

                  {/* Detail */}
                  {entry.action_detail && (
                    <div style={{ fontSize: '10px', color: '#6b7280', lineHeight: 1.45, marginBottom: '7px', fontFamily: 'JetBrains Mono, monospace', background: 'rgba(0,0,0,0.3)', padding: '8px 10px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.04)' }}>
                      {entry.action_detail}
                    </div>
                  )}

                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '8px' }}>
                    {entry.pod && (
                      <div style={{ fontSize: '9px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace', padding: '4px 8px', borderRadius: '4px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.05)' }}>
                        Pod: <span style={{ color: '#8b949e' }}>{entry.pod}</span>
                      </div>
                    )}
                    {entry.incident_id && (
                      <div style={{ fontSize: '9px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace', padding: '4px 8px', borderRadius: '4px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.05)' }}>
                        Incident: <span style={{ color: '#58a6ff' }}>{entry.incident_id.slice(0, 10)}</span>
                      </div>
                    )}
                  </div>

                </div>

                {/* Action buttons */}
                {!isDone && (
                  <div style={{
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'center',
                    gap: '12px',
                    width: '180px',
                    alignSelf: 'center',
                    padding: '4px 0',
                  }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', alignItems: 'flex-end', paddingRight: '2px' }}>
                      <div style={{ fontSize: '7px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', fontFamily: 'JetBrains Mono, monospace' }}>
                        Decision
                      </div>
                      <div style={{ fontSize: '8px', color: '#8b949e', fontFamily: 'JetBrains Mono, monospace' }}>
                        {fmtTs(entry.timestamp)}
                      </div>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                      <button
                        onClick={() => act(entry.id, 'approve')}
                        disabled={!!isActing}
                        style={{
                          width: '100%',
                          justifyContent: 'center',
                          padding: '10px 10px', borderRadius: '6px', cursor: isActing ? 'not-allowed' : 'pointer',
                          background: isActing === 'approving' ? 'rgba(0,255,159,0.2)' : 'rgba(0,255,159,0.1)',
                          border: '1px solid rgba(0,255,159,0.35)', color: '#00ff9f',
                          fontSize: '10px', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace',
                          transition: 'all 0.15s', display: 'flex', alignItems: 'center', gap: '5px',
                        }}
                        onMouseEnter={e => !isActing && (e.currentTarget.style.background = 'rgba(0,255,159,0.2)')}
                        onMouseLeave={e => !isActing && (e.currentTarget.style.background = 'rgba(0,255,159,0.1)')}
                      >
                        {isActing === 'approving' ? '...' : (
                          <>
                            <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="#00ff9f" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                              <polyline points="1.5 5.5 4 8 8.5 2.5"/>
                            </svg>
                            Approve
                          </>
                        )}
                      </button>
                      <button
                        onClick={() => act(entry.id, 'reject')}
                        disabled={!!isActing}
                        style={{
                          width: '100%',
                          justifyContent: 'center',
                          padding: '10px 10px', borderRadius: '6px', cursor: isActing ? 'not-allowed' : 'pointer',
                          background: isActing === 'rejecting' ? 'rgba(255,45,85,0.2)' : 'rgba(255,45,85,0.08)',
                          border: '1px solid rgba(255,45,85,0.3)', color: '#ff2d55',
                          fontSize: '10px', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace',
                          transition: 'all 0.15s', display: 'flex', alignItems: 'center', gap: '5px',
                        }}
                        onMouseEnter={e => !isActing && (e.currentTarget.style.background = 'rgba(255,45,85,0.18)')}
                        onMouseLeave={e => !isActing && (e.currentTarget.style.background = 'rgba(255,45,85,0.08)')}
                      >
                        {isActing === 'rejecting' ? '...' : (
                          <>
                            <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="#ff2d55" strokeWidth="1.8" strokeLinecap="round">
                              <line x1="2" y1="2" x2="8" y2="8"/><line x1="8" y1="2" x2="2" y2="8"/>
                            </svg>
                            Reject
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                )}

                {isDone && (
                  <div style={{
                    width: '180px',
                    padding: '10px 12px', borderRadius: '8px',
                    background: isDone === 'approved' ? 'rgba(0,255,159,0.1)' : 'rgba(255,45,85,0.1)',
                    border: `1px solid ${isDone === 'approved' ? 'rgba(0,255,159,0.3)' : 'rgba(255,45,85,0.3)'}`,
                    color: isDone === 'approved' ? '#00ff9f' : '#ff2d55',
                    fontSize: '10px', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace',
                    alignSelf: 'center',
                    textAlign: 'center',
                  }}>
                    {isDone === 'approved' ? '✓ Approved' : '✕ Rejected'}
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* Footer stats */}
      <div style={{ padding: '10px 20px', borderTop: '1px solid rgba(0,255,159,0.06)', display: 'flex', alignItems: 'center', gap: '16px', flexShrink: 0 }}>
        <span style={{ fontSize: '8px', color: '#3d4a5f', fontFamily: 'JetBrains Mono, monospace' }}>HUMAN-IN-THE-LOOP · AUTO-REFRESH 5s</span>
        <div style={{ flex: 1 }} />
        <div style={{ display: 'flex', gap: '12px' }}>
          <span style={{ fontSize: '9px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>
            <span style={{ color: '#ff9f0a', fontWeight: 700 }}>{visible.length}</span> pending
          </span>
        </div>
      </div>

      <style>{`
        ::-webkit-scrollbar { width: 2px; }
        ::-webkit-scrollbar-thumb { background: rgba(0,255,159,0.15); border-radius: 1px; }
      `}</style>
    </div>
  )
}
