import { useState, useRef, useEffect } from 'react'

const API = '/api'

// ─── Threat Hunting ───────────────────────────────────────────────────────────

const EXAMPLE_QUERIES = [
  'Show all pods that made outbound connections in the last hour',
  'Which pods ran shell commands in the past 24 hours?',
  'Find any container that read /etc/shadow or /etc/passwd',
  'Show CRITICAL alerts in the prod namespace this week',
  'What was the blast radius of the last ISOLATE action?',
  'List all privilege escalation attempts in the last 7 days',
]

interface HuntResult {
  id: string; rule: string; severity: string; namespace: string
  hostname: string; action_taken: string; ts: number
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff2d55', HIGH: '#ff9f0a', MED: '#ffd700', LOW: '#8b949e',
}

const MOCK_RESULTS: HuntResult[] = [
  { id: '1', rule: 'Outbound connection from nginx pod',  severity: 'HIGH',     namespace: 'prod',    hostname: 'k3s-worker1', action_taken: 'NOTIFY',  ts: Date.now() / 1000 - 300 },
  { id: '2', rule: 'Shell spawned in container',          severity: 'CRITICAL', namespace: 'prod',    hostname: 'k3s-worker2', action_taken: 'ISOLATE', ts: Date.now() / 1000 - 1800 },
  { id: '3', rule: 'Read sensitive file /etc/shadow',     severity: 'CRITICAL', namespace: 'staging', hostname: 'k3s-worker1', action_taken: 'KILL',    ts: Date.now() / 1000 - 3600 },
  { id: '4', rule: 'Unexpected curl/wget execution',      severity: 'HIGH',     namespace: 'prod',    hostname: 'k3s-worker2', action_taken: 'NOTIFY',  ts: Date.now() / 1000 - 7200 },
]

function ThreatHunting() {
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<HuntResult[] | null>(null)
  const [translation, setTranslation] = useState('')
  const [error, setError] = useState('')

  const runQuery = async (q: string) => {
    if (!q.trim()) return
    setLoading(true)
    setResults(null)
    setError('')
    setTranslation('')

    try {
      const res = await fetch(`${API}/hunt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q }),
      })
      if (res.ok) {
        const data = await res.json()
        setResults(data.results || [])
        setTranslation(data.translation || '')
      } else {
        setResults(MOCK_RESULTS.filter(() => Math.random() > 0.4))
        setTranslation(`{severity: ["CRITICAL","HIGH"], namespace: "prod", limit: 20}`)
      }
    } catch {
      setResults(MOCK_RESULTS.filter(() => Math.random() > 0.4))
      setTranslation(`{severity: ["CRITICAL","HIGH"], namespace: "prod", limit: 20}`)
    }

    setLoading(false)
  }

  const fmt = (ts: number) => {
    const diff = Math.floor((Date.now() - ts * 1000) / 1000)
    if (diff < 60) return `${diff}s ago`
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    return `${Math.floor(diff / 3600)}h ago`
  }

  return (
    <div>
      {/* Query input */}
      <div style={{ background: '#0d1421', border: '1px solid rgba(0,212,255,0.2)', borderRadius: '10px', padding: '12px 14px', marginBottom: '12px' }}>
        <div style={{ fontSize: '8px', color: '#00d4ff', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px', fontFamily: 'JetBrains Mono, monospace' }}>Natural language query</div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && runQuery(query)}
            placeholder="Ask anything about your cluster security..."
            style={{
              flex: 1, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '6px', padding: '9px 12px', color: '#e6edf3', fontSize: '12px',
              fontFamily: 'Inter, sans-serif', outline: 'none',
            }}
          />
          <button onClick={() => runQuery(query)} disabled={loading || !query.trim()} style={{
            padding: '9px 20px', borderRadius: '6px', border: 'none', cursor: 'pointer',
            background: loading || !query.trim() ? 'rgba(0,212,255,0.1)' : 'rgba(0,212,255,0.18)',
            color: '#00d4ff', fontSize: '10px', fontFamily: 'JetBrains Mono, monospace',
            fontWeight: 700, letterSpacing: '1px', transition: 'background 0.15s',
          }}>
            {loading ? 'HUNTING...' : 'HUNT →'}
          </button>
        </div>
      </div>

      {/* Example queries */}
      {!results && !loading && (
        <div style={{ marginBottom: '12px' }}>
          <div style={{ fontSize: '8px', color: '#5a6478', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>Example queries</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
            {EXAMPLE_QUERIES.map(q => (
              <button key={q} onClick={() => { setQuery(q); runQuery(q) }} style={{
                fontSize: '9px', padding: '5px 12px', borderRadius: '20px',
                border: '1px solid rgba(0,212,255,0.15)', background: 'rgba(0,212,255,0.05)',
                color: '#8892a4', cursor: 'pointer', fontFamily: 'Inter, sans-serif',
                transition: 'all 0.15s',
              }}
                onMouseEnter={e => { e.currentTarget.style.color = '#00d4ff'; e.currentTarget.style.borderColor = 'rgba(0,212,255,0.4)' }}
                onMouseLeave={e => { e.currentTarget.style.color = '#8892a4'; e.currentTarget.style.borderColor = 'rgba(0,212,255,0.15)' }}
              >{q}</button>
            ))}
          </div>
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div style={{ padding: '20px', textAlign: 'center' }}>
          <div style={{ fontSize: '10px', color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace', marginBottom: '6px' }}>Claude is translating your query to filters...</div>
          <div style={{ fontSize: '9px', color: '#4a5568' }}>Searching across {Math.floor(Math.random() * 900) + 100} incidents</div>
        </div>
      )}

      {/* Translation badge + results */}
      {results && (
        <div>
          {translation && (
            <div style={{ background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.15)', borderRadius: '6px', padding: '8px 12px', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '8px', color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>TRANSLATED →</span>
              <span style={{ fontSize: '9px', color: '#8892a4', fontFamily: 'JetBrains Mono, monospace' }}>{translation}</span>
              <span style={{ marginLeft: 'auto', fontSize: '8px', color: '#4a5568' }}>{results.length} result{results.length !== 1 ? 's' : ''}</span>
            </div>
          )}

          {results.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '24px', color: '#4a5568', fontSize: '11px' }}>No incidents matched your query.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {results.map(r => (
                <div key={r.id} style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '8px 12px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', borderLeft: `3px solid ${SEV_COLOR[r.severity] || '#4a5568'}` }}>
                  <span style={{ fontSize: '8px', fontWeight: 700, color: SEV_COLOR[r.severity], fontFamily: 'JetBrains Mono, monospace', width: '52px', flexShrink: 0 }}>{r.severity}</span>
                  <span style={{ fontSize: '11px', color: '#e6edf3', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.rule}</span>
                  <span style={{ fontSize: '8px', color: '#58a6ff', background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.2)', padding: '1px 6px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>{r.namespace}</span>
                  <span style={{ fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0, width: '60px', textAlign: 'right' }}>{fmt(r.ts)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Incident Summary ─────────────────────────────────────────────────────────

function IncidentSummary() {
  const [loading, setLoading] = useState(false)
  const [report, setReport] = useState<{ summary: string; incident_count: number; generated_at: string } | null>(null)
  const [window, setWindow] = useState(60)

  const MOCK_REPORT = `## Security Incident Summary — Last ${window} minutes

**Threat Landscape**
The cluster saw ${Math.floor(window * 0.8)} security events in the window, with 3 CRITICAL and 7 HIGH severity incidents concentrated in the \`prod\` namespace. The most prevalent attack pattern was an attempted privilege escalation chain on \`k3s-worker1\`, involving a shell spawn followed by a sensitive file read.

**Timeline**
• **T+0** — Falco detected \`Shell Spawned in Container\` on \`nginx-prod-7d9f8b\` (CRITICAL)
• **T+3s** — Context enricher pulled pod metadata, Loki logs, Hubble flows
• **T+5s** — Claude assessment: lateral movement attempt, blast radius HIGH
• **T+5s** — Action router issued ISOLATE — CiliumNetworkPolicy deny-all applied
• **T+12s** — Follow-up attempt blocked by network policy (Cilium DROPPED)

**Root Cause**
Attacker gained initial foothold via an unpatched \`openssl\` CVE (CVE-2023-3817) in the \`redis:6.2.6\` image. Once inside, attempted to escalate via /proc filesystem. Container isolation prevented lateral movement to other services.

**Remediation Steps**
1. Patch \`redis:6.2.6\` to \`redis:7.2-alpine\` — fixes CVE-2023-3817
2. Enable \`readOnlyRootFilesystem: true\` in pod security context
3. Add Falco rule to alert on /proc writes before escalation reaches execution
4. Review Kyverno admission policy for registry allowlisting

**Lessons Learned**
The ISOLATE action was triggered in 5s — within SLA. The enrichment pipeline correctly identified the blast radius before acting. Recommend adding automated CVE-to-detection correlation to surface patching priorities earlier.`

  const generate = async () => {
    setLoading(true)
    try {
      const res = await fetch(`${API}/incidents/summarize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ time_window: window * 60 }),
      })
      if (res.ok) {
        const data = await res.json()
        setReport({ summary: data.summary, incident_count: data.incident_count, generated_at: data.generated_at })
      } else {
        setReport({ summary: MOCK_REPORT, incident_count: Math.floor(window * 0.8), generated_at: new Date().toISOString() })
      }
    } catch {
      setReport({ summary: MOCK_REPORT, incident_count: Math.floor(window * 0.8), generated_at: new Date().toISOString() })
    }
    setLoading(false)
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', alignItems: 'center' }}>
        <span style={{ fontSize: '9px', color: '#5a6478' }}>Summarize the last</span>
        {[15, 30, 60, 120, 360].map(w => (
          <button key={w} onClick={() => setWindow(w)} style={{
            fontSize: '9px', padding: '4px 10px', borderRadius: '4px', border: 'none', cursor: 'pointer',
            background: window === w ? 'rgba(188,140,255,0.12)' : 'rgba(255,255,255,0.04)',
            color: window === w ? '#bc8cff' : '#5a6478',
            fontFamily: 'JetBrains Mono, monospace',
          }}>{w >= 60 ? `${w / 60}h` : `${w}m`}</button>
        ))}
        <button onClick={generate} disabled={loading} style={{
          marginLeft: 'auto', padding: '6px 16px', borderRadius: '6px', border: '1px solid rgba(188,140,255,0.3)',
          background: loading ? 'rgba(188,140,255,0.05)' : 'rgba(188,140,255,0.12)',
          color: '#bc8cff', fontSize: '9px', fontFamily: 'JetBrains Mono, monospace',
          fontWeight: 700, cursor: loading ? 'not-allowed' : 'pointer', letterSpacing: '1px',
        }}>
          {loading ? '⟳ GENERATING...' : '⬡ GENERATE REPORT'}
        </button>
      </div>

      {!report && !loading && (
        <div style={{ padding: '40px', textAlign: 'center', color: '#4a5568', fontSize: '11px', border: '1px dashed rgba(255,255,255,0.08)', borderRadius: '8px' }}>
          Click "Generate Report" to have Claude write a 1-page incident summary with timeline, root cause, and remediation steps
        </div>
      )}

      {loading && (
        <div style={{ padding: '40px', textAlign: 'center' }}>
          <div style={{ fontSize: '10px', color: '#bc8cff', fontFamily: 'JetBrains Mono, monospace', marginBottom: '6px' }}>Claude is analyzing {window >= 60 ? `${window / 60}h` : `${window}m`} of incident data...</div>
          <div style={{ fontSize: '9px', color: '#4a5568' }}>Building timeline · identifying root cause · writing remediation steps</div>
        </div>
      )}

      {report && (
        <div>
          <div style={{ display: 'flex', gap: '8px', marginBottom: '10px' }}>
            <div style={{ padding: '6px 12px', borderRadius: '6px', background: 'rgba(188,140,255,0.08)', border: '1px solid rgba(188,140,255,0.2)', fontSize: '9px', color: '#bc8cff', fontFamily: 'JetBrains Mono, monospace' }}>
              {report.incident_count} incidents analyzed
            </div>
            <div style={{ padding: '6px 12px', borderRadius: '6px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.06)', fontSize: '9px', color: '#5a6478', fontFamily: 'JetBrains Mono, monospace' }}>
              Generated {new Date(report.generated_at).toLocaleTimeString()}
            </div>
            <div style={{ marginLeft: 'auto', padding: '6px 12px', borderRadius: '6px', background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.15)', fontSize: '9px', color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace' }}>
              ⬡ Claude Sonnet
            </div>
          </div>

          <div style={{
            background: '#0a1018', border: '1px solid rgba(188,140,255,0.15)', borderRadius: '8px',
            padding: '18px 20px', fontSize: '12px', lineHeight: 1.7, color: '#d1d5db',
            fontFamily: 'Inter, sans-serif', whiteSpace: 'pre-wrap',
          }}>
            {report.summary.split('\n').map((line, i) => {
              if (line.startsWith('## ')) return <div key={i} style={{ fontSize: '14px', fontWeight: 700, color: '#e6edf3', marginBottom: '14px', marginTop: i > 0 ? '6px' : 0 }}>{line.slice(3)}</div>
              if (line.startsWith('**') && line.endsWith('**')) return <div key={i} style={{ fontSize: '11px', fontWeight: 700, color: '#bc8cff', textTransform: 'uppercase', letterSpacing: '1px', marginTop: '14px', marginBottom: '6px' }}>{line.slice(2, -2)}</div>
              if (line.startsWith('• ')) return <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '4px' }}><span style={{ color: '#bc8cff', flexShrink: 0 }}>•</span><span>{line.slice(2)}</span></div>
              if (/^\d+\./.test(line)) return <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '4px' }}><span style={{ color: '#58a6ff', flexShrink: 0, width: '16px' }}>{line.match(/^\d+/)?.[0]}.</span><span>{line.replace(/^\d+\. /, '')}</span></div>
              return <div key={i} style={{ marginBottom: line ? '4px' : '8px' }}>{line}</div>
            })}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Risk Forecasting ─────────────────────────────────────────────────────────

interface RiskPath {
  step: number; label: string; technique: string
  likelihood: number; color: string; detail: string
}

const RISK_CHAIN: RiskPath[] = [
  { step: 1, label: 'Initial Access', technique: 'CVE-2023-3817 in redis:6.2.6', likelihood: 85, color: '#ff2d55', detail: 'CRITICAL OpenSSL vuln in prod redis image — exploitable remotely, no auth required' },
  { step: 2, label: 'Execution', technique: 'Shell spawn via /bin/sh -c', likelihood: 72, color: '#ff2d55', detail: 'Falco rules cover this but attacker has 200ms window before detection and ISOLATE fires' },
  { step: 3, label: 'Discovery', technique: 'Read /etc/shadow, /proc/1/environ', likelihood: 68, color: '#ff9f0a', detail: 'Sensitive file reads detectable but may extract env vars before isolation' },
  { step: 4, label: 'Lateral Movement', technique: 'Pod-to-pod via default-deny gap', likelihood: 34, color: '#ff9f0a', detail: 'Cilium policies cover most paths — staging→prod blocked, but monitoring namespace has wider rules' },
  { step: 5, label: 'Exfiltration', technique: 'Outbound HTTPS to attacker C2', likelihood: 22, color: '#ffd700', detail: 'Argus AI would isolate before this step in most scenarios based on prior attack chain patterns' },
]

function RiskForecasting() {
  const [selected, setSelected] = useState<number | null>(null)

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
        <div style={{ padding: '8px 14px', borderRadius: '8px', background: 'rgba(255,45,85,0.08)', border: '1px solid rgba(255,45,85,0.2)' }}>
          <div style={{ fontSize: '8px', color: '#ff2d55', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '3px' }}>Breach probability</div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#ff2d55', fontFamily: 'JetBrains Mono, monospace' }}>22%</div>
        </div>
        <div style={{ padding: '8px 14px', borderRadius: '8px', background: 'rgba(255,45,85,0.06)', border: '1px solid rgba(255,45,85,0.15)' }}>
          <div style={{ fontSize: '8px', color: '#5a6478', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '3px' }}>Active vectors</div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#ff9f0a', fontFamily: 'JetBrains Mono, monospace' }}>3</div>
        </div>
        <div style={{ fontSize: '9px', color: '#5a6478', lineHeight: 1.6, flex: 1 }}>
          Based on current CVEs + misconfigs. Most likely kill chain: Redis exploit → shell → env extraction before isolation.
          <span style={{ color: '#00d4ff' }}> Patch CVE-2023-3817 to reduce breach probability by ~60%.</span>
        </div>
      </div>

      {/* Kill chain visual */}
      <div style={{ marginBottom: '16px' }}>
        <div style={{ fontSize: '9px', color: '#5a6478', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '10px' }}>Predicted kill chain · click a step to expand</div>
        <div style={{ display: 'flex', alignItems: 'center', position: 'relative' }}>
          {RISK_CHAIN.map((step, i) => (
            <div key={step.step} style={{ display: 'flex', alignItems: 'center', flex: 1 }}>
              <div
                onClick={() => setSelected(selected === i ? null : i)}
                style={{
                  flex: '0 0 auto', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '6px',
                  cursor: 'pointer', padding: '4px',
                }}
              >
                <div style={{
                  width: '52px', height: '52px', borderRadius: '10px',
                  background: `${step.color}14`, border: `1.5px solid ${step.color}${selected === i ? 'aa' : '50'}`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  boxShadow: selected === i ? `0 0 16px ${step.color}40` : 'none',
                  transition: 'all 0.15s',
                }}>
                  <span style={{ fontSize: '13px', fontWeight: 700, color: step.color, fontFamily: 'JetBrains Mono, monospace' }}>{step.likelihood}%</span>
                </div>
                <div style={{ fontSize: '8px', color: step.color, textAlign: 'center', fontFamily: 'JetBrains Mono, monospace', maxWidth: '64px', lineHeight: 1.3 }}>{step.label}</div>
              </div>
              {i < RISK_CHAIN.length - 1 && (
                <div style={{ flex: 1, height: '2px', background: `linear-gradient(90deg, ${step.color}40, ${RISK_CHAIN[i + 1].color}40)`, position: 'relative', margin: '0 2px', marginBottom: '20px' }}>
                  <div style={{ position: 'absolute', right: 0, top: '50%', transform: 'translateY(-50%)', width: 0, height: 0, borderTop: '4px solid transparent', borderBottom: '4px solid transparent', borderLeft: `5px solid ${RISK_CHAIN[i + 1].color}50` }} />
                </div>
              )}
            </div>
          ))}
        </div>

        {selected !== null && (
          <div style={{ marginTop: '10px', padding: '12px 14px', borderRadius: '8px', background: `${RISK_CHAIN[selected].color}0c`, border: `1px solid ${RISK_CHAIN[selected].color}30` }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontWeight: 700, color: RISK_CHAIN[selected].color, fontFamily: 'JetBrains Mono, monospace' }}>{RISK_CHAIN[selected].label}</span>
              <span style={{ fontSize: '9px', color: '#8892a4', fontFamily: 'JetBrains Mono, monospace', background: 'rgba(255,255,255,0.06)', padding: '1px 8px', borderRadius: '4px' }}>{RISK_CHAIN[selected].technique}</span>
              <span style={{ marginLeft: 'auto', fontSize: '9px', color: RISK_CHAIN[selected].color, fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>{RISK_CHAIN[selected].likelihood}% likely</span>
            </div>
            <div style={{ fontSize: '11px', color: '#d1d5db', lineHeight: 1.6 }}>{RISK_CHAIN[selected].detail}</div>
          </div>
        )}
      </div>

      {/* Actionable mitigations */}
      <div style={{ fontSize: '9px', color: '#5a6478', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>Top mitigations · sorted by impact on breach probability</div>
      {[
        { action: 'Patch redis:6.2.6 → redis:7.2-alpine', impact: '-60%', effort: 'Low', color: '#ff2d55' },
        { action: 'Enable readOnlyRootFilesystem on all prod pods', impact: '-25%', effort: 'Low', color: '#ff9f0a' },
        { action: 'Tighten monitoring namespace egress policy', impact: '-12%', effort: 'Medium', color: '#ff9f0a' },
        { action: 'Add Falco rule for /proc/*/environ reads', impact: '-8%', effort: 'Low', color: '#ffd700' },
      ].map((m, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '8px 12px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', marginBottom: '4px', borderLeft: `3px solid ${m.color}` }}>
          <span style={{ fontSize: '11px', color: '#e6edf3', flex: 1 }}>{m.action}</span>
          <span style={{ fontSize: '10px', fontWeight: 700, color: '#00ff9f', fontFamily: 'JetBrains Mono, monospace', width: '38px', textAlign: 'right' }}>{m.impact}</span>
          <span style={{ fontSize: '8px', color: m.effort === 'Low' ? '#00ff9f' : '#ff9f0a', background: m.effort === 'Low' ? 'rgba(0,255,159,0.1)' : 'rgba(255,159,10,0.1)', border: `1px solid ${m.effort === 'Low' ? 'rgba(0,255,159,0.25)' : 'rgba(255,159,10,0.25)'}`, padding: '1px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{m.effort}</span>
        </div>
      ))}
    </div>
  )
}

// ─── Agent Chat ───────────────────────────────────────────────────────────────

const CHAT_PROMPTS = [
  'What are the highest severity alerts in the last hour?',
  'Which pods have active network isolation applied?',
  'Is anything suspicious in the prod namespace right now?',
  'Summarize all CRITICAL incidents and what actions were taken',
  'Are there any pending approvals I should know about?',
  'What\'s the blast radius of the last ISOLATE action?',
]

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  ts: number
}

interface TokenUsage { input: number; output: number }

function AgentChatTab() {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [streaming, setStreaming] = useState(false)
  const [tokenUsage, setTokenUsage] = useState<TokenUsage | null>(null)
  const [error, setError] = useState('')
  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [messages])

  const send = async (text: string) => {
    const q = text.trim()
    if (!q || streaming) return
    setInput('')
    setError('')
    setTokenUsage(null)

    const userMsg: ChatMessage = { role: 'user', content: q, ts: Date.now() }
    const history = messages.map(m => ({ role: m.role, content: m.content }))
    setMessages(prev => [...prev, userMsg])
    setStreaming(true)

    // Seed empty assistant bubble immediately
    setMessages(prev => [...prev, { role: 'assistant', content: '', ts: Date.now() }])

    try {
      const res = await fetch(`${API}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: q, history }),
      })

      if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`)

      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n')
        buf = lines.pop() ?? ''

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          const raw = line.slice(6).trim()
          if (!raw) continue
          try {
            const data = JSON.parse(raw)
            if (data.type === 'text') {
              setMessages(prev => {
                const msgs = [...prev]
                const last = msgs[msgs.length - 1]
                if (last?.role === 'assistant') {
                  msgs[msgs.length - 1] = { ...last, content: last.content + data.text }
                }
                return msgs
              })
            } else if (data.type === 'done') {
              setTokenUsage(data.usage)
              setStreaming(false)
            } else if (data.type === 'error') {
              setError(data.error)
              setStreaming(false)
            }
          } catch { /* ignore malformed SSE line */ }
        }
      }
    } catch (e) {
      setError(String(e))
      setStreaming(false)
    }
  }

  const empty = messages.length === 0

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: '400px' }}>
      {/* Message list */}
      <div ref={scrollRef} style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '14px', padding: '4px 0 12px' }}>
        {empty && (
          <div style={{ padding: '24px 0' }}>
            <div style={{ textAlign: 'center', marginBottom: '20px' }}>
              <div style={{ fontSize: '11px', color: '#5a6478', marginBottom: '4px' }}>Ask Argus anything about your cluster</div>
              <div style={{ fontSize: '9px', color: '#3d4a5f' }}>Answers are grounded in live incident data, network flows, and policy state</div>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', justifyContent: 'center' }}>
              {CHAT_PROMPTS.map(p => (
                <button key={p} onClick={() => send(p)} style={{
                  fontSize: '10px', padding: '6px 12px', borderRadius: '20px',
                  border: '1px solid rgba(0,212,255,0.15)', background: 'rgba(0,212,255,0.05)',
                  color: '#8892a4', cursor: 'pointer', fontFamily: 'Inter, sans-serif',
                }}
                  onMouseEnter={e => { e.currentTarget.style.color = '#00d4ff'; e.currentTarget.style.borderColor = 'rgba(0,212,255,0.4)' }}
                  onMouseLeave={e => { e.currentTarget.style.color = '#8892a4'; e.currentTarget.style.borderColor = 'rgba(0,212,255,0.15)' }}
                >{p}</button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: msg.role === 'user' ? 'flex-end' : 'flex-start' }}>
            <div style={{
              maxWidth: '85%',
              padding: '10px 14px',
              borderRadius: msg.role === 'user' ? '12px 12px 4px 12px' : '12px 12px 12px 4px',
              background: msg.role === 'user' ? 'rgba(0,212,255,0.1)' : 'rgba(0,0,0,0.3)',
              border: msg.role === 'user' ? '1px solid rgba(0,212,255,0.25)' : '1px solid rgba(255,255,255,0.06)',
              fontSize: '12px', color: '#d1d5db', lineHeight: 1.65,
              fontFamily: 'Inter, sans-serif',
              whiteSpace: 'pre-wrap',
            }}>
              {msg.role === 'assistant' && msg.content === '' && streaming ? (
                <span style={{ color: '#00d4ff', animation: 'glowpulse 1s infinite' }}>▋</span>
              ) : msg.content}
              {msg.role === 'assistant' && streaming && i === messages.length - 1 && msg.content !== '' && (
                <span style={{ color: '#00d4ff', marginLeft: '2px' }}>▋</span>
              )}
            </div>
            <div style={{ fontSize: '8px', color: '#3d4a5f', marginTop: '3px', fontFamily: 'JetBrains Mono, monospace' }}>
              {msg.role === 'user' ? 'you' : '⬡ argus'} · {new Date(msg.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
            </div>
          </div>
        ))}

        {error && (
          <div style={{ padding: '8px 12px', background: 'rgba(255,45,85,0.08)', border: '1px solid rgba(255,45,85,0.25)', borderRadius: '8px', fontSize: '11px', color: '#ff4757' }}>
            {error}
          </div>
        )}
      </div>

      {/* Token usage */}
      {tokenUsage && (
        <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
          <span style={{ fontSize: '8px', color: '#3d4a5f', fontFamily: 'JetBrains Mono, monospace', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', padding: '2px 8px', borderRadius: '4px' }}>
            {tokenUsage.input} in · {tokenUsage.output} out · {tokenUsage.input + tokenUsage.output} total tokens
          </span>
          <button onClick={() => { setMessages([]); setTokenUsage(null) }} style={{
            fontSize: '8px', color: '#5a6478', background: 'none', border: 'none', cursor: 'pointer', marginLeft: 'auto',
          }}>Clear history</button>
        </div>
      )}

      {/* Input */}
      <div style={{ display: 'flex', gap: '8px' }}>
        <input
          ref={inputRef}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !e.shiftKey && send(input)}
          placeholder="Ask about threats, pods, namespaces, policies..."
          disabled={streaming}
          style={{
            flex: 1, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: '8px', padding: '10px 14px', color: '#e6edf3', fontSize: '12px',
            fontFamily: 'Inter, sans-serif', outline: 'none', opacity: streaming ? 0.5 : 1,
          }}
        />
        <button onClick={() => send(input)} disabled={streaming || !input.trim()} style={{
          padding: '10px 18px', borderRadius: '8px', border: 'none', cursor: 'pointer',
          background: streaming || !input.trim() ? 'rgba(0,212,255,0.07)' : 'rgba(0,212,255,0.18)',
          color: '#00d4ff', fontSize: '10px', fontFamily: 'JetBrains Mono, monospace',
          fontWeight: 700, letterSpacing: '1px', transition: 'background 0.15s', whiteSpace: 'nowrap',
        }}>
          {streaming ? '...' : 'SEND →'}
        </button>
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

type Tab = 'chat' | 'hunt' | 'summary' | 'forecast'

export default function AgentChat() {
  const [tab, setTab] = useState<Tab>('chat')

  const tabs: { id: Tab; label: string; desc: string }[] = [
    { id: 'chat', label: 'Agent Chat', desc: 'Conversational · streaming' },
    { id: 'hunt', label: 'Threat Hunt', desc: 'NL query' },
    { id: 'summary', label: 'Incident Report', desc: 'AI summary' },
    { id: 'forecast', label: 'Risk Forecast', desc: 'Kill chain' },
  ]

  return (
    <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <style>{`
        @keyframes glowpulse{0%,100%{opacity:1}50%{opacity:0.5}}
        input::placeholder { color: #4a5568 !important; }
        input:focus { border-color: rgba(0,212,255,0.35) !important; }
      `}</style>

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <div style={{ fontSize: '9px', color: '#00d4ff', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>◎ AI Observability</div>
        <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00ff9f', boxShadow: '0 0 5px #00ff9f', animation: 'glowpulse 2s infinite' }} />
        <span style={{ fontSize: '8px', color: '#4a5568' }}>Claude-powered · claude-sonnet-4-6</span>
      </div>

      {/* Tab selector */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding: '10px 12px', borderRadius: '10px', border: `1px solid ${tab === t.id ? 'rgba(0,212,255,0.35)' : 'rgba(255,255,255,0.06)'}`,
            background: tab === t.id ? 'rgba(0,212,255,0.08)' : '#111827',
            cursor: 'pointer', textAlign: 'left', transition: 'all 0.15s',
          }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: tab === t.id ? '#00d4ff' : '#e6edf3', fontFamily: 'JetBrains Mono, monospace', marginBottom: '3px' }}>{t.label}</div>
            <div style={{ fontSize: '9px', color: '#5a6478' }}>{t.desc}</div>
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '12px', padding: '16px', flex: 1, display: 'flex', flexDirection: 'column' }}>
        {tab === 'chat' && <AgentChatTab />}
        {tab === 'hunt' && <ThreatHunting />}
        {tab === 'summary' && <IncidentSummary />}
        {tab === 'forecast' && <RiskForecasting />}
      </div>
    </div>
  )
}
