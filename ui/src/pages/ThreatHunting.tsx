import { useEffect, useMemo, useState } from 'react'

const API = '/api'

interface QueryResult {
  query: string
  results: any[]
  source: 'hubble' | 'loki' | 'k8s'
  timestamp: string
  explanation?: string
}

interface QueryHistoryEntry {
  id: string
  query: string
  source?: 'hubble' | 'loki' | 'k8s'
  timestamp: string
  status: 'success' | 'error'
  error?: string
}

interface HealthStatus {
  anthropic_configured?: boolean
  anthropic_key_hint?: string | null
}

export default function ThreatHunting() {
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<QueryResult | null>(null)
  const [history, setHistory] = useState<QueryHistoryEntry[]>([])
  const [error, setError] = useState<string | null>(null)
  const [health, setHealth] = useState<HealthStatus | null>(null)

  const exampleQueries = [
    "Show me all failed network connections in the last hour",
    "Find pods with privilege escalation attempts",
    "List all secrets accessed in production namespace",
    "Show suspicious outbound connections",
    "Find containers running as root",
    "Show all CVEs in nginx images",
    "List pods without resource limits",
    "Find all shell spawns in the last 24 hours"
  ]

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const res = await fetch(`${API}/health`)
        if (!res.ok) return
        setHealth(await res.json())
      } catch {}
    }

    fetchHealth()
    const timer = setInterval(fetchHealth, 15000)
    return () => clearInterval(timer)
  }, [])

  const executeQuery = async () => {
    if (!query.trim()) return

    setLoading(true)
    setError(null)
    const submittedQuery = query.trim()
    try {
      const res = await fetch(`${API}/threat-hunt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: submittedQuery })
      })

      const data = await res.json()

      if (!res.ok || data.error) {
        setResults(null)
        const message = data.error || `Threat hunt failed with status ${res.status}`
        setError(message)
        setHistory(prev => [{
          id: `${Date.now()}`,
          query: submittedQuery,
          timestamp: new Date().toISOString(),
          status: 'error',
          error: message,
        }, ...prev.slice(0, 9)])
        return
      }

      setResults({
        query: data.query || submittedQuery,
        source: ['hubble', 'loki', 'k8s'].includes(data.source) ? data.source : 'loki',
        timestamp: data.timestamp || new Date().toISOString(),
        explanation: data.explanation || '',
        results: Array.isArray(data.results) ? data.results : [],
      })
      setHistory(prev => [{
        id: `${Date.now()}`,
        query: submittedQuery,
        source: ['hubble', 'loki', 'k8s'].includes(data.source) ? data.source : 'loki',
        timestamp: data.timestamp || new Date().toISOString(),
        status: 'success',
      }, ...prev.slice(0, 9)])
    } catch (e) {
      console.error('Query failed:', e)
      setResults(null)
      const message = 'Threat hunt request failed. Check that the agent is running and reachable.'
      setError(message)
      setHistory(prev => [{
        id: `${Date.now()}`,
        query: submittedQuery,
        timestamp: new Date().toISOString(),
        status: 'error',
        error: message,
      }, ...prev.slice(0, 9)])
    } finally {
      setLoading(false)
    }
  }

  const successfulHistory = history.filter(item => item.status === 'success')
  const sourceCounts = successfulHistory.reduce<Record<string, number>>((acc, item) => {
    const key = item.source || 'unknown'
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {})
  const dominantSource = useMemo(() => {
    const entries = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1])
    return entries[0]?.[0] || null
  }, [sourceCounts])
  const queryTheme = useMemo(() => {
    const corpus = history.map(item => item.query.toLowerCase()).join(' ')
    if (/(network|dns|connection|egress|flow|outbound)/.test(corpus)) return 'Network telemetry'
    if (/(secret|token|credential|metadata)/.test(corpus)) return 'Secrets and identity'
    if (/(privilege|root|shell|exec|process|suid)/.test(corpus)) return 'Runtime escalation'
    if (/(cve|image|registry|package)/.test(corpus)) return 'Image and vulnerability posture'
    return history.length ? 'Mixed hunt patterns' : 'No hunt pattern yet'
  }, [history])
  const authBroken = Boolean(error && /invalid x-api-key|authentication_error/i.test(error))
  const latestHistory = history[0]
  const insightCards = [
    {
      key: 'backend',
      accent: authBroken ? '#ff2d55' : health?.anthropic_configured ? '#00ff9f' : '#ff9f0a',
      kicker: 'Backend state',
      text: authBroken
        ? 'Anthropic auth is failing on the backend, so query translation is blocked.'
        : health?.anthropic_configured
          ? `Agent is configured${health?.anthropic_key_hint ? ` (${health.anthropic_key_hint})` : ''}.`
          : 'Agent health is up, but Anthropic is not configured.',
    },
    {
      key: 'pattern',
      accent: '#58a6ff',
      kicker: 'Dominant hunt pattern',
      text: queryTheme,
    },
    {
      key: 'source',
      accent: '#bc8cff',
      kicker: 'Top backend source',
      text: dominantSource ? `${dominantSource.toUpperCase()} from ${successfulHistory.length} successful hunt${successfulHistory.length === 1 ? '' : 's'}` : 'No successful backend translations yet',
    },
    {
      key: 'latest',
      accent: latestHistory?.status === 'error' ? '#ff9f0a' : '#00ff9f',
      kicker: 'Latest activity',
      text: latestHistory
        ? `${latestHistory.status === 'success' ? 'Successful' : 'Failed'} query at ${new Date(latestHistory.timestamp).toLocaleTimeString()}`
        : 'Waiting for the first hunt request',
    },
  ]

  return (
    <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <style>{`
        @keyframes shimmer { 0% { background-position: -1000px 0; } 100% { background-position: 1000px 0; } }
      `}</style>

      <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>
        🔍 AI Threat Hunting
      </div>

      {/* Query Input */}
      <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px' }}>
        <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px' }}>
          Threat Hunt Workbench
        </div>

        <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault()
                executeQuery()
              }
            }}
            placeholder="Trace signals, pivot on incidents, and hunt across the cluster..."
            style={{
              flex: 1,
              padding: '12px 16px',
              background: 'rgba(0,0,0,0.3)',
              border: '1px solid rgba(0,212,255,0.3)',
              borderRadius: '8px',
              color: '#e6edf3',
              fontSize: '12px',
              fontFamily: 'Inter, sans-serif',
              outline: 'none'
            }}
          />
          <button
            onClick={executeQuery}
            disabled={loading || !query.trim()}
            style={{
              padding: '12px 24px',
              background: loading ? 'rgba(255,255,255,0.05)' : 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,255,159,0.2))',
              border: '1px solid rgba(0,212,255,0.4)',
              borderRadius: '8px',
              color: '#00d4ff',
              fontSize: '11px',
              fontFamily: 'JetBrains Mono, monospace',
              fontWeight: 700,
              cursor: loading || !query.trim() ? 'not-allowed' : 'pointer',
              transition: 'all 0.2s',
              whiteSpace: 'nowrap'
            }}
          >
            {loading ? '⟳ Analyzing...' : '🔍 Hunt'}
          </button>
        </div>

        <div style={{ fontSize: '8px', color: '#4a5568', marginBottom: '8px' }}>
          Queries Hubble, Loki, and Kubernetes API
        </div>

        {/* Example Queries */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
          {exampleQueries.map((example, idx) => (
            <button
              key={idx}
              onClick={() => setQuery(example)}
              style={{
                padding: '6px 10px',
                background: 'rgba(0,212,255,0.05)',
                border: '1px solid rgba(0,212,255,0.15)',
                borderRadius: '6px',
                color: '#58a6ff',
                fontSize: '9px',
                fontFamily: 'Inter, sans-serif',
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
            >
              {example}
            </button>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '12px', flex: 1 }}>
        {/* Results Panel */}
        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>
              Query Results
            </div>
            <span style={{ marginLeft: 'auto', fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>
              live /api/threat-hunt
            </span>
          </div>

          {loading && (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '16px' }}>
              <div style={{
                width: '60px',
                height: '60px',
                border: '3px solid rgba(0,212,255,0.1)',
                borderTop: '3px solid #00d4ff',
                borderRadius: '50%',
                animation: 'spin 1s linear infinite'
              }} />
              <div style={{ fontSize: '10px', color: '#8892a4' }}>
                Analyzing your query and translating to system queries...
              </div>
              <style>{`@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }`}</style>
            </div>
          )}

          {!loading && error && (
            <div style={{ padding: '14px', background: 'rgba(255,45,85,0.08)', border: '1px solid rgba(255,45,85,0.22)', borderRadius: '8px', color: '#ffd7df', fontSize: '12px', lineHeight: 1.6 }}>
              {error}
            </div>
          )}

          {!loading && !results && !error && (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '12px', color: '#4a5568' }}>
              <div style={{ fontSize: '48px' }}>🔍</div>
              <div style={{ fontSize: '11px', textAlign: 'center' }}>
                Enter a natural language query to hunt for threats<br/>
                <span style={{ fontSize: '9px', color: '#5a6478' }}>Natural language queries are translated to Hubble, Loki, and Kubernetes API calls</span>
              </div>
            </div>
          )}

          {results && (
            <div style={{ flex: 1, overflowY: 'auto' }}>
              <div style={{ marginBottom: '12px', padding: '12px', background: 'rgba(0,212,255,0.05)', border: '1px solid rgba(0,212,255,0.15)', borderRadius: '8px' }}>
                <div style={{ fontSize: '9px', color: '#4a5568', marginBottom: '4px' }}>TRANSLATED QUERY</div>
                <div style={{ fontSize: '10px', color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace' }}>
                  {results.query}
                </div>
                {results.explanation && (
                  <div style={{ fontSize: '10px', color: '#b6c2d0', marginTop: '8px', lineHeight: 1.6 }}>
                    {results.explanation}
                  </div>
                )}
                <div style={{ fontSize: '8px', color: '#4a5568', marginTop: '6px' }}>
                  Source: <span style={{ color: '#58a6ff', fontWeight: 700 }}>{results.source.toUpperCase()}</span> • 
                  Time: <span style={{ color: '#8892a4' }}>{new Date(results.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>

              {results.results.length === 0 ? (
                <div style={{ padding: '16px', background: 'rgba(0,0,0,0.2)', border: '1px dashed rgba(0,212,255,0.2)', borderRadius: '8px', color: '#94a3b8', fontSize: '11px', lineHeight: 1.7 }}>
                  The backend translated the query successfully, but no live result rows were returned yet.
                  <div style={{ marginTop: '8px', fontSize: '10px', color: '#5a6478' }}>
                    This page is now showing backend output only, not UI mock findings.
                  </div>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {results.results.map((item, idx) => (
                    <pre
                      key={idx}
                      style={{
                        margin: 0,
                        padding: '12px',
                        background: 'rgba(0,0,0,0.2)',
                        border: '1px solid rgba(255,255,255,0.05)',
                        borderRadius: '8px',
                        fontSize: '10px',
                        color: '#cdd9e5',
                        fontFamily: 'JetBrains Mono, monospace',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                      }}
                    >
                      {JSON.stringify(item, null, 2)}
                    </pre>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Query History & Insights */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px' }}>
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px' }}>
              Query History
            </div>

            {history.length === 0 && (
              <div style={{ fontSize: '9px', color: '#4a5568', textAlign: 'center', padding: '20px' }}>
                No queries yet
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {history.map((entry) => (
                <button
                  key={entry.id}
                  onClick={() => setQuery(entry.query)}
                  style={{
                    padding: '8px',
                    background: 'rgba(0,0,0,0.2)',
                    border: '1px solid rgba(255,255,255,0.05)',
                    borderRadius: '6px',
                    color: '#8892a4',
                    fontSize: '9px',
                    fontFamily: 'Inter, sans-serif',
                    textAlign: 'left',
                    cursor: 'pointer',
                    transition: 'all 0.2s'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                    <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: entry.status === 'success' ? '#00ff9f' : '#ff2d55', flexShrink: 0 }} />
                    <span style={{ fontSize: '8px', color: entry.status === 'success' ? '#00ff9f' : '#ff9f0a', fontFamily: 'JetBrains Mono, monospace' }}>
                      {entry.status === 'success' ? (entry.source || 'query').toUpperCase() : 'ERROR'}
                    </span>
                    <span style={{ marginLeft: 'auto', fontSize: '8px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div>{entry.query}</div>
                </button>
              ))}
            </div>
          </div>

          <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px' }}>
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px' }}>
              AI Insights
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {insightCards.map((insight) => (
                <div key={insight.key} style={{
                  padding: '10px',
                  background: 'rgba(0,0,0,0.2)',
                  border: `1px solid ${insight.accent}22`,
                  borderRadius: '6px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '5px',
                  position: 'relative',
                  overflow: 'hidden',
                }}>
                  <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '1px', background: `linear-gradient(90deg, transparent, ${insight.accent}, transparent)`, opacity: 0.5 }} />
                  <span style={{ fontSize: '8px', color: insight.accent, fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase', letterSpacing: '1px' }}>
                    {insight.kicker}
                  </span>
                  <span style={{ fontSize: '10px', color: '#d5deea', lineHeight: 1.5 }}>{insight.text}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

