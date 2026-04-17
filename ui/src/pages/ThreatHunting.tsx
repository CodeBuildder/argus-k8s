import { useState } from 'react'

const API = '/api'

interface QueryResult {
  query: string
  results: any[]
  source: 'hubble' | 'loki' | 'k8s'
  timestamp: string
}

export default function ThreatHunting() {
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<QueryResult | null>(null)
  const [history, setHistory] = useState<string[]>([])

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

  const executeQuery = async () => {
    if (!query.trim()) return
    
    setLoading(true)
    try {
      const res = await fetch(`${API}/threat-hunt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query })
      })
      
      if (res.ok) {
        const data = await res.json()
        setResults(data)
        setHistory(prev => [query, ...prev.slice(0, 9)])
      }
    } catch (e) {
      console.error('Query failed:', e)
    }
    setLoading(false)
  }

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
          Natural Language Query
        </div>

        <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && executeQuery()}
            placeholder="Ask anything about your cluster security..."
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
          💡 Powered by Claude • Queries Hubble, Loki, and Kubernetes API
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
          <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px' }}>
            Query Results
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
                Claude is analyzing your query and translating to system queries...
              </div>
              <style>{`@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }`}</style>
            </div>
          )}

          {!loading && !results && (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '12px', color: '#4a5568' }}>
              <div style={{ fontSize: '48px' }}>🔍</div>
              <div style={{ fontSize: '11px', textAlign: 'center' }}>
                Enter a natural language query to hunt for threats<br/>
                <span style={{ fontSize: '9px', color: '#5a6478' }}>Claude will translate it to the appropriate system queries</span>
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
                <div style={{ fontSize: '8px', color: '#4a5568', marginTop: '6px' }}>
                  Source: <span style={{ color: '#58a6ff', fontWeight: 700 }}>{results.source.toUpperCase()}</span> • 
                  Time: <span style={{ color: '#8892a4' }}>{new Date(results.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>

              {/* Mock Results */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {[
                  { type: 'network', src: 'prod-api-7f8d9', dst: '203.0.113.42:443', verdict: 'DROPPED', reason: 'Suspicious external IP' },
                  { type: 'process', pod: 'nginx-abc123', cmd: '/bin/bash -c curl http://malicious.com', severity: 'HIGH' },
                  { type: 'file', pod: 'worker-xyz789', path: '/etc/passwd', action: 'read', user: 'www-data' },
                  { type: 'secret', pod: 'api-server-456', secret: 'AWS_ACCESS_KEY', detected: 'environment variable' }
                ].map((item, idx) => (
                  <div key={idx} style={{
                    padding: '12px',
                    background: 'rgba(0,0,0,0.2)',
                    border: '1px solid rgba(255,255,255,0.05)',
                    borderRadius: '8px',
                    fontSize: '10px',
                    fontFamily: 'JetBrains Mono, monospace'
                  }}>
                    {item.type === 'network' && (
                      <>
                        <div style={{ color: '#ff9f0a', marginBottom: '6px' }}>🌐 Network Connection Blocked</div>
                        <div style={{ color: '#8892a4', fontSize: '9px' }}>
                          {item.src} → {item.dst}<br/>
                          Verdict: <span style={{ color: '#ff2d55', fontWeight: 700 }}>{item.verdict}</span><br/>
                          Reason: {item.reason}
                        </div>
                      </>
                    )}
                    {item.type === 'process' && (
                      <>
                        <div style={{ color: '#ff2d55', marginBottom: '6px' }}>⚠️ Suspicious Process Execution</div>
                        <div style={{ color: '#8892a4', fontSize: '9px' }}>
                          Pod: <span style={{ color: '#58a6ff' }}>{item.pod}</span><br/>
                          Command: <span style={{ color: '#e6edf3' }}>{item.cmd}</span><br/>
                          Severity: <span style={{ color: '#ff9f0a', fontWeight: 700 }}>{item.severity}</span>
                        </div>
                      </>
                    )}
                    {item.type === 'file' && (
                      <>
                        <div style={{ color: '#ff9f0a', marginBottom: '6px' }}>📁 Sensitive File Access</div>
                        <div style={{ color: '#8892a4', fontSize: '9px' }}>
                          Pod: <span style={{ color: '#58a6ff' }}>{item.pod}</span><br/>
                          Path: <span style={{ color: '#e6edf3' }}>{item.path}</span><br/>
                          Action: {item.action} by {item.user}
                        </div>
                      </>
                    )}
                    {item.type === 'secret' && (
                      <>
                        <div style={{ color: '#ff2d55', marginBottom: '6px' }}>🔐 Secret Detected</div>
                        <div style={{ color: '#8892a4', fontSize: '9px' }}>
                          Pod: <span style={{ color: '#58a6ff' }}>{item.pod}</span><br/>
                          Secret: <span style={{ color: '#ff9f0a', fontWeight: 700 }}>{item.secret}</span><br/>
                          Location: {item.detected}
                        </div>
                      </>
                    )}
                  </div>
                ))}
              </div>
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
              {history.map((q, idx) => (
                <button
                  key={idx}
                  onClick={() => setQuery(q)}
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
                  {q}
                </button>
              ))}
            </div>
          </div>

          <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px' }}>
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px' }}>
              AI Insights
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {[
                { icon: '🎯', text: 'Most queries target network flows', color: '#58a6ff' },
                { icon: '⚡', text: 'Average query time: 1.2s', color: '#00ff9f' },
                { icon: '🔥', text: 'Top threat: Privilege escalation', color: '#ff9f0a' }
              ].map((insight, idx) => (
                <div key={idx} style={{
                  padding: '10px',
                  background: 'rgba(0,0,0,0.2)',
                  border: '1px solid rgba(255,255,255,0.05)',
                  borderRadius: '6px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}>
                  <span style={{ fontSize: '16px' }}>{insight.icon}</span>
                  <span style={{ fontSize: '9px', color: insight.color }}>{insight.text}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// Made with Bob
