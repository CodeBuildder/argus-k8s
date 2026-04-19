import { useState, useEffect } from 'react'

const API = '/api'

interface IncidentSummary {
  summary: string
  incident_count: number
  time_window_minutes: number
  generated_at: string
}

export default function SecurityPosture() {
  const [summary, setSummary] = useState<IncidentSummary | null>(null)
  const [loading, setLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<'summary' | 'secrets' | 'cves' | 'compliance'>('summary')

  const generateSummary = async () => {
    setLoading(true)
    try {
      const res = await fetch(`${API}/incidents/summarize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ time_window: 3600 })
      })
      if (res.ok) {
        const data = await res.json()
        setSummary(data)
      }
    } catch (e) {
      console.error('Failed to generate summary:', e)
    }
    setLoading(false)
  }

  useEffect(() => {
    generateSummary()
    const interval = setInterval(generateSummary, 300000) // Every 5 minutes
    return () => clearInterval(interval)
  }, [])

  return (
    <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>🛡️ Security Posture</div>

      {/* Tab Navigation */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid rgba(0,255,159,0.12)', paddingBottom: '8px' }}>
        {[
          { id: 'summary', label: 'AI Summary', icon: '🤖' },
          { id: 'secrets', label: 'Secret Scanning', icon: '🔐' },
          { id: 'cves', label: 'CVE Dashboard', icon: '🐛' },
          { id: 'compliance', label: 'Compliance', icon: '✓' }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            style={{
              padding: '8px 16px',
              background: activeTab === tab.id ? 'rgba(0,255,159,0.1)' : 'transparent',
              border: activeTab === tab.id ? '1px solid rgba(0,255,159,0.3)' : '1px solid rgba(255,255,255,0.05)',
              borderRadius: '6px',
              color: activeTab === tab.id ? '#00ff9f' : '#8892a4',
              fontSize: '10px',
              fontFamily: 'JetBrains Mono, monospace',
              cursor: 'pointer',
              transition: 'all 0.2s',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* AI Summary Tab */}
      {activeTab === 'summary' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>
                Incident Summary (AI-Powered)
              </div>
              <button
                onClick={generateSummary}
                disabled={loading}
                style={{
                  padding: '6px 12px',
                  background: loading ? 'rgba(255,255,255,0.05)' : 'rgba(0,212,255,0.1)',
                  border: '1px solid rgba(0,212,255,0.3)',
                  borderRadius: '6px',
                  color: '#00d4ff',
                  fontSize: '9px',
                  fontFamily: 'JetBrains Mono, monospace',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  transition: 'all 0.2s'
                }}
              >
                {loading ? '⟳ Generating...' : '↻ Refresh'}
              </button>
            </div>

            {summary && (
              <div>
                <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
                  <div style={{ flex: 1, background: 'rgba(0,212,255,0.05)', border: '1px solid rgba(0,212,255,0.15)', borderRadius: '8px', padding: '12px' }}>
                    <div style={{ fontSize: '8px', color: '#4a5568', marginBottom: '4px' }}>INCIDENTS ANALYZED</div>
                    <div style={{ fontSize: '24px', fontWeight: 700, color: '#00d4ff' }}>{summary.incident_count}</div>
                  </div>
                  <div style={{ flex: 1, background: 'rgba(0,255,159,0.05)', border: '1px solid rgba(0,255,159,0.15)', borderRadius: '8px', padding: '12px' }}>
                    <div style={{ fontSize: '8px', color: '#4a5568', marginBottom: '4px' }}>TIME WINDOW</div>
                    <div style={{ fontSize: '24px', fontWeight: 700, color: '#00ff9f' }}>{summary.time_window_minutes}m</div>
                  </div>
                  <div style={{ flex: 2, background: 'rgba(188,140,255,0.05)', border: '1px solid rgba(188,140,255,0.15)', borderRadius: '8px', padding: '12px' }}>
                    <div style={{ fontSize: '8px', color: '#4a5568', marginBottom: '4px' }}>GENERATED AT</div>
                    <div style={{ fontSize: '11px', fontWeight: 600, color: '#bc8cff', fontFamily: 'JetBrains Mono, monospace' }}>
                      {new Date(summary.generated_at).toLocaleString()}
                    </div>
                  </div>
                </div>

                <div style={{
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid rgba(0,255,159,0.12)',
                  borderRadius: '8px',
                  padding: '16px',
                  fontSize: '11px',
                  lineHeight: '1.6',
                  color: '#d1d5db',
                  fontFamily: 'Inter, sans-serif',
                  whiteSpace: 'pre-wrap'
                }}>
                  {summary.summary}
                </div>
              </div>
            )}

            {!summary && !loading && (
              <div style={{ textAlign: 'center', padding: '40px', color: '#4a5568', fontSize: '10px' }}>
                Click "Refresh" to generate an AI-powered incident summary
              </div>
            )}
          </div>
        </div>
      )}

      {/* Secret Scanning Tab */}
      {activeTab === 'secrets' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px' }}>
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px' }}>
              Kyverno Secret Policies
            </div>
            
            {[
              { name: 'Env Var Secret Detection', status: 'active', violations: 3, severity: 'high' },
              { name: 'ConfigMap Secret Detection', status: 'active', violations: 1, severity: 'medium' },
              { name: 'Secret Encryption Required', status: 'active', violations: 0, severity: 'high' }
            ].map(policy => (
              <div key={policy.name} style={{
                padding: '12px',
                background: 'rgba(0,0,0,0.2)',
                border: '1px solid rgba(255,255,255,0.05)',
                borderRadius: '8px',
                marginBottom: '8px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '10px', color: '#e6edf3', fontWeight: 600 }}>{policy.name}</span>
                  <span style={{
                    fontSize: '8px',
                    color: policy.status === 'active' ? '#00ff9f' : '#4a5568',
                    background: policy.status === 'active' ? 'rgba(0,255,159,0.1)' : 'rgba(255,255,255,0.05)',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    fontFamily: 'JetBrains Mono, monospace'
                  }}>
                    {policy.status}
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '12px', fontSize: '9px', color: '#8892a4' }}>
                  <span>Violations: <span style={{ color: policy.violations > 0 ? '#ff9f0a' : '#00ff9f', fontWeight: 700 }}>{policy.violations}</span></span>
                  <span>Severity: <span style={{ color: policy.severity === 'high' ? '#ff2d55' : '#ff9f0a', fontWeight: 700 }}>{policy.severity}</span></span>
                </div>
              </div>
            ))}
          </div>

          <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px' }}>
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px' }}>
              Falco Secret Detection Rules
            </div>
            
            {[
              { name: 'Secret in Command Line', detections: 2, priority: 'HIGH' },
              { name: 'AWS Credentials Accessed', detections: 0, priority: 'CRITICAL' },
              { name: 'SSH Key Accessed', detections: 0, priority: 'CRITICAL' },
              { name: 'K8s Secret Mounted', detections: 5, priority: 'WARNING' },
              { name: 'Base64 Encoding Detected', detections: 1, priority: 'WARNING' }
            ].map(rule => (
              <div key={rule.name} style={{
                padding: '10px',
                background: 'rgba(0,0,0,0.2)',
                border: '1px solid rgba(255,255,255,0.05)',
                borderRadius: '8px',
                marginBottom: '6px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <div>
                  <div style={{ fontSize: '9px', color: '#e6edf3', marginBottom: '2px' }}>{rule.name}</div>
                  <div style={{ fontSize: '8px', color: '#4a5568' }}>
                    {rule.detections} detection{rule.detections !== 1 ? 's' : ''} (24h)
                  </div>
                </div>
                <span style={{
                  fontSize: '7px',
                  color: rule.priority === 'CRITICAL' ? '#ff2d55' : rule.priority === 'HIGH' ? '#ff9f0a' : '#8892a4',
                  background: rule.priority === 'CRITICAL' ? 'rgba(255,45,85,0.1)' : rule.priority === 'HIGH' ? 'rgba(255,159,10,0.1)' : 'rgba(255,255,255,0.05)',
                  padding: '3px 6px',
                  borderRadius: '4px',
                  fontFamily: 'JetBrains Mono, monospace',
                  fontWeight: 700
                }}>
                  {rule.priority}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* CVE Dashboard Tab */}
      {activeTab === 'cves' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
            {[
              { label: 'Critical CVEs', value: 2, color: '#ff2d55' },
              { label: 'High CVEs', value: 7, color: '#ff9f0a' },
              { label: 'Medium CVEs', value: 15, color: '#ffd700' },
              { label: 'Images Scanned', value: 23, color: '#00d4ff' }
            ].map(stat => (
              <div key={stat.label} style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '8px', padding: '12px' }}>
                <div style={{ fontSize: '8px', color: '#4a5568', marginBottom: '4px' }}>{stat.label}</div>
                <div style={{ fontSize: '24px', fontWeight: 700, color: stat.color }}>{stat.value}</div>
              </div>
            ))}
          </div>

          <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px' }}>
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px' }}>
              Critical Vulnerabilities (Trivy)
            </div>

            {[
              { cve: 'CVE-2024-1234', severity: 'CRITICAL', score: 9.8, image: 'nginx:1.21', namespace: 'production', fixAvailable: true },
              { cve: 'CVE-2024-5678', severity: 'CRITICAL', score: 9.1, image: 'postgres:14', namespace: 'default', fixAvailable: true },
              { cve: 'CVE-2023-9999', severity: 'HIGH', score: 8.6, image: 'redis:7', namespace: 'cache', fixAvailable: false }
            ].map(vuln => (
              <div key={vuln.cve} style={{
                padding: '12px',
                background: 'rgba(0,0,0,0.2)',
                border: `1px solid ${vuln.severity === 'CRITICAL' ? 'rgba(255,45,85,0.2)' : 'rgba(255,159,10,0.2)'}`,
                borderRadius: '8px',
                marginBottom: '8px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '11px', color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>{vuln.cve}</span>
                    <span style={{
                      fontSize: '8px',
                      color: vuln.severity === 'CRITICAL' ? '#ff2d55' : '#ff9f0a',
                      background: vuln.severity === 'CRITICAL' ? 'rgba(255,45,85,0.1)' : 'rgba(255,159,10,0.1)',
                      padding: '2px 6px',
                      borderRadius: '4px',
                      fontFamily: 'JetBrains Mono, monospace'
                    }}>
                      {vuln.severity}
                    </span>
                    <span style={{ fontSize: '10px', color: '#e6edf3', fontWeight: 700 }}>CVSS {vuln.score}</span>
                  </div>
                  {vuln.fixAvailable && (
                    <span style={{
                      fontSize: '8px',
                      color: '#00ff9f',
                      background: 'rgba(0,255,159,0.1)',
                      padding: '3px 8px',
                      borderRadius: '4px',
                      fontFamily: 'JetBrains Mono, monospace'
                    }}>
                      FIX AVAILABLE
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '9px', color: '#8892a4' }}>
                  <span style={{ color: '#58a6ff' }}>{vuln.image}</span> in <span style={{ color: '#bc8cff' }}>{vuln.namespace}</span>
                </div>
              </div>
            ))}

            <div style={{
              marginTop: '12px',
              padding: '12px',
              background: 'rgba(0,212,255,0.05)',
              border: '1px solid rgba(0,212,255,0.15)',
              borderRadius: '8px',
              fontSize: '9px',
              color: '#8892a4',
              textAlign: 'center'
            }}>
              💡 Trivy scans run every 6 hours. Last scan: 2 hours ago
            </div>
          </div>
        </div>
      )}

      {/* Compliance Tab */}
      {activeTab === 'compliance' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
            {[
              { label: 'CIS Score', value: '87%', color: '#00ff9f' },
              { label: 'Passed Checks', value: '174/200', color: '#00d4ff' },
              { label: 'Failed Checks', value: '26', color: '#ff9f0a' }
            ].map(stat => (
              <div key={stat.label} style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '8px', padding: '12px' }}>
                <div style={{ fontSize: '8px', color: '#4a5568', marginBottom: '4px' }}>{stat.label}</div>
                <div style={{ fontSize: '24px', fontWeight: 700, color: stat.color }}>{stat.value}</div>
              </div>
            ))}
          </div>

          <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px' }}>
            <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px' }}>
              CIS Kubernetes Benchmark (kube-bench)
            </div>

            {[
              { section: '1.2 API Server', passed: 12, failed: 2, score: 86 },
              { section: '2.1 etcd', passed: 8, failed: 0, score: 100 },
              { section: '3.2 Kubelet', passed: 15, failed: 3, score: 83 },
              { section: '4.1 Worker Nodes', passed: 18, failed: 1, score: 95 },
              { section: '5.1 RBAC', passed: 22, failed: 4, score: 85 }
            ].map(section => (
              <div key={section.section} style={{
                padding: '12px',
                background: 'rgba(0,0,0,0.2)',
                border: '1px solid rgba(255,255,255,0.05)',
                borderRadius: '8px',
                marginBottom: '8px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '10px', color: '#e6edf3', fontWeight: 600 }}>{section.section}</span>
                  <span style={{ fontSize: '12px', color: section.score >= 90 ? '#00ff9f' : section.score >= 80 ? '#ff9f0a' : '#ff2d55', fontWeight: 700 }}>
                    {section.score}%
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '12px', fontSize: '9px', color: '#8892a4' }}>
                  <span>Passed: <span style={{ color: '#00ff9f', fontWeight: 700 }}>{section.passed}</span></span>
                  <span>Failed: <span style={{ color: section.failed > 0 ? '#ff9f0a' : '#00ff9f', fontWeight: 700 }}>{section.failed}</span></span>
                </div>
                <div style={{ marginTop: '8px', height: '4px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px', overflow: 'hidden' }}>
                  <div style={{
                    height: '100%',
                    width: `${section.score}%`,
                    background: section.score >= 90 ? '#00ff9f' : section.score >= 80 ? '#ff9f0a' : '#ff2d55',
                    borderRadius: '2px',
                    transition: 'width 1s ease-out'
                  }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// Made with Bob
