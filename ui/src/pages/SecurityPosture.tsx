import { useState, useEffect } from 'react'
import type React from 'react'
import FormattedAssistantContent from '../components/FormattedAssistantContent'

const API = '/api'

interface IncidentSummary {
  summary: string
  incident_count: number
  time_window_minutes: number
  generated_at: string
  ai_error?: string
}

interface Incident {
  id: string
  ts: number
  rule: string
  severity: string
  namespace: string
  hostname: string
  action_taken: string
  confidence: number
  likely_false_positive?: boolean
  kyverno_blocked?: boolean
}

interface PostureData {
  source: string
  generated_at: string
  window_minutes: number
  counts: {
    incidents: number
    secret_findings: number
    cve_findings: number
    compliance_findings: number
    passed_checks: number
    failed_checks: number
    cis_score: number
  }
  secrets: {
    policies: Array<{ name: string; status: string; violations: number; severity: string }>
    rules: Array<{ name: string; detections: number; priority: string; namespace?: string }>
  }
  cves: {
    findings: Array<{ cve: string; severity: string; score: number; image: string; namespace: string; fixAvailable: boolean; evidence?: string }>
  }
  compliance: {
    sections: Array<{ section: string; passed: number; failed: number; score: number }>
  }
}

const sevColor = (severity?: string) => {
  if (severity === 'CRITICAL' || severity === 'critical') return '#ff2d55'
  if (severity === 'HIGH' || severity === 'high') return '#ff9f0a'
  if (severity === 'MED' || severity === 'MEDIUM' || severity === 'medium') return '#ffd700'
  return '#8b949e'
}

function EmptyBackendState({ label }: { label: string }) {
  return (
    <div style={{ padding: '26px', textAlign: 'center', color: '#4a5568', fontSize: '10px', border: '1px dashed rgba(0,255,159,0.12)', borderRadius: '8px', background: 'rgba(0,0,0,0.18)' }}>
      No backend {label} in the last hour. Run a backend simulation to populate this view.
    </div>
  )
}

export default function SecurityPosture() {
  const [summary, setSummary] = useState<IncidentSummary | null>(null)
  const [summaryLoading, setSummaryLoading] = useState(false)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [posture, setPosture] = useState<PostureData | null>(null)
  const [loading, setLoading] = useState(true)
  const [backendLive, setBackendLive] = useState(false)
  const [activeTab, setActiveTab] = useState<'summary' | 'secrets' | 'cves' | 'compliance'>('summary')

  const localSummary = (items: Incident[], aiError?: string): IncidentSummary => {
    const critical = items.filter(i => i.severity === 'CRITICAL').length
    const high = items.filter(i => i.severity === 'HIGH').length
    const human = items.filter(i => i.action_taken === 'HUMAN_REQUIRED').length
    const contained = items.filter(i => i.action_taken === 'KILL' || i.action_taken === 'ISOLATE' || i.kyverno_blocked).length
    const topNamespaces = [...new Set(items.map(i => i.namespace).filter(Boolean))].slice(0, 3)
    return {
      incident_count: items.length,
      time_window_minutes: 60,
      generated_at: new Date().toISOString(),
      ai_error: aiError,
      summary: items.length
        ? [
            `${items.length} backend incidents were observed in the last hour: ${critical} critical, ${high} high, and ${contained} contained or blocked.`,
            human ? `${human} incident${human === 1 ? '' : 's'} require human approval before remediation proceeds.` : 'No incident currently requires human approval.',
            topNamespaces.length ? `Most affected namespaces: ${topNamespaces.join(', ')}.` : 'No namespace concentration detected yet.',
          ].join('\n\n')
        : 'No incidents were returned by the backend for the last hour. Use the backend simulator to generate live incident, approval, and attack-chain data.',
    }
  }

  const fetchAiSummary = async (backendIncidents: Incident[]) => {
    setSummaryLoading(true)
    try {
      const summaryRes = await fetch(`${API}/incidents/summarize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ time_window: 3600 }),
      })
      if (summaryRes.ok) {
        const data = await summaryRes.json()
        setSummary(data.error ? localSummary(backendIncidents, data.error) : {
          summary: data.summary || localSummary(backendIncidents).summary,
          incident_count: data.incident_count ?? backendIncidents.length,
          time_window_minutes: data.time_window_minutes ?? 60,
          generated_at: data.generated_at || new Date().toISOString(),
        })
      } else {
        setSummary(localSummary(backendIncidents, 'Summary endpoint returned an error.'))
      }
    } catch {
      setSummary(localSummary(backendIncidents, 'Could not reach the agent posture endpoints.'))
    }
    setSummaryLoading(false)
  }

  const refresh = async () => {
    setLoading(true)
    try {
      const [incidentRes, postureRes] = await Promise.all([
        fetch(`${API}/incidents?limit=100`),
        fetch(`${API}/security-posture`),
      ])
      const incidentData = incidentRes.ok ? await incidentRes.json() : { incidents: [] }
      const backendIncidents = incidentData.incidents || []
      setIncidents(backendIncidents)
      if (postureRes.ok) {
        setPosture(await postureRes.json())
        setBackendLive(true)
      }
      setLoading(false)
      // Fire AI summary separately — doesn't block the page render
      fetchAiSummary(backendIncidents)
    } catch (e) {
      console.error('Failed to refresh posture:', e)
      setBackendLive(false)
      setLoading(false)
      setSummary(localSummary(incidents, 'Could not reach the agent posture endpoints.'))
    }
  }

  useEffect(() => {
    refresh()
    const interval = setInterval(refresh, 300000)
    return () => clearInterval(interval)
  }, [])

  const sourceBadge = posture?.source ? `${posture.source} · ${posture.window_minutes}m` : 'backend pending'
  const secretEvidence = posture?.secrets.rules ?? []
  const cveFindings = posture?.cves.findings ?? []
  const topSecretNamespaces = Array.from(
    incidents
      .filter(i => /secret|credential|token|shadow|metadata/i.test(i.rule))
      .reduce((acc, incident) => {
        const ns = incident.namespace || 'unknown'
        acc.set(ns, (acc.get(ns) || 0) + 1)
        return acc
      }, new Map<string, number>())
  ).sort((a, b) => b[1] - a[1]).slice(0, 4)
  const topCveNamespaces = Array.from(
    cveFindings.reduce((acc, finding) => {
      const ns = finding.namespace || 'unknown'
      acc.set(ns, (acc.get(ns) || 0) + 1)
      return acc
    }, new Map<string, number>())
  ).sort((a, b) => b[1] - a[1]).slice(0, 4)
  const secretSeverityBreakdown = [
    ['Critical', secretEvidence.filter(rule => rule.priority === 'CRITICAL').length],
    ['High', secretEvidence.filter(rule => rule.priority === 'HIGH').length],
    ['Medium', secretEvidence.filter(rule => rule.priority === 'MED' || rule.priority === 'MEDIUM').length],
  ] as Array<[string, number]>
  const cveSeverityBreakdown = [
    ['Critical', cveFindings.filter(f => f.severity === 'CRITICAL').length],
    ['High', cveFindings.filter(f => f.severity === 'HIGH').length],
    ['Medium', cveFindings.filter(f => f.severity === 'MED' || f.severity === 'MEDIUM').length],
  ] as Array<[string, number]>
  const policyBreakdown = posture?.secrets.policies.map(policy => [policy.name, policy.violations] as [string, number]) ?? []

  if (loading) {
    return (
      <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', display: 'flex', flexDirection: 'column', gap: '12px' }}>
        <style>{`
          @keyframes shimmer { 0% { background-position: -400px 0 } 100% { background-position: 400px 0 } }
        `}</style>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ width: '120px', height: '12px', borderRadius: '4px', background: 'linear-gradient(90deg, #111827 25%, #1a2233 50%, #111827 75%)', backgroundSize: '400px 100%', animation: 'shimmer 1.4s ease-in-out infinite' }} />
          <div style={{ width: '80px', height: '12px', borderRadius: '4px', background: 'linear-gradient(90deg, #111827 25%, #1a2233 50%, #111827 75%)', backgroundSize: '400px 100%', animation: 'shimmer 1.4s ease-in-out infinite 0.1s' }} />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
          {[0,1,2].map(i => (
            <div key={i} style={{ height: '84px', borderRadius: '8px', background: 'linear-gradient(90deg, #111827 25%, #1a2233 50%, #111827 75%)', backgroundSize: '400px 100%', animation: `shimmer 1.4s ease-in-out infinite ${i * 0.1}s` }} />
          ))}
        </div>
        <div style={{ flex: 1, borderRadius: '10px', background: 'linear-gradient(90deg, #111827 25%, #1a2233 50%, #111827 75%)', backgroundSize: '400px 100%', animation: 'shimmer 1.4s ease-in-out infinite 0.3s' }} />
      </div>
    )
  }

  return (
    <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <style>{`
        @keyframes liveBlink {
          0%, 100% { opacity: 1; box-shadow: 0 0 6px rgba(0,255,159,0.75); }
          50% { opacity: 0.45; box-shadow: 0 0 14px rgba(0,255,159,0.25); }
        }
        @keyframes shimmer { 0% { background-position: -400px 0 } 100% { background-position: 400px 0 } }
        @keyframes spin { to { transform: rotate(360deg) } }
      `}</style>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <div style={{ fontSize: '9px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>Security Posture</div>
        <span style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          fontSize: '8px',
          color: backendLive ? '#00ff9f' : '#ff9f0a',
          background: backendLive ? 'rgba(0,255,159,0.06)' : 'rgba(255,159,10,0.08)',
          border: `1px solid ${backendLive ? 'rgba(0,255,159,0.2)' : 'rgba(255,159,10,0.25)'}`,
          borderRadius: '4px',
          padding: '3px 8px',
          fontFamily: 'JetBrains Mono, monospace',
        }}>
          <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: backendLive ? '#00ff9f' : '#ff9f0a', animation: backendLive ? 'liveBlink 1.4s infinite' : 'none' }} />
          {sourceBadge}
        </span>
        <button onClick={refresh} disabled={loading} style={{ marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 12px', background: loading ? 'rgba(0,212,255,0.06)' : 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.3)', borderRadius: '6px', color: '#00d4ff', fontSize: '9px', fontFamily: 'JetBrains Mono, monospace', cursor: loading ? 'not-allowed' : 'pointer', opacity: loading ? 0.7 : 1, transition: 'all 0.15s' }}>
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#00d4ff" strokeWidth="2.5" strokeLinecap="round" style={{ animation: loading ? 'spin 0.7s linear infinite' : 'none', flexShrink: 0 }}><path d="M21 12a9 9 0 1 1-6.219-8.56" /></svg>
          {loading ? 'Refreshing...' : 'Refresh backend'}
        </button>
      </div>

      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid rgba(0,255,159,0.12)', paddingBottom: '8px' }}>
        {[
          { id: 'summary', label: 'Summary' },
          { id: 'secrets', label: 'Secret Scanning' },
          { id: 'cves', label: 'CVE Dashboard' },
          { id: 'compliance', label: 'Compliance' },
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
              display: 'flex',
              alignItems: 'center',
            }}
          >
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {activeTab === 'summary' && (
        <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px' }}>
          <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px' }}>Incident Summary</div>
          {summary?.ai_error && (
            <div style={{ marginBottom: '12px', padding: '10px 12px', background: 'rgba(255,159,10,0.06)', border: '1px solid rgba(255,159,10,0.2)', borderRadius: '8px', color: '#ff9f0a', fontSize: '10px', lineHeight: 1.5 }}>
              Argus AI summary fallback is active: {summary.ai_error}
            </div>
          )}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '16px' }}>
            <Metric label="Incidents analyzed" value={incidents.length} color="#00d4ff" />
            <Metric label="Time window" value="60m" color="#00ff9f" />
            <Metric label="Generated" value={summary ? new Date(summary.generated_at).toLocaleTimeString() : '—'} color="#bc8cff" />
          </div>
          {summaryLoading && !summary ? (
            <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(0,255,159,0.12)', borderRadius: '8px', padding: '20px', display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{ width: '16px', height: '16px', borderRadius: '50%', border: '2px solid rgba(0,212,255,0.2)', borderTopColor: '#00d4ff', animation: 'spin 0.8s linear infinite', flexShrink: 0 }} />
              <span style={{ fontSize: '11px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>Argus AI is generating the security summary...</span>
            </div>
          ) : summary ? (
            <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(0,255,159,0.12)', borderRadius: '8px', padding: '16px' }}>
              <FormattedAssistantContent content={summary.summary} />
            </div>
          ) : null}
        </div>
      )}

      {activeTab === 'secrets' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
            <Metric label="Policies tripped" value={posture?.secrets.policies.length ?? 0} color="#00d4ff" />
            <Metric label="Active detections" value={secretEvidence.length} color="#ff2d55" />
            <Metric label="Namespaces affected" value={topSecretNamespaces.length} color="#ff9f0a" />
            <Metric label="Window" value={`${posture?.window_minutes ?? 60}m`} color="#00ff9f" />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <Panel title="Secret Policy Activity" live>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '14px' }}>
                <div>
                  <div style={{ fontSize: '9px', color: '#4a5568', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '1px' }}>Violations by policy</div>
                  <MiniBarList items={policyBreakdown} color="#ff2d55" />
                </div>
                <div>
                  <div style={{ fontSize: '9px', color: '#4a5568', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '1px' }}>Detections by namespace</div>
                  <MiniBarList items={topSecretNamespaces} color="#00d4ff" />
                </div>
              </div>
              <div style={{ fontSize: '9px', color: '#5a6478', marginBottom: '12px', lineHeight: 1.5 }}>
                Counts update from backend incident evidence as secret, token, and credential alerts arrive.
              </div>
              {posture?.secrets.policies.length ? posture.secrets.policies.map(policy => (
                <Row key={policy.name} title={policy.name} meta={`${policy.violations} violation${policy.violations === 1 ? '' : 's'}`} color={sevColor(policy.severity)} right={policy.status} />
              )) : <EmptyBackendState label="secret findings" />}
            </Panel>
            <Panel title="Secret Detection Evidence" live>
              <div style={{ marginBottom: '14px' }}>
                <div style={{ fontSize: '9px', color: '#4a5568', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '1px' }}>Severity distribution</div>
                <MiniBarList items={secretSeverityBreakdown.filter(([, count]) => count > 0)} color="#ff9f0a" />
              </div>
              {secretEvidence.length ? secretEvidence.map(rule => (
                <Row key={`${rule.name}-${rule.namespace}`} title={rule.name} meta={`${rule.detections} detection · ${rule.namespace || 'unknown'}`} color={sevColor(rule.priority)} right={rule.priority} />
              )) : <EmptyBackendState label="secret detections" />}
            </Panel>
          </div>
        </div>
      )}

      {activeTab === 'cves' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
            <Metric label="Critical exposure" value={cveFindings.filter(f => f.severity === 'CRITICAL').length} color="#ff2d55" />
            <Metric label="High exposure" value={cveFindings.filter(f => f.severity === 'HIGH').length} color="#ff9f0a" />
            <Metric label="Findings" value={posture?.counts.cve_findings ?? 0} color="#ffd700" />
            <Metric label="Namespaces affected" value={topCveNamespaces.length} color="#00d4ff" />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <Panel title="Exposure Overview" live>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '14px' }}>
                <div>
                  <div style={{ fontSize: '9px', color: '#4a5568', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '1px' }}>Severity distribution</div>
                  <MiniBarList items={cveSeverityBreakdown.filter(([, count]) => count > 0)} color="#ff2d55" />
                </div>
                <div>
                  <div style={{ fontSize: '9px', color: '#4a5568', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '1px' }}>Findings by namespace</div>
                  <MiniBarList items={topCveNamespaces} color="#ff9f0a" />
                </div>
              </div>
              <div style={{ fontSize: '9px', color: '#5a6478', lineHeight: 1.5 }}>
                This view is backend evidence derived from cluster incidents, image-policy alerts, and runtime findings.
              </div>
            </Panel>
            <Panel title="Backend Vulnerability Evidence" live>
              {cveFindings.length ? cveFindings.map(finding => (
                <ScoredRow key={finding.cve} title={`${finding.cve} · ${finding.evidence || 'incident evidence'}`} meta={`${finding.image} in ${finding.namespace}`} color={sevColor(finding.severity)} right={finding.fixAvailable ? 'fix available' : 'review'} score={finding.score} />
              )) : <EmptyBackendState label="vulnerability evidence" />}
            </Panel>
          </div>
        </div>
      )}

      {activeTab === 'compliance' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
            <Metric label="CIS posture" value={`${posture?.counts.cis_score ?? 0}%`} color="#00ff9f" />
            <Metric label="Passed checks" value={posture?.counts.passed_checks ?? 0} color="#00d4ff" />
            <Metric label="Failed checks" value={posture?.counts.failed_checks ?? 0} color="#ff9f0a" />
          </div>
          <Panel title="Backend Compliance Signals">
            {posture?.compliance.sections.length ? posture.compliance.sections.map(section => (
              <Row key={section.section} title={section.section} meta={`${section.passed} passed · ${section.failed} failed`} color={section.score >= 90 ? '#00ff9f' : section.score >= 70 ? '#ff9f0a' : '#ff2d55'} right={`${section.score}%`} />
            )) : <EmptyBackendState label="compliance findings" />}
          </Panel>
        </div>
      )}
    </div>
  )
}

function Metric({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div style={{ background: '#111827', border: `1px solid ${color}24`, borderRadius: '8px', padding: '12px', minHeight: '84px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
      <div style={{ fontSize: '8px', color: '#4a5568', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '1px' }}>{label}</div>
      <div style={{ fontSize: '22px', fontWeight: 700, color, fontFamily: 'JetBrains Mono, monospace' }}>{value}</div>
      <div style={{ marginTop: '10px', height: '3px', borderRadius: '999px', background: 'rgba(255,255,255,0.05)', overflow: 'hidden' }}>
        <div style={{ width: '100%', height: '100%', background: `linear-gradient(90deg, ${color}, ${color}66)` }} />
      </div>
    </div>
  )
}

function Panel({ title, children, live = false }: { title: string; children: React.ReactNode; live?: boolean }) {
  return (
    <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '10px', padding: '16px' }}>
      <div style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
        {title}
        {live && <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#00ff9f', animation: 'liveBlink 1.4s infinite', boxShadow: '0 0 7px rgba(0,255,159,0.5)' }} />}
      </div>
      {children}
    </div>
  )
}

function Row({ title, meta, color, right }: { title: string; meta: string; color: string; right: string }) {
  return (
    <div style={{ padding: '12px', background: 'rgba(0,0,0,0.2)', border: `1px solid ${color}26`, borderRadius: '8px', marginBottom: '8px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '5px' }}>
        <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: color, boxShadow: `0 0 7px ${color}` }} />
        <span style={{ fontSize: '10px', color: '#e6edf3', fontWeight: 600, flex: 1 }}>{title}</span>
        <span style={{ fontSize: '8px', color, background: `${color}12`, border: `1px solid ${color}30`, padding: '2px 6px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{right}</span>
      </div>
      <div style={{ fontSize: '9px', color: '#8892a4', marginLeft: '15px' }}>{meta}</div>
    </div>
  )
}

function ScoredRow({ title, meta, color, right, score }: { title: string; meta: string; color: string; right: string; score: number }) {
  return (
    <div style={{ padding: '12px', background: 'rgba(0,0,0,0.2)', border: `1px solid ${color}26`, borderRadius: '8px', marginBottom: '8px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '5px' }}>
        <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: color, boxShadow: `0 0 7px ${color}` }} />
        <span style={{ fontSize: '10px', color: '#e6edf3', fontWeight: 600, flex: 1 }}>{title}</span>
        <span style={{ fontSize: '8px', color, background: `${color}12`, border: `1px solid ${color}30`, padding: '2px 6px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{right}</span>
      </div>
      <div style={{ fontSize: '9px', color: '#8892a4', marginLeft: '15px', marginBottom: '8px' }}>{meta}</div>
      <div style={{ display: 'grid', gridTemplateColumns: '60px 1fr 42px', gap: '8px', alignItems: 'center', marginLeft: '15px' }}>
        <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px' }}>CVSS</div>
        <div style={{ height: '6px', background: 'rgba(255,255,255,0.06)', borderRadius: '999px', overflow: 'hidden' }}>
          <div style={{ width: `${Math.max(0, Math.min(100, score * 10))}%`, height: '100%', background: color, borderRadius: '999px', transition: 'width 350ms ease' }} />
        </div>
        <div style={{ fontSize: '9px', color, fontFamily: 'JetBrains Mono, monospace', textAlign: 'right' }}>{score.toFixed(1)}</div>
      </div>
    </div>
  )
}

function MiniBarList({ items, color }: { items: Array<[string, number]>; color: string }) {
  const max = Math.max(...items.map(([, count]) => count), 1)
  if (!items.length) return <div style={{ fontSize: '9px', color: '#4a5568' }}>No backend concentration yet.</div>
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '7px' }}>
      {items.map(([label, count]) => (
        <div key={label} style={{ display: 'grid', gridTemplateColumns: '110px 1fr 28px', gap: '8px', alignItems: 'center' }}>
          <div style={{ fontSize: '9px', color: '#d1d5db', fontFamily: 'JetBrains Mono, monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</div>
          <div style={{ height: '5px', background: 'rgba(255,255,255,0.05)', borderRadius: '999px', overflow: 'hidden' }}>
            <div style={{ width: `${(count / max) * 100}%`, height: '100%', background: color, borderRadius: '999px', transition: 'width 350ms ease' }} />
          </div>
          <div style={{ fontSize: '9px', color, fontFamily: 'JetBrains Mono, monospace', textAlign: 'right' }}>{count}</div>
        </div>
      ))}
    </div>
  )
}
