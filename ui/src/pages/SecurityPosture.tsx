import { useState } from 'react'

// ─── Mock data ────────────────────────────────────────────────────────────────

const MOCK_CVES = [
  { id: 'CVE-2023-44487', image: 'nginx', tag: '1.21.3', severity: 'CRITICAL', pkg: 'nghttp2', installed: '1.43.0-1', fix: '1.43.0-2', desc: 'HTTP/2 Rapid Reset Attack — remote DoS via request cancellation' },
  { id: 'CVE-2023-3817', image: 'redis', tag: '6.2.6', severity: 'CRITICAL', pkg: 'openssl', installed: '1.1.1k', fix: '1.1.1l', desc: 'Excessive time spent checking DH keys and parameters' },
  { id: 'CVE-2022-4450', image: 'python', tag: '3.9-slim', severity: 'HIGH', pkg: 'openssl', installed: '1.1.1n', fix: '1.1.1t', desc: 'Double free after calling PEM_read_bio_ex' },
  { id: 'CVE-2023-0215', image: 'python', tag: '3.9-slim', severity: 'HIGH', pkg: 'openssl', installed: '1.1.1n', fix: '1.1.1t', desc: 'Use-after-free in BIO_new_NDEF' },
  { id: 'CVE-2023-1255', image: 'grafana', tag: 'latest', severity: 'HIGH', pkg: 'golang.org/x/net', installed: 'v0.7.0', fix: 'v0.8.0', desc: 'Excessive memory growth in HTTP/2 server' },
  { id: 'CVE-2023-27561', image: 'argus-agent', tag: 'latest', severity: 'MEDIUM', pkg: 'runc', installed: '1.1.3', fix: '1.1.5', desc: 'Container escape via improper handling of /proc/sys/fs/file-max' },
  { id: 'CVE-2022-41721', image: 'prometheus', tag: 'v2.40.0', severity: 'MEDIUM', pkg: 'golang.org/x/net', installed: 'v0.1.0', fix: 'v0.4.0', desc: 'Request smuggling via invalid Transfer-Encoding header' },
  { id: 'CVE-2023-0464', image: 'nginx', tag: '1.21.3', severity: 'LOW', pkg: 'openssl', installed: '1.1.1k', fix: null as string | null, desc: 'Infinite loop in BN_mod_sqrt for non-prime moduli' },
]

const MOCK_DRIFT = [
  { pod: 'nginx-prod-7d9f8b', namespace: 'prod', status: 'critical', changes: ['ENV DEBUG=true added at runtime', 'Image tag changed: 1.21.3 → 1.21.4-slim'], at: '14:22' },
  { pod: 'api-server-abc12', namespace: 'prod', status: 'warning', changes: ['Resource limits removed from spec'], at: '13:45' },
  { pod: 'redis-master-0', namespace: 'prod', status: 'clean', changes: [], at: '—' },
  { pod: 'grafana-5f9d', namespace: 'monitoring', status: 'warning', changes: ['ConfigMap mount removed'], at: '12:10' },
  { pod: 'argus-agent-xyz', namespace: 'argus-system', status: 'clean', changes: [], at: '—' },
  { pod: 'prometheus-0', namespace: 'monitoring', status: 'clean', changes: [], at: '—' },
]

const MOCK_SECRETS = [
  { pod: 'api-server-abc12', namespace: 'prod', type: 'env_var', key: 'AWS_SECRET_ACCESS_KEY', hint: 'value matches AWS secret key pattern', severity: 'high' },
  { pod: 'api-server-abc12', namespace: 'prod', type: 'env_var', key: 'DATABASE_PASSWORD', hint: 'plaintext string, not a secretKeyRef', severity: 'high' },
  { pod: 'app-staging-789', namespace: 'staging', type: 'env_var', key: 'STRIPE_SECRET_KEY', hint: 'matches sk_live_ prefix pattern', severity: 'high' },
  { pod: 'nginx-prod-7d9f8b', namespace: 'prod', type: 'log_output', key: 'access.log', hint: 'JWT token pattern found in access log line 2847', severity: 'medium' },
  { pod: 'grafana-5f9d', namespace: 'monitoring', type: 'env_var', key: 'GF_SECURITY_ADMIN_PASSWORD', hint: 'hardcoded string, not mounted from secret', severity: 'medium' },
]

const MOCK_CIS = [
  { id: '1.1.1', section: 'Control Plane', title: 'API server pod spec file permissions set to 644', result: 'pass', fix: '' },
  { id: '1.1.2', section: 'Control Plane', title: 'etcd data directory permissions set to 700', result: 'pass', fix: '' },
  { id: '1.2.1', section: 'API Server', title: 'Anonymous auth is disabled', result: 'fail', fix: 'Set --anonymous-auth=false in kube-apiserver flags' },
  { id: '1.2.6', section: 'API Server', title: 'AlwaysPullImages admission plugin is set', result: 'warn', fix: 'Enable AlwaysPullImages to prevent image caching attacks' },
  { id: '1.2.9', section: 'API Server', title: 'EventRateLimit is set', result: 'fail', fix: 'Configure --enable-admission-plugins=EventRateLimit' },
  { id: '2.1', section: 'etcd', title: 'etcd is configured with TLS', result: 'pass', fix: '' },
  { id: '2.2', section: 'etcd', title: 'etcd client cert auth is enabled', result: 'pass', fix: '' },
  { id: '3.1.1', section: 'RBAC', title: 'ClusterAdmin role not used for non-admin workloads', result: 'fail', fix: 'Audit service accounts with cluster-admin binding' },
  { id: '4.1.1', section: 'Worker Node', title: 'kubelet service file permissions set to 644', result: 'pass', fix: '' },
  { id: '4.2.1', section: 'Worker Node', title: 'kubelet anonymous auth is disabled', result: 'pass', fix: '' },
  { id: '4.2.6', section: 'Worker Node', title: 'kubelet ProtectKernelDefaults is enabled', result: 'warn', fix: 'Set --protect-kernel-defaults=true in kubelet config' },
  { id: '5.1.1', section: 'Policies', title: 'ClusterRoles restrict wildcard verbs', result: 'fail', fix: 'Audit RBAC roles for use of wildcard verbs (*)' },
  { id: '5.2.1', section: 'Policies', title: 'Privileged pods are disallowed', result: 'pass', fix: '' },
  { id: '5.2.5', section: 'Policies', title: 'Containers do not run as root by default', result: 'pass', fix: '' },
]

// ─── CVE Dashboard ────────────────────────────────────────────────────────────

function CveDashboard() {
  const [sevFilter, setSevFilter] = useState('ALL')
  const rows = sevFilter === 'ALL' ? MOCK_CVES : MOCK_CVES.filter(c => c.severity === sevFilter)
  const sc = (s: string) => s === 'CRITICAL' ? '#ff2d55' : s === 'HIGH' ? '#ff9f0a' : s === 'MEDIUM' ? '#ffd700' : '#8b949e'
  const counts = MOCK_CVES.reduce((a, c) => ({ ...a, [c.severity]: (a[c.severity] || 0) + 1 }), {} as Record<string, number>)

  return (
    <div>
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', alignItems: 'center' }}>
        {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(s => {
          const count = s === 'ALL' ? MOCK_CVES.length : (counts[s] || 0)
          const color = s === 'ALL' ? '#00d4ff' : sc(s)
          return (
            <button key={s} onClick={() => setSevFilter(s)} style={{
              display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 14px',
              borderRadius: '6px', border: `1px solid ${sevFilter === s ? color : `${color}30`}`,
              background: sevFilter === s ? `${color}15` : 'rgba(255,255,255,0.03)', cursor: 'pointer',
            }}>
              <span style={{ fontSize: '16px', fontWeight: 700, color, fontFamily: 'JetBrains Mono, monospace' }}>{count}</span>
              <span style={{ fontSize: '8px', color: sevFilter === s ? color : '#5a6478', textTransform: 'uppercase', letterSpacing: '1px' }}>{s}</span>
            </button>
          )
        })}
        <span style={{ marginLeft: 'auto', fontSize: '8px', color: '#4a5568' }}>last scanned 4m ago via Trivy</span>
      </div>

      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            {['CVE ID', 'Image', 'Severity', 'Package', 'Installed', 'Fix', 'Description'].map(h => (
              <th key={h} style={{ textAlign: 'left', fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', padding: '4px 8px', fontWeight: 400 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((cve, i) => (
            <tr key={cve.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', background: cve.severity === 'CRITICAL' ? 'rgba(255,45,85,0.04)' : i % 2 === 1 ? 'rgba(255,255,255,0.01)' : 'transparent' }}>
              <td style={{ padding: '6px 8px', fontSize: '9px', color: sc(cve.severity), fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>{cve.id}</td>
              <td style={{ padding: '6px 8px' }}>
                <div style={{ fontSize: '10px', color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>{cve.image}</div>
                <div style={{ fontSize: '8px', color: '#5a6478' }}>{cve.tag}</div>
              </td>
              <td style={{ padding: '6px 8px' }}>
                <span style={{ fontSize: '8px', fontWeight: 700, color: sc(cve.severity), background: `${sc(cve.severity)}15`, border: `1px solid ${sc(cve.severity)}30`, padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{cve.severity}</span>
              </td>
              <td style={{ padding: '6px 8px', fontSize: '9px', color: '#8892a4', fontFamily: 'JetBrains Mono, monospace' }}>{cve.pkg}</td>
              <td style={{ padding: '6px 8px', fontSize: '9px', color: '#ff2d55', fontFamily: 'JetBrains Mono, monospace' }}>{cve.installed}</td>
              <td style={{ padding: '6px 8px', fontSize: '9px', fontFamily: 'JetBrains Mono, monospace' }}>
                {cve.fix ? <span style={{ color: '#00ff9f' }}>{cve.fix}</span> : <span style={{ color: '#4a5568' }}>no fix</span>}
              </td>
              <td style={{ padding: '6px 8px', fontSize: '9px', color: '#8892a4', maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cve.desc}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── Drift Detection ──────────────────────────────────────────────────────────

function DriftDetection() {
  const [selected, setSelected] = useState<string | null>(null)
  const sc = (s: string) => s === 'critical' ? '#ff2d55' : s === 'warning' ? '#ff9f0a' : '#00ff9f'
  return (
    <div>
      <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
        {[
          { label: 'Clean', value: MOCK_DRIFT.filter(d => d.status === 'clean').length, color: '#00ff9f' },
          { label: 'Warnings', value: MOCK_DRIFT.filter(d => d.status === 'warning').length, color: '#ff9f0a' },
          { label: 'Critical', value: MOCK_DRIFT.filter(d => d.status === 'critical').length, color: '#ff2d55' },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ background: '#0d1421', border: `1px solid ${color}25`, borderRadius: '8px', padding: '10px 16px', display: 'flex', gap: '10px', alignItems: 'center' }}>
            <span style={{ fontSize: '20px', fontWeight: 700, color, fontFamily: 'JetBrains Mono, monospace' }}>{value}</span>
            <span style={{ fontSize: '8px', color: '#5a6478', textTransform: 'uppercase', letterSpacing: '1px' }}>{label}</span>
          </div>
        ))}
        <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', fontSize: '8px', color: '#4a5568' }}>Baseline snapshot from 08:00 today · click row to expand changes</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {MOCK_DRIFT.map(entry => (
          <div key={entry.pod} onClick={() => setSelected(selected === entry.pod ? null : entry.pod)} style={{
            padding: '12px 14px', borderRadius: '8px', cursor: 'pointer',
            background: selected === entry.pod ? 'rgba(0,212,255,0.06)' : entry.status === 'critical' ? 'rgba(255,45,85,0.05)' : entry.status === 'warning' ? 'rgba(255,159,10,0.04)' : 'rgba(0,0,0,0.2)',
            border: `1px solid ${selected === entry.pod ? 'rgba(0,212,255,0.25)' : sc(entry.status) + '25'}`,
            transition: 'all 0.12s',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: sc(entry.status), boxShadow: entry.status !== 'clean' ? `0 0 6px ${sc(entry.status)}` : 'none', flexShrink: 0 }} />
              <span style={{ fontSize: '11px', color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace', flex: 1 }}>{entry.pod}</span>
              <span style={{ fontSize: '9px', color: '#58a6ff', background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.2)', padding: '1px 6px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace' }}>{entry.namespace}</span>
              {entry.status !== 'clean'
                ? <span style={{ fontSize: '8px', color: sc(entry.status), fontFamily: 'JetBrains Mono, monospace' }}>{entry.changes.length} change{entry.changes.length > 1 ? 's' : ''} · {entry.at}</span>
                : <span style={{ fontSize: '8px', color: '#4a5568' }}>no drift detected</span>}
            </div>
            {selected === entry.pod && entry.changes.length > 0 && (
              <div style={{ marginTop: '10px', paddingTop: '10px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                {entry.changes.map((c, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', marginBottom: '4px' }}>
                    <span style={{ color: sc(entry.status), fontSize: '10px', marginTop: '1px' }}>▸</span>
                    <span style={{ fontSize: '11px', color: '#d1d5db' }}>{c}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Secret Scanning ──────────────────────────────────────────────────────────

function SecretScanning() {
  const sc = (s: string) => s === 'high' ? '#ff2d55' : '#ff9f0a'
  const tc = (t: string) => t === 'env_var' ? '#bc8cff' : '#ff9f0a'
  return (
    <div>
      <div style={{ display: 'flex', gap: '10px', marginBottom: '14px', alignItems: 'center' }}>
        <div style={{ padding: '8px 14px', borderRadius: '8px', background: 'rgba(255,45,85,0.08)', border: '1px solid rgba(255,45,85,0.2)' }}>
          <span style={{ fontSize: '18px', fontWeight: 700, color: '#ff2d55', fontFamily: 'JetBrains Mono, monospace', marginRight: '8px' }}>{MOCK_SECRETS.filter(s => s.severity === 'high').length}</span>
          <span style={{ fontSize: '8px', color: '#ff2d55', textTransform: 'uppercase', letterSpacing: '1px' }}>High severity</span>
        </div>
        <div style={{ padding: '8px 14px', borderRadius: '8px', background: 'rgba(255,159,10,0.08)', border: '1px solid rgba(255,159,10,0.2)' }}>
          <span style={{ fontSize: '18px', fontWeight: 700, color: '#ff9f0a', fontFamily: 'JetBrains Mono, monospace', marginRight: '8px' }}>{MOCK_SECRETS.filter(s => s.severity === 'medium').length}</span>
          <span style={{ fontSize: '8px', color: '#ff9f0a', textTransform: 'uppercase', letterSpacing: '1px' }}>Medium severity</span>
        </div>
        <span style={{ marginLeft: 'auto', fontSize: '8px', color: '#4a5568' }}>Scans env vars and log streams · use secretKeyRef to remediate</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '14px' }}>
        {MOCK_SECRETS.map((hit, i) => (
          <div key={i} style={{ padding: '12px 14px', borderRadius: '8px', background: hit.severity === 'high' ? 'rgba(255,45,85,0.05)' : 'rgba(255,159,10,0.04)', border: `1px solid ${sc(hit.severity)}25` }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <span style={{ fontSize: '8px', fontWeight: 700, color: sc(hit.severity), background: `${sc(hit.severity)}15`, border: `1px solid ${sc(hit.severity)}30`, padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{hit.severity.toUpperCase()}</span>
              <span style={{ fontSize: '8px', color: tc(hit.type), background: `${tc(hit.type)}15`, border: `1px solid ${tc(hit.type)}25`, padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{hit.type === 'env_var' ? 'ENV VAR' : 'LOG OUTPUT'}</span>
              <span style={{ fontSize: '9px', color: '#58a6ff', background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.2)', padding: '1px 6px', borderRadius: '3px', fontFamily: 'JetBrains Mono, monospace', marginLeft: 'auto' }}>{hit.namespace}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '10px', color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace', flex: 1 }}>{hit.pod}</span>
              <span style={{ fontSize: '10px', color: sc(hit.severity), fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>{hit.key}</span>
            </div>
            <div style={{ marginTop: '4px', fontSize: '9px', color: '#8892a4' }}>{hit.hint}</div>
          </div>
        ))}
      </div>
      <div style={{ padding: '10px 14px', borderRadius: '8px', background: 'rgba(88,166,255,0.05)', border: '1px solid rgba(88,166,255,0.15)' }}>
        <div style={{ fontSize: '9px', color: '#58a6ff', marginBottom: '4px', fontWeight: 600 }}>Fix pattern</div>
        <div style={{ fontSize: '9px', color: '#8892a4', lineHeight: 1.6 }}>
          Replace hardcoded env values with <span style={{ color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>secretKeyRef</span> in your pod spec. Kyverno policy <span style={{ color: '#bc8cff', fontFamily: 'JetBrains Mono, monospace' }}>disallow-env-secrets</span> can enforce this automatically at admission time.
        </div>
      </div>
    </div>
  )
}

// ─── CIS Compliance ───────────────────────────────────────────────────────────

function CisCompliance() {
  const [sectionFilter, setSectionFilter] = useState('ALL')
  const sections = ['ALL', ...Array.from(new Set(MOCK_CIS.map(c => c.section)))]
  const pass = MOCK_CIS.filter(c => c.result === 'pass').length
  const fail = MOCK_CIS.filter(c => c.result === 'fail').length
  const warn = MOCK_CIS.filter(c => c.result === 'warn').length
  const score = Math.round((pass / MOCK_CIS.length) * 100)
  const rows = sectionFilter === 'ALL' ? MOCK_CIS : MOCK_CIS.filter(c => c.section === sectionFilter)
  const rc = (r: string) => r === 'pass' ? '#00ff9f' : r === 'fail' ? '#ff2d55' : '#ff9f0a'
  const rl = (r: string) => r === 'pass' ? '✓ PASS' : r === 'fail' ? '✗ FAIL' : '⚠ WARN'
  const scoreColor = score >= 70 ? '#00ff9f' : score >= 50 ? '#ff9f0a' : '#ff2d55'

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '20px', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ position: 'relative', width: '64px', height: '64px', flexShrink: 0 }}>
            <svg width="64" height="64" viewBox="0 0 64 64">
              <circle cx="32" cy="32" r="28" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="6" />
              <circle cx="32" cy="32" r="28" fill="none" stroke={scoreColor} strokeWidth="6"
                strokeDasharray={`${score * 1.759} 175.9`} strokeLinecap="round" strokeDashoffset="44" transform="rotate(-90 32 32)" />
            </svg>
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '14px', fontWeight: 700, color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>{score}</div>
          </div>
          <div>
            <div style={{ fontSize: '12px', fontWeight: 600, color: '#e6edf3', marginBottom: '2px' }}>CIS K8s Benchmark</div>
            <div style={{ fontSize: '9px', color: '#5a6478' }}>{MOCK_CIS.length} automated checks</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          {[{ label: 'Pass', count: pass, color: '#00ff9f' }, { label: 'Fail', count: fail, color: '#ff2d55' }, { label: 'Warn', count: warn, color: '#ff9f0a' }].map(({ label, count, color }) => (
            <div key={label} style={{ padding: '6px 12px', borderRadius: '6px', background: `${color}12`, border: `1px solid ${color}25`, textAlign: 'center' }}>
              <div style={{ fontSize: '18px', fontWeight: 700, color, fontFamily: 'JetBrains Mono, monospace' }}>{count}</div>
              <div style={{ fontSize: '8px', color, textTransform: 'uppercase', letterSpacing: '1px' }}>{label}</div>
            </div>
          ))}
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
          {sections.map(s => (
            <button key={s} onClick={() => setSectionFilter(s)} style={{ fontSize: '8px', padding: '3px 8px', borderRadius: '4px', border: 'none', cursor: 'pointer', background: sectionFilter === s ? 'rgba(0,212,255,0.12)' : 'rgba(255,255,255,0.04)', color: sectionFilter === s ? '#00d4ff' : '#5a6478', fontFamily: 'JetBrains Mono, monospace' }}>{s}</button>
          ))}
        </div>
      </div>

      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            {['Check', 'Section', 'Result', 'Description', 'Remediation'].map(h => (
              <th key={h} style={{ textAlign: 'left', fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', padding: '4px 8px', fontWeight: 400 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((c, i) => (
            <tr key={c.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', background: c.result === 'fail' ? 'rgba(255,45,85,0.03)' : i % 2 === 1 ? 'rgba(255,255,255,0.01)' : 'transparent' }}>
              <td style={{ padding: '6px 8px', fontSize: '9px', color: '#8892a4', fontFamily: 'JetBrains Mono, monospace' }}>{c.id}</td>
              <td style={{ padding: '6px 8px', fontSize: '9px', color: '#5a6478', fontFamily: 'JetBrains Mono, monospace', whiteSpace: 'nowrap' }}>{c.section}</td>
              <td style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>
                <span style={{ fontSize: '8px', fontWeight: 700, color: rc(c.result), background: `${rc(c.result)}15`, border: `1px solid ${rc(c.result)}30`, padding: '2px 7px', borderRadius: '4px', fontFamily: 'JetBrains Mono, monospace' }}>{rl(c.result)}</span>
              </td>
              <td style={{ padding: '6px 8px', fontSize: '10px', color: '#d1d5db' }}>{c.title}</td>
              <td style={{ padding: '6px 8px', fontSize: '9px', color: c.fix ? '#8892a4' : '#4a5568' }}>{c.fix || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

type Tab = 'cve' | 'drift' | 'secrets' | 'cis'

export default function SecurityPosture() {
  const [tab, setTab] = useState<Tab>('cve')

  const tabs: { id: Tab; label: string; badge?: string }[] = [
    { id: 'cve', label: 'CVE Dashboard', badge: '3' },
    { id: 'drift', label: 'Drift Detection', badge: '3' },
    { id: 'secrets', label: 'Secret Scanning', badge: '5' },
    { id: 'cis', label: 'CIS Benchmark' },
  ]

  return (
    <div style={{ padding: '14px', fontFamily: 'Inter, sans-serif', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <style>{`@keyframes glowpulse{0%,100%{opacity:1}50%{opacity:0.5}}`}</style>

      <div style={{ fontSize: '9px', color: '#bc8cff', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace' }}>⬡ Security Posture</div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
        {[
          { label: 'Critical CVEs', value: MOCK_CVES.filter(c => c.severity === 'CRITICAL').length, color: '#ff2d55', sub: 'in prod images' },
          { label: 'Drifted pods', value: MOCK_DRIFT.filter(d => d.status !== 'clean').length, color: '#ff9f0a', sub: 'vs baseline' },
          { label: 'Secret exposures', value: MOCK_SECRETS.length, color: '#ff9f0a', sub: 'across namespaces' },
          { label: 'CIS score', value: '73/100', color: '#00ff9f', sub: '10/14 checks pass' },
        ].map(({ label, value, color, sub }) => (
          <div key={label} style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '8px', padding: '10px 12px' }}>
            <div style={{ fontSize: '8px', color: '#4a5568', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '4px' }}>{label}</div>
            <div style={{ fontSize: '22px', fontWeight: 700, color, letterSpacing: '-0.02em' }}>{value}</div>
            <div style={{ fontSize: '8px', color: '#5a6478', marginTop: '2px' }}>{sub}</div>
          </div>
        ))}
      </div>

      <div style={{ background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '12px', flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.06)', padding: '0 16px', flexShrink: 0 }}>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              fontSize: '9px', padding: '12px 14px', border: 'none', cursor: 'pointer',
              background: 'transparent', color: tab === t.id ? '#bc8cff' : '#5a6478',
              borderBottom: tab === t.id ? '2px solid #bc8cff' : '2px solid transparent',
              fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase', letterSpacing: '1px',
              display: 'flex', alignItems: 'center', gap: '5px', transition: 'color 0.15s',
            }}>
              {t.label}
              {t.badge && <span style={{ fontSize: '7px', background: '#ff2d55', color: '#fff', width: '14px', height: '14px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700 }}>{t.badge}</span>}
            </button>
          ))}
        </div>
        <div style={{ padding: '16px', overflow: 'auto' }}>
          {tab === 'cve' && <CveDashboard />}
          {tab === 'drift' && <DriftDetection />}
          {tab === 'secrets' && <SecretScanning />}
          {tab === 'cis' && <CisCompliance />}
        </div>
      </div>
    </div>
  )
}
