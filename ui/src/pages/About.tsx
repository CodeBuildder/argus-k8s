import { Activity, BrainCircuit, CloudCog, GitBranch, RadioTower, ShieldCheck, Zap } from 'lucide-react'

const pipeline = [
  { label: 'Kernel signal', detail: 'Falco and eBPF surface runtime behavior as it happens.', icon: RadioTower, color: '#00d4ff' },
  { label: 'Cluster context', detail: 'Cilium, Kyverno, and Kubernetes state add blast-radius evidence.', icon: GitBranch, color: '#00ff9f' },
  { label: 'Threat decision', detail: 'Argus scores confidence, MITRE stage, and recommended containment.', icon: BrainCircuit, color: '#bc8cff' },
  { label: 'Autonomous action', detail: 'Policy-aware remediation isolates, terminates, notifies, or asks a human.', icon: Zap, color: '#ff9f0a' },
]

const proofPoints = [
  { value: '3', label: 'k3s nodes', color: '#00ff9f' },
  { value: '<30s', label: 'action window', color: '#00d4ff' },
  { value: 'MITRE', label: 'kill-chain reasoning', color: '#bc8cff' },
  { value: 'eBPF', label: 'kernel visibility', color: '#ff9f0a' },
]

const stack = [
  'k3s',
  'Cilium eBPF',
  'Falco',
  'Kyverno',
  'Detection engine',
  'FastAPI',
  'React',
  'Prometheus',
  'Grafana',
  'Loki',
]

const principles = [
  'Every alert carries evidence, confidence, blast radius, and a next action.',
  'Human approval stays in the path for ambiguous or high-impact remediation.',
  'Chaos-driven threat injection keeps the console honest under multi-stage attacks.',
  'Local-first Kubernetes makes the system reproducible without cloud ceremony.',
]

export default function About() {
  return (
    <div className="min-h-full overflow-y-auto bg-[#060912] text-[#e6edf3]" style={{ fontFamily: 'Inter, sans-serif' }}>
      <section className="border-b border-[rgba(0,255,159,0.12)] bg-[#080d18]">
        <div className="grid gap-7 px-8 py-8 xl:grid-cols-[1.05fr_0.95fr]">
          <div className="flex min-w-0 flex-col justify-center gap-6">
            <div className="flex flex-wrap items-center gap-3">
              <span className="rounded-md border border-[rgba(0,255,159,0.35)] bg-[rgba(0,255,159,0.08)] px-3 py-1 font-mono text-[10px] font-bold uppercase tracking-[0.24em] text-[#00ff9f]">
                Live Defense Platform
              </span>
              <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#5a6478]">
                Kubernetes Runtime Security
              </span>
            </div>

            <div>
              <h1 className="max-w-4xl text-[38px] font-bold leading-tight text-[#f0f6fc]">
                Autonomous Kubernetes defense, verified on a real local cluster.
              </h1>
              <p className="mt-5 max-w-5xl text-[16px] leading-8 text-[#b8c2d6]">
                Argus turns raw runtime telemetry into reasoned containment. Falco watches syscalls,
                Cilium adds network truth, Kyverno guards admission, and the agent correlates the chain
                before taking the smallest useful action.
              </p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              {proofPoints.map(point => (
                <div key={point.label} className="rounded-lg border border-[rgba(255,255,255,0.08)] bg-[#101826] p-4">
                  <div className="font-mono text-[24px] font-bold" style={{ color: point.color }}>{point.value}</div>
                  <div className="mt-1 font-mono text-[9px] uppercase tracking-[0.18em] text-[#6f7a8e]">{point.label}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="min-w-0 rounded-lg border border-[rgba(0,212,255,0.18)] bg-[#0d1420] p-3">
            <div className="mb-3 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[#00d4ff]">
                <Activity size={14} />
                Observability Proof
              </div>
              <span className="rounded-md border border-[rgba(0,255,159,0.2)] bg-[rgba(0,255,159,0.08)] px-2 py-1 font-mono text-[9px] text-[#00ff9f]">
                local cluster
              </span>
            </div>
            <img
              src="/about-security-overview.png"
              alt="Argus Grafana security overview dashboard"
              className="h-auto w-full rounded-md border border-[rgba(255,255,255,0.08)]"
            />
          </div>
        </div>
      </section>

      <section className="px-8 py-7">
        <div className="mb-4 flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-[#00ff9f]">
          <ShieldCheck size={14} />
          How Defense Moves
        </div>
        <div className="grid gap-4 lg:grid-cols-4">
          {pipeline.map(({ label, detail, icon: Icon, color }) => (
            <div key={label} className="rounded-lg border border-[rgba(255,255,255,0.08)] bg-[#101826] p-5">
              <div className="mb-5 flex h-9 w-9 items-center justify-center rounded-md border" style={{ borderColor: `${color}55`, background: `${color}14`, color }}>
                <Icon size={18} />
              </div>
              <h2 className="text-[14px] font-bold text-[#f0f6fc]">{label}</h2>
              <p className="mt-3 text-[12px] leading-6 text-[#9aa7bb]">{detail}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="border-b border-[rgba(0,255,159,0.08)] px-8 py-5">
        <div className="flex items-center gap-3">
          <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-[#4a5568]">Built by</span>
          <span className="font-mono text-[13px] font-bold text-[#e6edf3]">Kaushik Kumaran</span>
          <span className="font-mono text-[11px] text-[#58a6ff]">a.k.a CodeBuildder</span>
        </div>
      </section>

      <section className="grid gap-5 px-8 pb-8 xl:grid-cols-[0.9fr_1.1fr]">
        <div className="rounded-lg border border-[rgba(188,140,255,0.16)] bg-[#101826] p-5">
          <div className="mb-5 flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-[#bc8cff]">
            <CloudCog size={14} />
            Operating Model
          </div>
          <div className="flex flex-col gap-3">
            {principles.map(principle => (
              <div key={principle} className="rounded-md border border-[rgba(255,255,255,0.06)] bg-[#0b111d] p-4 text-[12px] leading-6 text-[#c8d2e5]">
                {principle}
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-lg border border-[rgba(0,212,255,0.14)] bg-[#101826] p-5">
          <div className="mb-5 font-mono text-[10px] uppercase tracking-[0.22em] text-[#00d4ff]">
            Stack
          </div>
          <div className="flex flex-wrap gap-2">
            {stack.map(item => (
              <span key={item} className="rounded-md border border-[rgba(0,212,255,0.2)] bg-[rgba(0,212,255,0.07)] px-3 py-2 font-mono text-[11px] text-[#80d8ff]">
                {item}
              </span>
            ))}
          </div>
          <div className="mt-6 grid gap-3 md:grid-cols-3">
            {[
              ['Detect', 'Runtime events, admission risks, and network movement.'],
              ['Reason', 'Blast radius, MITRE stage, false-positive risk, and confidence.'],
              ['Respond', 'Containment that favors precision over noise.'],
            ].map(([title, body]) => (
              <div key={title} className="rounded-md border border-[rgba(255,255,255,0.06)] bg-[#0b111d] p-4">
                <div className="font-mono text-[11px] font-bold uppercase tracking-[0.16em] text-[#f0f6fc]">{title}</div>
                <p className="mt-3 text-[12px] leading-6 text-[#9aa7bb]">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  )
}
