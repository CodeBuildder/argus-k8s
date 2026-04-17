export default function CommandCenter() {
  return (
    <div className="p-6 font-mono">
      <div className="text-[#00d4ff] text-xs uppercase tracking-widest mb-4">⌂ Command Center</div>
      <div className="grid grid-cols-3 gap-4 mb-6">
        {[
          { label: 'Active threats', value: '3', color: 'text-[#ff4757]' },
          { label: 'Auto-remediated', value: '38', color: 'text-[#00d4ff]' },
          { label: 'False positives', value: '9', color: 'text-[#00ff88]' },
          { label: 'Policies blocked', value: '23', color: 'text-[#00d4ff]' },
          { label: 'Network drops', value: '312', color: 'text-[#ff6b35]' },
          { label: 'Posture score', value: '73/100', color: 'text-[#ffd700]' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-[#0f1525] border border-[rgba(99,179,237,0.12)] rounded-lg p-4">
            <div className="text-[9px] text-[#5a6478] uppercase tracking-widest mb-1">{label}</div>
            <div className={`text-2xl font-bold ${color}`}>{value}</div>
          </div>
        ))}
      </div>
      <div className="text-[#5a6478] text-xs">Full dashboard coming in issue #19</div>
    </div>
  )
}
