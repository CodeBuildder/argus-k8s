import React, { useState, useEffect, useRef } from 'react'
import FormattedAssistantContent from '../components/FormattedAssistantContent'

const API = '/api'

interface Message {
  role: 'user' | 'assistant'
  content: string
  ts?: number
}

const QUICK_ACTIONS = [
  { label: 'Summarize last hour', query: 'Give me a summary of all security incidents in the last hour. What are the key patterns?' },
  { label: 'Top threats', query: 'What are the most critical threats right now? Which ones need immediate attention?' },
  { label: 'What bypassed Kyverno?', query: 'Which threats bypassed Kyverno admission control and made it into the cluster? What runtime detections fired?' },
  { label: 'Kyverno blocks', query: 'What did Kyverno block today? Were these legitimate policy violations or misconfigured deployments?' },
  { label: 'Lateral movement', query: 'Is there any evidence of lateral movement between pods or namespaces?' },
  { label: 'Risk forecast', query: 'Based on current activity, what threats should I watch for in the next few hours?' },
]

const WELCOME: Message = {
  role: 'assistant',
  content: `Welcome to **Argus AI** — your embedded Kubernetes security analyst.

I have full situational awareness of the argus-k8s cluster: live incident telemetry, Falco runtime detections, Kyverno admission blocks, Cilium network flows, and eBPF kernel events.

You can ask me to:
• Investigate specific threats or explain what happened
• Identify attack patterns across the incident feed
• Suggest remediation steps with kubectl commands
• Explain MITRE ATT&CK techniques observed in your cluster
• Forecast emerging risks based on current activity

Use the quick actions below or type any question.`,
  ts: Date.now(),
}

function TypingIndicator() {
  return (
    <div style={{ display: 'flex', gap: '4px', alignItems: 'center', padding: '10px 0' }}>
      {[0, 1, 2].map(i => (
        <div key={i} style={{
          width: '6px', height: '6px', borderRadius: '50%', background: '#00ff9f',
          animation: `typingDot 1.2s ease-in-out ${i * 0.2}s infinite`,
        }} />
      ))}
      <span style={{ fontSize: '9px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace', marginLeft: '6px' }}>Argus AI is analyzing...</span>
    </div>
  )
}

export default function AgentChat() {
  const [messages, setMessages] = useState<Message[]>([WELCOME])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [connected, setConnected] = useState<boolean | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    fetch(`${API}/health`).then(r => setConnected(r.ok)).catch(() => setConnected(false))
  }, [])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  const send = async (userInput: string) => {
    const text = userInput.trim()
    if (!text || loading) return

    const userMsg: Message = { role: 'user', content: text, ts: Date.now() }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)

    const history = [...messages.filter(m => m !== WELCOME || messages.length === 1), userMsg]
      .map(m => ({ role: m.role, content: m.content }))

    try {
      const res = await fetch(`${API}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: history }),
      })
      const data = await res.json()
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.response || data.error || 'No response',
        ts: Date.now(),
      }])
    } catch {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: 'Failed to reach Argus AI. Check that the agent is running at /api/health.',
        ts: Date.now(),
      }])
    } finally {
      setLoading(false)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }

  const onKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send(input)
    }
  }

  const fmt = (ts?: number) => ts ? new Date(ts).toTimeString().slice(0, 8) : ''

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: '#0d1117', fontFamily: 'Inter, sans-serif' }}>
      <style>{`
        @keyframes typingDot { 0%,60%,100%{transform:translateY(0)} 30%{transform:translateY(-4px)} }
        @keyframes fadeInUp { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
        @keyframes glowpulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        .chat-input:focus { outline: none; border-color: rgba(0,255,159,0.4) !important; }
        .chat-input::placeholder { color: #3d4a5f; }
        .qa-btn:hover { background: rgba(0,255,159,0.1) !important; border-color: rgba(0,255,159,0.4) !important; color: #00ff9f !important; }
      `}</style>

      {/* Header */}
      <div style={{ padding: '12px 20px', borderBottom: '1px solid rgba(0,255,159,0.08)', display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>
        <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: connected === true ? '#00ff9f' : connected === false ? '#ff2d55' : '#ff9f0a', boxShadow: connected === true ? '0 0 8px #00ff9f' : 'none', animation: connected === true ? 'glowpulse 2s infinite' : 'none' }} />
        <span style={{ fontSize: '10px', color: '#00ff9f', textTransform: 'uppercase', letterSpacing: '2px', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>◎ Argus AI</span>
        <span style={{ fontSize: '9px', color: '#4a5568', fontFamily: 'JetBrains Mono, monospace' }}>— Security Intelligence</span>
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: '8px', color: connected === true ? '#00ff9f' : connected === false ? '#ff2d55' : '#ff9f0a', fontFamily: 'JetBrains Mono, monospace' }}>
          {connected === true ? '● connected · argus-k8s' : connected === false ? '○ agent offline' : '◌ connecting...'}
        </span>
        <button
          onClick={() => { setMessages([WELCOME]); setInput('') }}
          style={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '6px', color: '#4a5568', cursor: 'pointer', padding: '3px 10px', fontSize: '9px', fontFamily: 'JetBrains Mono, monospace', transition: 'all 0.15s' }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(255,45,85,0.3)'; e.currentTarget.style.color = '#ff2d55' }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)'; e.currentTarget.style.color = '#4a5568' }}
        >
          Clear
        </button>
      </div>

      {/* Messages */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {messages.map((msg, i) => (
          <div key={i} style={{ display: 'flex', flexDirection: msg.role === 'user' ? 'row-reverse' : 'row', gap: '10px', alignItems: 'flex-start', animation: 'fadeInUp 0.25s ease-out' }}>
            {/* Avatar */}
            <div style={{
              width: '28px', height: '28px', borderRadius: '50%', flexShrink: 0,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: '11px', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace',
              background: msg.role === 'user' ? 'rgba(88,166,255,0.15)' : 'rgba(0,255,159,0.1)',
              border: `1px solid ${msg.role === 'user' ? 'rgba(88,166,255,0.3)' : 'rgba(0,255,159,0.25)'}`,
              color: msg.role === 'user' ? '#58a6ff' : '#00ff9f',
            }}>
              {msg.role === 'user' ? 'U' : 'A'}
            </div>

            {/* Bubble */}
            <div style={{ maxWidth: '72%', display: 'flex', flexDirection: 'column', gap: '4px', alignItems: msg.role === 'user' ? 'flex-end' : 'flex-start' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
                {msg.role === 'assistant' && (
                  <span style={{ fontSize: '9px', color: '#00ff9f', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>ARGUS AI</span>
                )}
                {msg.role === 'user' && (
                  <span style={{ fontSize: '9px', color: '#58a6ff', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>YOU</span>
                )}
                <span style={{ fontSize: '8px', color: '#3d4a5f', fontFamily: 'JetBrains Mono, monospace' }}>{fmt(msg.ts)}</span>
              </div>

              <div style={{
                padding: '10px 14px',
                background: msg.role === 'user' ? 'rgba(88,166,255,0.1)' : '#111827',
                border: `1px solid ${msg.role === 'user' ? 'rgba(88,166,255,0.25)' : 'rgba(0,255,159,0.08)'}`,
                borderRadius: msg.role === 'user' ? '12px 4px 12px 12px' : '4px 12px 12px 12px',
                borderLeft: msg.role === 'assistant' ? '3px solid rgba(0,255,159,0.4)' : undefined,
              }}>
                {msg.role === 'user' ? (
                  <span style={{ fontSize: '12px', color: '#e2e8f5', lineHeight: 1.6 }}>{msg.content}</span>
                ) : (
                  <FormattedAssistantContent content={msg.content} />
                )}
              </div>
            </div>
          </div>
        ))}

        {loading && (
          <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-start', animation: 'fadeInUp 0.2s ease-out' }}>
            <div style={{ width: '28px', height: '28px', borderRadius: '50%', flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '11px', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', background: 'rgba(0,255,159,0.1)', border: '1px solid rgba(0,255,159,0.25)', color: '#00ff9f' }}>A</div>
            <div style={{ padding: '10px 14px', background: '#111827', border: '1px solid rgba(0,255,159,0.08)', borderRadius: '4px 12px 12px 12px', borderLeft: '3px solid rgba(0,255,159,0.4)' }}>
              <TypingIndicator />
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Quick actions */}
      <div style={{ padding: '10px 20px 0', borderTop: '1px solid rgba(0,255,159,0.06)', display: 'flex', gap: '6px', flexWrap: 'wrap', flexShrink: 0 }}>
        <span style={{ fontSize: '8px', color: '#3d4a5f', fontFamily: 'JetBrains Mono, monospace', alignSelf: 'center', marginRight: '2px' }}>QUICK:</span>
        {QUICK_ACTIONS.map(qa => (
          <button
            key={qa.label}
            className="qa-btn"
            onClick={() => send(qa.query)}
            disabled={loading}
            style={{
              background: 'rgba(0,255,159,0.04)', border: '1px solid rgba(0,255,159,0.15)',
              borderRadius: '20px', color: '#6b7280', cursor: loading ? 'not-allowed' : 'pointer',
              padding: '4px 12px', fontSize: '9px', fontFamily: 'JetBrains Mono, monospace',
              transition: 'all 0.15s', opacity: loading ? 0.5 : 1,
            }}
          >
            {qa.label}
          </button>
        ))}
      </div>

      {/* Input */}
      <div style={{ padding: '12px 20px 16px', flexShrink: 0 }}>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-end', background: '#111827', border: '1px solid rgba(0,255,159,0.15)', borderRadius: '10px', padding: '10px 14px' }}>
          <span style={{ fontSize: '10px', color: '#3d4a5f', fontFamily: 'JetBrains Mono, monospace', alignSelf: 'flex-end', marginBottom: '1px', flexShrink: 0 }}>›</span>
          <textarea
            ref={inputRef}
            className="chat-input"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={onKey}
            placeholder="Ask about threats, incidents, cluster security... (Enter to send, Shift+Enter for newline)"
            disabled={loading}
            rows={1}
            style={{
              flex: 1, background: 'transparent', border: 'none', color: '#e2e8f5',
              fontSize: '12px', resize: 'none', fontFamily: 'Inter, sans-serif',
              lineHeight: 1.5, maxHeight: '100px', overflowY: 'auto',
            }}
            onInput={e => {
              const t = e.currentTarget
              t.style.height = 'auto'
              t.style.height = Math.min(t.scrollHeight, 100) + 'px'
            }}
          />
          <button
            onClick={() => send(input)}
            disabled={!input.trim() || loading}
            style={{
              background: input.trim() && !loading ? 'rgba(0,255,159,0.15)' : 'rgba(255,255,255,0.04)',
              border: `1px solid ${input.trim() && !loading ? 'rgba(0,255,159,0.4)' : 'rgba(255,255,255,0.08)'}`,
              borderRadius: '6px', color: input.trim() && !loading ? '#00ff9f' : '#3d4a5f',
              cursor: input.trim() && !loading ? 'pointer' : 'not-allowed',
              padding: '6px 14px', fontSize: '10px', fontWeight: 700,
              fontFamily: 'JetBrains Mono, monospace', transition: 'all 0.15s', flexShrink: 0,
            }}
          >
            {loading ? '...' : '↵ Send'}
          </button>
        </div>
        <div style={{ fontSize: '8px', color: '#2a3349', textAlign: 'center', marginTop: '6px', fontFamily: 'JetBrains Mono, monospace' }}>
          Powered by Claude · Full cluster context · Shift+Enter for newline
        </div>
      </div>

      <style>{`
        ::-webkit-scrollbar { width: 2px; }
        ::-webkit-scrollbar-thumb { background: rgba(0,255,159,0.15); border-radius: 1px; }
      `}</style>
    </div>
  )
}
