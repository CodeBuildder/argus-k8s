import React from 'react'

function stripDecorativeGlyphs(text: string): string {
  return text
    // Remove all emoji/pictographic characters anywhere in the text
    .replace(/[\p{Extended_Pictographic}\u2600-\u27BF]/gu, '')
    // Remove REC-N, REC-N — style labels
    .replace(/\bREC-\d+\s*(?:—|--)?\s*/g, '')
    // Remove blockquote markers
    .replace(/^\s*>\s*/g, '')
    // Clean up multiple spaces left after stripping
    .replace(/  +/g, ' ')
    .trim()
}

function renderInline(text: string): React.ReactNode[] {
  const nodes: React.ReactNode[] = []
  const safeText = stripDecorativeGlyphs(text)
  const pattern = /(`[^`]+`|\*\*[^*]+\*\*)/g
  let lastIndex = 0
  let match: RegExpExecArray | null
  let key = 0

  while ((match = pattern.exec(safeText)) !== null) {
    if (match.index > lastIndex) {
      nodes.push(<span key={key++}>{safeText.slice(lastIndex, match.index)}</span>)
    }
    const token = match[0]
    if (token.startsWith('**')) {
      nodes.push(<strong key={key++} style={{ color: '#f0f6fc', fontWeight: 700 }}>{token.slice(2, -2)}</strong>)
    } else if (token.startsWith('`')) {
      nodes.push(
        <code
          key={key++}
          style={{
            background: 'rgba(0,0,0,0.36)',
            border: '1px solid rgba(0,255,159,0.14)',
            borderRadius: '4px',
            padding: '1px 6px',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: '0.92em',
            color: '#00ff9f',
          }}
        >
          {token.slice(1, -1)}
        </code>
      )
    }
    lastIndex = pattern.lastIndex
  }

  if (lastIndex < safeText.length) {
    nodes.push(<span key={key++}>{safeText.slice(lastIndex)}</span>)
  }

  return nodes
}

function parseTableRow(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map(cell => cell.trim())
}

export default function FormattedAssistantContent({ content, compact = false }: { content: string; compact?: boolean }) {
  const lines = content.split('\n')
  const output: React.ReactNode[] = []
  let key = 0
  let inCode = false
  let codeLines: string[] = []

  const flushCode = () => {
    if (!codeLines.length) return
    output.push(
      <pre
        key={key++}
        style={{
          margin: compact ? '6px 0' : '8px 0',
          padding: compact ? '8px 10px' : '10px 12px',
          background: 'rgba(0,0,0,0.5)',
          border: '1px solid rgba(0,255,159,0.15)',
          borderRadius: '8px',
          color: '#00ff9f',
          fontSize: compact ? '10px' : '11px',
          lineHeight: 1.65,
          overflowX: 'auto',
          fontFamily: 'JetBrains Mono, monospace',
          whiteSpace: 'pre-wrap',
        }}
      >
        {codeLines.join('\n')}
      </pre>
    )
    codeLines = []
  }

  for (let i = 0; i < lines.length; i += 1) {
    const line = stripDecorativeGlyphs(lines[i])

    if (line.startsWith('```')) {
      if (inCode) {
        flushCode()
        inCode = false
      } else {
        inCode = true
      }
      continue
    }

    if (inCode) {
      codeLines.push(line)
      continue
    }

    const next = lines[i + 1]
    if (line.includes('|') && next && /^\|?[-:\s|]+\|?$/.test(next.trim())) {
      const headers = parseTableRow(line)
      const rows: string[][] = []
      i += 2
      while (i < lines.length && lines[i].includes('|')) {
        rows.push(parseTableRow(lines[i]))
        i += 1
      }
      i -= 1
      output.push(
        <div key={key++} style={{ overflowX: 'auto', margin: compact ? '6px 0' : '8px 0' }}>
          <table style={{ width: '100%', borderCollapse: 'separate', borderSpacing: 0, fontSize: compact ? '10px' : '11px' }}>
            <thead>
              <tr>
                {headers.map((header, idx) => (
                  <th
                    key={idx}
                    style={{
                      textAlign: 'left',
                      padding: compact ? '7px 8px' : '8px 10px',
                      color: '#00d4ff',
                      fontFamily: 'JetBrains Mono, monospace',
                      fontWeight: 700,
                      borderBottom: '1px solid rgba(0,212,255,0.18)',
                      background: 'rgba(0,212,255,0.06)',
                    }}
                  >
                    {header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, rowIdx) => (
                <tr key={rowIdx}>
                  {row.map((cell, cellIdx) => (
                    <td
                      key={cellIdx}
                      style={{
                        padding: compact ? '7px 8px' : '8px 10px',
                        color: '#d1d5db',
                        lineHeight: 1.55,
                        borderBottom: '1px solid rgba(255,255,255,0.05)',
                        background: rowIdx % 2 === 0 ? 'rgba(255,255,255,0.02)' : 'transparent',
                      }}
                    >
                      {renderInline(cell)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
      continue
    }

    if (!line.trim()) {
      output.push(<div key={key++} style={{ height: compact ? '6px' : '8px' }} />)
      continue
    }

    if (/^---+$/.test(line.trim())) {
      output.push(<div key={key++} style={{ height: '1px', background: 'rgba(255,255,255,0.08)', margin: compact ? '6px 0' : '8px 0' }} />)
      continue
    }

    if (/^#{1,3}\s/.test(line)) {
      output.push(
        <div
          key={key++}
          style={{
            fontSize: compact ? '10px' : '11px',
            fontWeight: 700,
            color: '#00ff9f',
            marginTop: compact ? '6px' : '8px',
            marginBottom: '4px',
            fontFamily: 'JetBrains Mono, monospace',
            textTransform: 'uppercase',
            letterSpacing: '1px',
          }}
        >
          {line.replace(/^#{1,3}\s*/, '')}
        </div>
      )
      continue
    }

    if (/^[\-\*•]\s/.test(line)) {
      output.push(
        <div key={key++} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', marginBottom: '4px' }}>
          <span style={{ color: '#00ff9f', marginTop: '2px', flexShrink: 0 }}>•</span>
          <div style={{ fontSize: compact ? '11px' : '12px', color: '#d1d5db', lineHeight: 1.6 }}>{renderInline(line.replace(/^[\-\*•]\s*/, ''))}</div>
        </div>
      )
      continue
    }

    if (/^\d+\.\s/.test(line)) {
      const index = line.match(/^(\d+)\./)?.[1] || ''
      output.push(
        <div key={key++} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', marginBottom: '4px' }}>
          <span style={{ width: '18px', height: '18px', borderRadius: '50%', background: 'rgba(88,166,255,0.12)', border: '1px solid rgba(88,166,255,0.25)', color: '#58a6ff', fontSize: '9px', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: '1px' }}>
            {index}
          </span>
          <div style={{ fontSize: compact ? '11px' : '12px', color: '#d1d5db', lineHeight: 1.6 }}>{renderInline(line.replace(/^\d+\.\s*/, ''))}</div>
        </div>
      )
      continue
    }

    output.push(
      <div key={key++} style={{ fontSize: compact ? '11px' : '12px', color: '#d1d5db', lineHeight: 1.7, marginBottom: '3px' }}>
        {renderInline(line)}
      </div>
    )
  }

  flushCode()
  return <div>{output}</div>
}
