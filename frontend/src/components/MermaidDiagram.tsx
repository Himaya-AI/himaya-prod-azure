'use client'

import { useEffect, useRef, useState } from 'react'

let _mermaidInitPromise: Promise<typeof import('mermaid').default> | null = null

async function getMermaid() {
  if (_mermaidInitPromise) return _mermaidInitPromise
  _mermaidInitPromise = (async () => {
    const mod = await import('mermaid')
    mod.default.initialize({
      startOnLoad: false,
      theme: 'dark',
      themeVariables: {
        background: '#0e0e14',
        primaryColor: '#1a1a22',
        primaryTextColor: '#e4e4e7',
        primaryBorderColor: '#3a3a48',
        lineColor: '#52525b',
        secondaryColor: '#191925',
        tertiaryColor: '#22222e',
        fontSize: '12px',
      },
      flowchart: { curve: 'basis', useMaxWidth: true, htmlLabels: true },
      securityLevel: 'loose',
    })
    return mod.default
  })()
  return _mermaidInitPromise
}

interface Props {
  chart: string
  className?: string
}

/**
 * Render a Mermaid diagram client-side. Used for DSPM data correlation /
 * blast-radius flows. Re-renders on chart change.
 */
export function MermaidDiagram({ chart, className = '' }: Props) {
  const ref = useRef<HTMLDivElement | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [_, force] = useState(0)

  useEffect(() => {
    let cancelled = false
    let renderId = `mermaid-${Math.random().toString(36).slice(2, 10)}`

    ;(async () => {
      if (!chart || !chart.trim()) return
      try {
        const mermaid = await getMermaid()
        const { svg } = await mermaid.render(renderId, chart)
        if (!cancelled && ref.current) {
          ref.current.innerHTML = svg
          force(x => x + 1)
        }
      } catch (e: unknown) {
        if (cancelled) return
        const msg = e instanceof Error ? e.message : String(e)
        setError(msg)
        if (ref.current) {
          ref.current.innerHTML = ''
        }
      }
    })()

    return () => { cancelled = true }
  }, [chart])

  if (error) {
    return (
      <div className={`text-[11px] text-red-400 font-mono whitespace-pre-wrap ${className}`}>
        Mermaid render error: {error}
      </div>
    )
  }

  return <div ref={ref} className={`overflow-auto ${className}`} />
}

export default MermaidDiagram
