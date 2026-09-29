'use client'

import { useCallback, useEffect, useState } from 'react'

type LiveSnapshot = {
  running?: boolean
  packets_seen?: number
  error?: string | null
  state?: string
  message?: string
  result?: {
    detections?: unknown[]
    attack_chains?: unknown[]
    risk?: { risk_score?: number; severity?: string }
  } | null
}

const API_BASE = 'http://localhost:8000'

export function LiveCapture() {
  const [snapshot, setSnapshot] = useState<LiveSnapshot | null>(null)
  const [error, setError] = useState('')
  const refresh = useCallback(async () => {
    try {
      const [status, analysis] = await Promise.all([
        fetch(`${API_BASE}/api/live/status`, { cache: 'no-store' }),
        fetch(`${API_BASE}/api/live/analysis`, { cache: 'no-store' }),
      ])
      if (!status.ok || !analysis.ok) throw new Error('Live capture API unavailable.')
      setSnapshot({ ...(await status.json()), ...(await analysis.json()) })
      setError('')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Live capture API unavailable.')
    }
  }, [])
  useEffect(() => {
    refresh()
    const timer = setInterval(refresh, 3000)
    return () => clearInterval(timer)
  }, [refresh])
  const result = snapshot?.result
  return <main><h1>Live capture</h1><p>{snapshot?.message ?? 'Waiting for live capture.'}</p>{error ? <p role="alert">{error}</p> : <dl><dt>Status</dt><dd>{snapshot?.running ? 'capturing' : snapshot?.state ?? 'idle'}</dd><dt>Packets</dt><dd>{snapshot?.packets_seen ?? 0}</dd><dt>Detections</dt><dd>{result?.detections?.length ?? 0}</dd><dt>Attack chains</dt><dd>{result?.attack_chains?.length ?? 0}</dd><dt>Risk</dt><dd>{result?.risk ? `${result.risk.risk_score ?? 0} (${result.risk.severity ?? 'unknown'})` : '—'}</dd>{snapshot?.error && <><dt>Capture error</dt><dd>{snapshot.error}</dd></>}</dl>}</main>
}
