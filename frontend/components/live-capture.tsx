'use client'

import { useCallback, useEffect, useState } from 'react'

type LiveSnapshot = { running?: boolean; packets_seen?: number; error?: string | null; state?: string; message?: string; target?: { input?: string; mode?: string }; result?: { detections?: unknown[]; attack_chains?: unknown[]; risk?: { risk_score?: number; severity?: string } } | null }
const API_BASE = 'http://127.0.0.1:8000'

export function LiveCapture() {
  const [snapshot, setSnapshot] = useState<LiveSnapshot | null>(null)
  const [error, setError] = useState('')
  const refresh = useCallback(async () => {
    try {
      const [status, analysis] = await Promise.all([fetch(`${API_BASE}/api/live/status`, { cache: 'no-store' }), fetch(`${API_BASE}/api/live/analysis`, { cache: 'no-store' })])
      if (!status.ok || !analysis.ok) throw new Error('Live capture API unavailable.')
      setSnapshot({ ...(await status.json()), ...(await analysis.json()) }); setError('')
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Live capture API unavailable.') }
  }, [])
  useEffect(() => { refresh(); const timer = setInterval(refresh, 3000); return () => clearInterval(timer) }, [refresh])
  const action = async (path: string) => {
    setError('')
    try {
      const response = await fetch(`${API_BASE}${path}`, { method: 'POST' }); const body = await response.json().catch(() => null)
      if (!response.ok) throw new Error(body?.detail || `Live capture request failed (HTTP ${response.status}).`)
      await refresh()
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Live capture request failed.') }
  }
  const result = snapshot?.result
  return <main><h1>Live capture</h1><p>Capture packets from the local interface, process them through CyberFlux detection, then analyze the observed events.</p><p><button type="button" onClick={() => action('/api/live/start')} disabled={!!snapshot?.running}>Start live capture</button>{' '}<button type="button" onClick={() => action('/api/live/start?demo=true')} disabled={!!snapshot?.running}>Run detection-test replay</button>{' '}<button type="button" onClick={() => action('/api/live/stop')} disabled={!snapshot?.running}>Stop and finalize</button>{' '}<button type="button" onClick={refresh}>Refresh</button></p><p><small>The replay is explicitly labeled and processes CyberFlux&apos;s deterministic SYN/port test packets through the same pipeline. It is not live network traffic.</small></p><p>{snapshot?.message ?? 'Waiting for live capture.'}</p>{error ? <p role="alert">{error}</p> : <dl><dt>Status</dt><dd>{snapshot?.running ? 'capturing / replay ready' : snapshot?.state ?? 'idle'}</dd><dt>Data source</dt><dd>{snapshot?.target?.input ?? 'No capture started'}</dd><dt>Packets processed</dt><dd>{snapshot?.packets_seen ?? 0}</dd><dt>Detections</dt><dd>{result?.detections?.length ?? 0}</dd><dt>Attack chains</dt><dd>{result?.attack_chains?.length ?? 0}</dd><dt>Risk</dt><dd>{result?.risk ? `${result.risk.risk_score ?? 0} (${result.risk.severity ?? 'unknown'})` : '—'}</dd>{snapshot?.error && <><dt>Capture error</dt><dd>{snapshot.error}</dd></>}</dl>}</main>
}
