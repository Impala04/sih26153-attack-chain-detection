'use client'

import { useCallback, useEffect, useState } from 'react'

const API = 'http://localhost:8000'
type Status = { scenario: string; scenario_label: string; running: boolean; interval_seconds: number; cursor: number; total: number; data_path: string; data_source?: string; error?: string | null }
type Host = { id: string; label: string; risk: number; severity: string; window_start: string }

const button: React.CSSProperties = { border: 0, borderRadius: 8, padding: '10px 14px', fontWeight: 700, cursor: 'pointer' }

export function DemoMode() {
  const [status, setStatus] = useState<Status | null>(null)
  const [hosts, setHosts] = useState<Host[]>([])
  const [notice, setNotice] = useState('')
  const refresh = useCallback(async () => {
    try {
      const [state, hostRows] = await Promise.all([fetch(`${API}/api/demo/status`), fetch(`${API}/api/hosts`)])
      setStatus(await state.json())
      if (hostRows.ok) setHosts(await hostRows.json())
    } catch { setNotice('Backend is offline. Start it with: uvicorn app:app --reload --port 8000') }
  }, [])
  useEffect(() => { refresh(); const timer = window.setInterval(refresh, 1000); return () => window.clearInterval(timer) }, [refresh])
  const action = async (path: string, body?: object) => {
    setNotice('')
    try {
      const response = await fetch(`${API}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined })
      const result = await response.json()
      if (!response.ok) throw new Error(result.detail || 'Request failed')
      setStatus(result); await refresh()
    } catch (error) { setNotice(error instanceof Error ? error.message : 'Demo request failed') }
  }
  return <main style={{ maxWidth: 1080, margin: '0 auto', padding: '48px 24px', fontFamily: 'Arial, sans-serif', color: '#e5edf8', background: '#08111f', minHeight: '100vh' }}>
    <p style={{ color: '#5eead4', fontWeight: 700, letterSpacing: 1 }}>CYBERFLUX / PRESENTATION MODE</p>
    <h1 style={{ margin: '0 0 8px' }}>Real scored-traffic replay</h1>
    <p style={{ color: '#9fb0c5', maxWidth: 760 }}>Replay pre-scored CIC-IDS2017 windows as a live security feed. Original window timestamps remain visible; playback speed only controls how quickly the dashboard receives them.</p>
    {notice && <p style={{ background: '#4a1d24', color: '#fecaca', padding: 14, borderRadius: 8 }}>{notice}</p>}
    {status?.error && <div style={{ background: '#44251b', color: '#fed7aa', padding: 16, borderRadius: 8 }}><b>Scored CSV required.</b><br />{status.error}</div>}
    <section style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 10, background: '#111d31', padding: 20, borderRadius: 12, marginTop: 24 }}>
      {['clean', 'ddos', 'infiltration'].map(s => <button key={s} onClick={() => action('/api/demo/settings', { scenario: s })} style={{ ...button, background: status?.scenario === s ? '#14b8a6' : '#26364f', color: 'white' }}>{s === 'ddos' ? 'DDoS burst' : s === 'infiltration' ? 'Subtle infiltration' : 'Clean traffic'}</button>)}
      <span style={{ flex: 1 }} />
      <label>Speed <select value={status?.interval_seconds ?? 1} onChange={e => action('/api/demo/settings', { interval_seconds: Number(e.target.value) })} style={{ marginLeft: 8, padding: 8 }}><option value=".5">2 windows/sec</option><option value="1">1 window/sec</option><option value="2">1 window / 2 sec</option></select></label>
      <button onClick={() => action(status?.running ? '/api/demo/pause' : '/api/demo/start')} style={{ ...button, background: status?.running ? '#f59e0b' : '#22c55e', color: '#06111d' }}>{status?.running ? 'Pause' : 'Start replay'}</button>
      <button onClick={() => action('/api/demo/reset')} style={{ ...button, background: '#334155', color: 'white' }}>Reset</button>
    </section>
    <section style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 14, margin: '20px 0' }}>
      <Card label="Scenario" value={status?.scenario_label || 'Loading'} /><Card label="Replay progress" value={`${status?.cursor || 0} / ${status?.total || 0}`} /><Card label="Status" value={status?.running ? 'PLAYING' : 'PAUSED'} />
    </section>
    <section style={{ background: '#111d31', borderRadius: 12, padding: 20 }}><h2 style={{ marginTop: 0 }}>Latest replayed hosts</h2>{hosts.length === 0 ? <p style={{ color: '#9fb0c5' }}>Choose a scenario and press Start replay.</p> : <table style={{ width: '100%', borderCollapse: 'collapse' }}><thead><tr><th align="left">Source host</th><th align="left">Risk</th><th align="left">Severity</th><th align="left">Original window time</th></tr></thead><tbody>{hosts.sort((a,b) => b.risk - a.risk).map(host => <tr key={host.id}><td style={{ padding: '12px 0' }}>{host.id}</td><td>{Math.round(host.risk * 100)}%</td><td style={{ color: host.severity === 'critical' ? '#fb7185' : host.severity === 'high' ? '#f59e0b' : '#5eead4', fontWeight: 700 }}>{host.severity.toUpperCase()}</td><td>{new Date(host.window_start).toLocaleString()}</td></tr>)}</tbody></table>}</section>
    <p style={{ color: '#64748b', fontSize: 12, marginTop: 20 }}>Data source: {status?.data_source || status?.data_path || 'loading…'}</p>
  </main>
}

export default function DemoPage() { return <DemoMode /> }

function Card({ label, value }: { label: string; value: string }) { return <div style={{ background: '#111d31', borderRadius: 12, padding: 18 }}><small style={{ color: '#9fb0c5' }}>{label}</small><strong style={{ display: 'block', marginTop: 7, fontSize: 20 }}>{value}</strong></div> }
