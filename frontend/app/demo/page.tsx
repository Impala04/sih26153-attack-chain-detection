'use client'

import { useCallback, useEffect, useState } from 'react'
import { Activity, AlertTriangle, CircleGauge, Info, Pause, Play, RefreshCw, RotateCcw, Shield } from 'lucide-react'

const API = 'http://127.0.0.1:8000'

type Status = {
  scenario: string
  scenario_label: string
  running: boolean
  interval_seconds: number
  cursor: number
  total: number
  data_path: string
  data_source?: string
  error?: string | null
}

type Host = {
  id: string
  label: string
  risk: number
  severity: string
  window_start: string
  status?: string
}

const TOOLTIPS: Record<string, string> = {
  clean: 'Clean Traffic: Streams normal Monday baseline traffic from host_features_v2_scored.csv with low risk scores.',
  ddos: 'DDoS Burst: Streams high-volume DDoS attack windows (Hulk/GoldenEye) showing high risk spikes and alerts.',
  infiltration: 'Subtle Infiltration: Streams multi-stage infiltration attack windows demonstrating progressive threat escalation.'
}

export function DemoMode() {
  const [status, setStatus] = useState<Status | null>(null)
  const [hosts, setHosts] = useState<Host[]>([])
  const [notice, setNotice] = useState('')
  const [hoverScenario, setHoverScenario] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [state, hostRows] = await Promise.all([
        fetch(`${API}/api/demo/status`, { cache: 'no-store' }),
        fetch(`${API}/api/hosts`, { cache: 'no-store' })
      ])
      if (state.ok) setStatus(await state.json())
      if (hostRows.ok) {
        const raw = await hostRows.json()
        setHosts(Array.isArray(raw) ? raw : [])
      }
    } catch {
      setNotice('Backend API is offline. Start the backend with: uvicorn app:app --reload --port 8000')
    }
  }, [])

  useEffect(() => {
    refresh()
    const timer = window.setInterval(refresh, 1000)
    return () => window.clearInterval(timer)
  }, [refresh])

  const action = async (path: string, body?: object) => {
    setNotice('')
    try {
      const response = await fetch(`${API}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined
      })
      const result = await response.json()
      if (!response.ok) throw new Error(result.detail || 'Request failed')
      setStatus(result)
      await refresh()
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Demo request failed')
    }
  }

  return (
    <div className="demo-mode-wrap">
      <div className="page-title">
        <div>
          <span className="eyebrow">CYBERFLUX / PRESENTATION DEMO MODE</span>
          <h1>Real scored-traffic replay</h1>
          <p>Replay pre-scored CIC-IDS2017 dataset windows as a live security feed. Timestamps preserve original capture timing.</p>
        </div>
        <div className="title-mark"><CircleGauge size={28}/></div>
      </div>

      {notice && (
        <div className="pcap-error" role="alert" style={{ marginBottom: 18 }}>
          <AlertTriangle size={18}/>
          <span>{notice}</span>
        </div>
      )}

      {status?.error && (
        <div className="info-panel" style={{ background: '#3b1d1d', borderColor: '#7f2929', marginBottom: 18 }}>
          <AlertTriangle size={20} style={{ color: 'var(--critical)', flex: 'none' }}/>
          <div>
            <b style={{ color: '#fca5a5' }}>Scored CSV Dataset Required</b>
            <p style={{ margin: '4px 0 0', color: '#fecaca' }}>{status.error}</p>
          </div>
        </div>
      )}

      {/* Demo Controls Bar */}
      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Select Demo Scenario &amp; Playback Speed</h2>
            <span>Switch attack scenarios and adjust playback rate in real time</span>
          </div>
          <span className={`badge ${status?.running ? 'low' : 'medium'}`}>
            <i style={{ background: status?.running ? 'var(--safe)' : 'var(--warn)' }}/>
            {status?.running ? 'PLAYBACK ACTIVE' : 'PLAYBACK PAUSED'}
          </span>
        </div>

        <div className="toolbar" style={{ alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {[
              ['clean', 'Clean Traffic'],
              ['ddos', 'DDoS Burst'],
              ['infiltration', 'Subtle Infiltration']
            ].map(([scenKey, scenLabel]) => (
              <button
                key={scenKey}
                onClick={() => action('/api/demo/settings', { scenario: scenKey })}
                onMouseEnter={() => setHoverScenario(scenKey)}
                onMouseLeave={() => setHoverScenario(null)}
                className="pcap-submit"
                style={{
                  background: status?.scenario === scenKey ? 'var(--primary)' : '#102436',
                  color: status?.scenario === scenKey ? '#06111d' : 'var(--foreground)',
                  borderColor: status?.scenario === scenKey ? 'var(--primary)' : 'var(--border)'
                }}
              >
                {scenLabel}
              </button>
            ))}
          </div>

          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12 }}>
            <label style={{ fontSize: 12, color: '#8299ad', display: 'flex', alignItems: 'center', gap: 6 }}>
              Speed:
              <select
                value={status?.interval_seconds ?? 1}
                onChange={e => action('/api/demo/settings', { interval_seconds: Number(e.target.value) })}
                style={{ background: '#091726', color: 'var(--foreground)', border: '1px solid var(--border)', borderRadius: 5, padding: '5px 8px', fontSize: 12 }}
              >
                <option value=".5">2 windows / sec</option>
                <option value="1">1 window / sec</option>
                <option value="2">1 window / 2 sec</option>
              </select>
            </label>

            <button
              onClick={() => action(status?.running ? '/api/demo/pause' : '/api/demo/start')}
              className="pcap-submit"
              style={{ background: status?.running ? 'var(--warn)' : 'var(--safe)', color: '#06111d' }}
            >
              {status?.running ? <><Pause size={14}/> Pause</> : <><Play size={14}/> Start Replay</>}
            </button>

            <button
              onClick={() => action('/api/demo/reset')}
              className="icon-btn"
              style={{ border: '1px solid var(--border)', padding: 7 }}
              aria-label="Reset replay"
            >
              <RotateCcw size={16}/>
            </button>
          </div>
        </div>

        {/* Dynamic Tooltip Explanation */}
        <div className="info-panel" style={{ margin: '14px 0 0', background: '#091829', borderColor: '#1b3854' }}>
          <Info size={18} style={{ color: 'var(--primary)', flex: 'none' }}/>
          <div>
            <b>{status?.scenario_label || 'Scenario Description'}</b>
            <p style={{ margin: '3px 0 0', fontSize: 12 }}>
              {hoverScenario ? TOOLTIPS[hoverScenario] : (status?.scenario ? TOOLTIPS[status.scenario] : 'Select a scenario button to read its data source and attack pattern description.')}
            </p>
          </div>
        </div>
      </section>

      {/* KPI Cards */}
      <div className="metrics-grid" style={{ marginBottom: 18 }}>
        <div className="metric-card">
          <span>ACTIVE SCENARIO</span>
          <b style={{ color: 'var(--primary)' }}>{status?.scenario_label || '—'}</b>
          <small>Selected replay preset</small>
        </div>

        <div className="metric-card">
          <span>PROGRESS</span>
          <b>{status?.cursor ?? 0} / {status?.total ?? 0}</b>
          <small>Replayed windows</small>
        </div>

        <div className="metric-card">
          <span>REPLAY STATE</span>
          <b style={{ color: status?.running ? 'var(--safe)' : 'var(--warn)' }}>
            {status?.running ? 'PLAYING' : 'PAUSED'}
          </b>
          <small>Speed: {status?.interval_seconds ? `${(1 / status.interval_seconds).toFixed(1)} w/s` : '1 w/s'}</small>
        </div>

        <div className="metric-card">
          <span>MONITORED HOSTS</span>
          <b>{hosts.length}</b>
          <small>Active in stream</small>
        </div>
      </div>

      {/* Hosts Table */}
      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Latest Replayed Hosts</h2>
            <span>Live host stream produced by the selected dataset scenario</span>
          </div>
          <em>{hosts.length} HOSTS</em>
        </div>

        {hosts.length === 0 ? (
          <div className="empty">
            <Shield size={24}/>
            <span>No host telemetry available. Choose a scenario and press <b>Start Replay</b>.</span>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="pcap-table">
              <thead>
                <tr>
                  <th>Source Host ID</th>
                  <th>Label</th>
                  <th>Risk Score</th>
                  <th>Severity</th>
                  <th>Original Window Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {hosts.slice().sort((a, b) => b.risk - a.risk).map(host => (
                  <tr key={host.id}>
                    <td className="mono"><b>{host.id}</b></td>
                    <td>{host.label || 'Replay Host'}</td>
                    <td className="mono"><b>{(host.risk > 1 ? Math.round(host.risk) : Math.round(host.risk * 100))}%</b></td>
                    <td>
                      <span className={`badge ${(host.severity || 'low').toLowerCase()}`}>
                        <i/>{(host.severity || 'LOW').toUpperCase()}
                      </span>
                    </td>
                    <td className="mono" style={{ color: '#8ca1b4' }}>
                      {host.window_start ? new Date(host.window_start).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div style={{ marginTop: 14, fontSize: 11, color: '#607990' }}>
          Data source path: <code className="mono">{status?.data_source || status?.data_path || 'Loading...'}</code>
        </div>
      </section>
    </div>
  )
}

export default function DemoPage() {
  return <DemoMode />
}

