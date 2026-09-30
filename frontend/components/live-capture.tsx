'use client'

import { useCallback, useEffect, useState } from 'react'
import { Activity, AlertTriangle, Info, Play, RefreshCw, Shield, StopCircle } from 'lucide-react'

type LiveSnapshot = {
  running?: boolean
  packets_seen?: number
  events_buffered?: number
  error?: string | null
  state?: string
  message?: string
  source?: string
  target?: { input?: string; ips?: string[]; mode?: string } | null
  result?: {
    detections?: { detection_type?: string; src_ip?: string; dst_ip?: string; confidence?: number }[]
    attack_chains?: { chain_id?: string; current_stage?: string; severity?: string }[]
    risk?: { risk_score?: number; severity?: string; recommended_action?: string }
    forecast?: { predicted_stage?: string; confidence?: number; source?: string; forecast_status?: string }
    mitre?: { technique_id?: string; name?: string }[]
  } | null
}

const API_BASE = 'http://127.0.0.1:8000'

const fmtPct = (val?: number) => val != null ? (val > 1 ? `${Math.round(val)}%` : `${Math.round(val * 100)}%`) : '0%'

const getSevColor = (s?: string) => {
  const lower = (s || 'low').toLowerCase()
  return lower === 'critical' ? 'var(--critical)' : lower === 'high' ? 'var(--high)' : lower === 'medium' ? 'var(--warn)' : 'var(--safe)'
}

export function LiveCapture() {
  const [snapshot, setSnapshot] = useState<LiveSnapshot | null>(null)
  const [error, setError] = useState('')
  const [targetInput, setTargetInput] = useState('')
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    try {
      const [statusRes, analysisRes] = await Promise.all([
        fetch(`${API_BASE}/api/live/status`, { cache: 'no-store' }),
        fetch(`${API_BASE}/api/live/analysis`, { cache: 'no-store' })
      ])
      if (!statusRes.ok || !analysisRes.ok) throw new Error('Live sensor API is unavailable.')
      const statusData = await statusRes.json()
      const analysisData = await analysisRes.json()
      setSnapshot({ ...statusData, ...analysisData })
      setError('')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Live sensor API unavailable.')
    }
  }, [])

  useEffect(() => {
    refresh()
    const timer = setInterval(refresh, 2500)
    return () => clearInterval(timer)
  }, [refresh])

  const action = async (endpoint: string) => {
    setError('')
    setBusy(true)
    try {
      const response = await fetch(`${API_BASE}${endpoint}`, { method: 'POST' })
      const body = await response.json().catch(() => null)
      if (!response.ok) throw new Error(body?.detail || `Live capture request failed (HTTP ${response.status}).`)
      await refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Live capture action failed.')
    } finally {
      setBusy(false)
    }
  }

  const startLive = () => {
    const query = targetInput.trim() ? `?target=${encodeURIComponent(targetInput.trim())}` : ''
    action(`/api/live/start${query}`)
  }

  const startDemoReplay = () => {
    action('/api/live/start?demo=true')
  }

  const stopCapture = () => {
    action('/api/live/stop')
  }

  const isDemoMode = snapshot?.target?.mode === 'demo_test_capture' || snapshot?.source === 'demo_test_capture'
  const isRunning = snapshot?.running ?? false
  const result = snapshot?.result

  return (
    <div className="live-capture-wrap">
      {/* Live Controller Panel */}
      <section className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-head">
          <div>
            <h2>Live Sensor &amp; Capture Controller</h2>
            <span>Capture real interface traffic or execute deterministic detection-test replays</span>
          </div>
          <span className={`badge ${isRunning ? (isDemoMode ? 'medium' : 'low') : 'low'}`}>
            <i style={{ background: isRunning ? (isDemoMode ? 'var(--warn)' : 'var(--safe)') : 'var(--muted)' }}/>
            {isRunning ? (isDemoMode ? 'DEMO/TEST REPLAY ACTIVE' : 'LIVE CAPTURE RUNNING') : 'SENSOR IDLE'}
          </span>
        </div>

        <div className="toolbar" style={{ alignItems: 'center', marginBottom: 16 }}>
          <div className="search" style={{ width: 320 }}>
            <Activity size={16}/>
            <input
              value={targetInput}
              onChange={e => setTargetInput(e.target.value)}
              placeholder="Optional target IP or domain..."
              disabled={isRunning}
            />
          </div>

          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginLeft: 'auto' }}>
            <button
              type="button"
              className="pcap-submit"
              style={{ background: isRunning ? '#1e293b' : 'var(--primary)', color: isRunning ? '#64748b' : '#06111d' }}
              disabled={isRunning || busy}
              onClick={startLive}
            >
              <Play size={14}/> Start Live Capture
            </button>

            <button
              type="button"
              className="pcap-submit"
              style={{ background: '#1c3d59', borderColor: '#2b587d', color: '#e0f2ff' }}
              disabled={isRunning || busy}
              onClick={startDemoReplay}
            >
              <Activity size={14}/> Run Detection-Test Replay
            </button>

            <button
              type="button"
              className="pcap-submit"
              style={{ background: isRunning ? 'var(--critical)' : '#1e293b', borderColor: isRunning ? 'var(--critical)' : '#334155', color: 'white' }}
              disabled={!isRunning || busy}
              onClick={stopCapture}
            >
              <StopCircle size={14}/> Stop Capture
            </button>

            <button
              type="button"
              className="icon-btn"
              onClick={refresh}
              aria-label="Refresh status"
              style={{ border: '1px solid var(--border)', padding: 8 }}
            >
              <RefreshCw size={16}/>
            </button>
          </div>
        </div>

        {isDemoMode && (
          <div className="info-panel" style={{ margin: '12px 0 0', background: '#172738', borderColor: '#264463' }}>
            <Info size={18} style={{ color: 'var(--warn)', flex: 'none' }}/>
            <div>
              <b style={{ color: '#fde047' }}>Demo / Test Data Replay Active</b>
              <p style={{ margin: '2px 0 0', fontSize: 11 }}>
                Currently streaming CyberFlux&apos;s deterministic SYN/port test packets through the live pipeline. This data is labeled as <b>demo_test_capture</b> and does not represent live physical interface traffic.
              </p>
            </div>
          </div>
        )}

        {error && (
          <div className="pcap-error" role="alert" style={{ marginTop: 12 }}>
            <AlertTriangle size={17}/>
            <span>{error}</span>
          </div>
        )}
      </section>

      {/* Live Stream Telemetry Metrics */}
      <div className="metrics-grid">
        <div className="metric-card">
          <span>SENSOR STATUS</span>
          <b style={{ color: isRunning ? 'var(--safe)' : 'var(--muted)' }}>
            {isRunning ? 'CAPTURING' : snapshot?.state?.toUpperCase() || 'IDLE'}
          </b>
          <small>{snapshot?.target?.input ? `Target: ${snapshot.target.input}` : 'No target host filter'}</small>
        </div>

        <div className="metric-card">
          <span>PACKETS PROCESSED</span>
          <b>{(snapshot?.packets_seen ?? 0).toLocaleString()}</b>
          <small>Buffered: {snapshot?.events_buffered ?? 0}</small>
        </div>

        <div className="metric-card">
          <span>DETECTIONS</span>
          <b style={{ color: 'var(--primary)' }}>{(result?.detections?.length ?? 0).toLocaleString()}</b>
          <small>Rule &amp; anomaly alerts</small>
        </div>

        <div className="metric-card">
          <span>ATTACK CHAINS</span>
          <b style={{ color: (result?.attack_chains?.length ?? 0) > 0 ? 'var(--critical)' : 'var(--safe)' }}>
            {(result?.attack_chains?.length ?? 0).toLocaleString()}
          </b>
          <small>Correlated scenarios</small>
        </div>

        <div className="metric-card">
          <span>LIVE RISK SCORE</span>
          <b style={{ color: getSevColor(result?.risk?.severity) }}>
            {fmtPct(result?.risk?.risk_score)}
          </b>
          <small>Severity: {(result?.risk?.severity || 'LOW').toUpperCase()}</small>
        </div>

        <div className="metric-card">
          <span>WORLD MODEL</span>
          <b>{result?.forecast?.source?.toUpperCase() || 'OFFLINE'}</b>
          <small>{result?.forecast?.predicted_stage || 'Monitoring'}</small>
        </div>
      </div>

      {/* Live Assessment Panel */}
      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Live Assessment Summary</h2>
            <span>{snapshot?.message || 'Awaiting live traffic...'}</span>
          </div>
          <em>STATUS: {snapshot?.state || 'IDLE'}</em>
        </div>

        {result ? (
          <div className="summary-list">
            <div>
              <span>Observed Detections</span>
              <b>{result.detections?.length || 0} events</b>
            </div>
            <div>
              <span>Correlated Attack Chains</span>
              <b style={{ color: (result.attack_chains?.length || 0) > 0 ? 'var(--critical)' : 'var(--safe)' }}>
                {result.attack_chains?.length || 0} chains
              </b>
            </div>
            <div>
              <span>Current Risk Severity</span>
              <span className={`badge ${(result.risk?.severity || 'low').toLowerCase()}`}>
                <i/>{(result.risk?.severity || 'LOW').toUpperCase()}
              </span>
            </div>
            {result.risk?.recommended_action && (
              <div>
                <span>Recommended Action</span>
                <b>{result.risk.recommended_action}</b>
              </div>
            )}
          </div>
        ) : (
          <div className="empty">
            <Shield size={24}/>
            <span>{snapshot?.message || 'Start live capture or run detection-test replay to inspect real-time traffic analysis.'}</span>
          </div>
        )}
      </section>
    </div>
  )
}

