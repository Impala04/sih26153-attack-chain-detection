'use client'

import { useRef, useState } from 'react'
import type { ChangeEvent, DragEvent } from 'react'
import { AlertTriangle, CheckCircle2, ChevronRight, FileUp, Info, LoaderCircle, Shield, Sparkles, X } from 'lucide-react'
import { PcapUpload } from './pcap-upload'

type Detection = {
  event_id?: string
  detection_type?: string
  src_ip?: string
  dst_ip?: string
  confidence?: number
  timestamp?: number
  metadata?: Record<string, unknown>
}

type AttackChain = {
  chain_id?: string
  src_ip?: string
  dst_ip?: string
  current_stage?: string
  severity?: string
  detections?: Detection[]
  first_seen?: number
  last_seen?: number
  [key: string]: unknown
}

type MitreMapping = {
  technique_id?: string
  name?: string
  tactic?: string
  confidence?: number
  description?: string
}

type FutureProb = {
  step: number
  window_start?: string
  probability: number
  threshold: number
  predicted_attack: boolean
}

type Forecast = {
  predicted_stage?: string
  confidence?: number
  probable_next_stages?: { stage: string; probability: number }[]
  source?: string
  forecast_status?: string
  probability_note?: string
  future_attack_probabilities?: FutureProb[]
  warning?: string
}

type RiskInfo = {
  risk_score?: number
  severity?: string
  source?: string
  risk_level?: string
  confidence?: number
  uncertainty?: number
  contributing_factors?: { factor?: string; weight?: number; contribution?: number }[]
  recommended_action?: string
  signals_used?: string[]
  signals_missing?: string[]
}

type AnalysisResult = {
  analysis_id: string
  input_source: string
  detections: Detection[]
  attack_chains: AttackChain[]
  forecast?: Forecast
  mitre?: MitreMapping[]
  explanation?: { summary?: string; source?: string }
  risk?: RiskInfo
  warnings: string[]
}

const ACCEPTED = ['.csv', '.pcap', '.pcapng']
const API_BASE = 'http://127.0.0.1:8000'
const MAX_UPLOAD_BYTES = 200 * 1024 * 1024

const fmt = (value: unknown) =>
  typeof value === 'number' ? value.toFixed(3) : value == null ? '-' : String(value)

const pct = (value: unknown) =>
  typeof value === 'number' ? (value > 1 ? `${Math.round(value)}%` : `${Math.round(value * 100)}%`) : '-'

const sevColor = (s?: string) => {
  const lower = (s || 'low').toLowerCase()
  return lower === 'critical' ? 'var(--critical)' : lower === 'high' ? 'var(--high)' : lower === 'medium' ? 'var(--warn)' : 'var(--safe)'
}

export function AnalysisUpload() {
  const [activeTab, setActiveTab] = useState<'analyze' | 'preview'>('analyze')
  const inputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  function chooseFile(next: File | undefined) {
    if (!next || busy) return
    setResult(null)
    setError('')
    const extension = `.${next.name.split('.').pop()?.toLowerCase()}`
    if (!ACCEPTED.includes(extension)) {
      setFile(null)
      setError('Invalid file format. Please upload a .csv, .pcap, or .pcapng file.')
      return
    }
    if (next.size > MAX_UPLOAD_BYTES) {
      setFile(null)
      setError('File size exceeds the 200 MB maximum limit.')
      return
    }
    setFile(next)
  }

  function onChange(event: ChangeEvent<HTMLInputElement>) {
    chooseFile(event.target.files?.[0])
  }

  function onDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault()
    chooseFile(event.dataTransfer.files[0])
  }

  function clearFile() {
    setFile(null)
    setResult(null)
    setError('')
    if (inputRef.current) inputRef.current.value = ''
  }

  async function analyze() {
    if (!file) return
    setBusy(true)
    setError('')
    setResult(null)
    const body = new FormData()
    body.append('file', file)
    try {
      const controller = new AbortController()
      const timer = window.setTimeout(() => controller.abort(), 60_000)
      const response = await fetch(`${API_BASE}/api/analyze`, { method: 'POST', body, signal: controller.signal })
      window.clearTimeout(timer)
      const payload = await response.json().catch(() => null)
      if (!response.ok) {
        throw new Error(
          typeof payload?.detail === 'string' ? payload.detail : `Analysis failed (HTTP ${response.status}).`
        )
      }
      setResult(payload as AnalysisResult)
    } catch (cause) {
      setError(
        cause instanceof TypeError
          ? 'Analysis timed out or the backend API at localhost:8000 is unavailable.'
          : cause instanceof Error
            ? cause.message
            : 'Analysis failed.'
      )
    } finally {
      setBusy(false)
    }
  }

  const isRealModel = result?.forecast?.source === 'real'
  const isMockModel = result?.forecast?.source === 'mock'

  return <>
    <div className="page-title">
      <div>
        <span className="eyebrow">INVESTIGATION / ATTACK CHAIN DETECTION</span>
        <h1>Attack chain analysis</h1>
        <p>Run end-to-end detection, correlation, MITRE mapping, and World Model forecasting on security logs or network packet captures.</p>
      </div>
      <div className="title-mark"><FileUp size={28} /></div>
    </div>

    <div className="toolbar" style={{ marginBottom: 20 }}>
      <div className="filters">
        <button className={activeTab === 'analyze' ? 'selected' : ''} onClick={() => setActiveTab('analyze')}>
          Full Attack-Chain Analysis
        </button>
        <button className={activeTab === 'preview' ? 'selected' : ''} onClick={() => setActiveTab('preview')}>
          PCAP Packet Preview
        </button>
      </div>
    </div>

    {activeTab === 'preview' ? (
      <PcapUpload />
    ) : (
      <>
        <section className="panel pcap-panel">
          <div className="panel-head">
            <div>
              <h2>Upload traffic source</h2>
              <span>CSV, PCAP, and PCAPNG files up to 200 MB</span>
            </div>
            <em>CYBERFLUX ENGINE</em>
          </div>

          <label className="pcap-drop" onDragOver={event => event.preventDefault()} onDrop={onDrop}>
            <input ref={inputRef} type="file" accept=".csv,.pcap,.pcapng" onChange={onChange} />
            <span className="pcap-upload-icon"><FileUp size={21} /></span>
            <b>Drop a file here or browse</b>
            <small>Accepted formats: .csv, .pcap, .pcapng (Max 200 MB)</small>
          </label>

          {file && (
            <div className="pcap-file">
              <div>
                <b>{file.name}</b>
                <small>{(file.size / 1024 / 1024).toFixed(2)} MB</small>
              </div>
              <button type="button" className="icon-btn" onClick={clearFile} aria-label="Remove file">
                <X size={17} />
              </button>
            </div>
          )}

          {error && (
            <div className="pcap-error" role="alert">
              <AlertTriangle size={17} />
              <span>{error}</span>
            </div>
          )}

          <div className="pcap-actions">
            <span>Files are processed in memory by the local CyberFlux backend and are not stored.</span>
            <button type="button" className="pcap-submit" disabled={!file || busy} onClick={analyze}>
              {busy && <LoaderCircle size={15} className="pcap-spinner" />}
              {busy ? 'Processing & Analyzing...' : 'Run Analysis'}
            </button>
          </div>
        </section>

        {result && (
          <>
            <section className="pcap-result-summary" style={{ flexWrap: 'wrap' }}>
              <div><span>INPUT SOURCE</span><b>{result.input_source}</b></div>
              <div><span>DETECTIONS</span><b style={{ color: 'var(--primary)' }}>{result.detections.length.toLocaleString()}</b></div>
              <div><span>ATTACK CHAINS</span><b style={{ color: result.attack_chains.length > 0 ? 'var(--critical)' : 'var(--safe)' }}>{result.attack_chains.length.toLocaleString()}</b></div>
              <div><span>RISK SCORE</span><b style={{ color: sevColor(result.risk?.severity) }}>{pct(result.risk?.risk_score)} ({result.risk?.severity?.toUpperCase() || 'LOW'})</b></div>
              <div><span>WORLD MODEL</span><b>{isRealModel ? 'Real GRU Forecast' : isMockModel ? 'Mock Forecaster' : 'Offline'}</b></div>
            </section>

            {/* Risk Engine & Recommendations */}
            {result.risk && (
              <div className="grid-two">
                <section className="panel">
                  <div className="panel-head">
                    <div><h2>CyberFlux Risk Engine</h2><span>Aggregated risk evaluation</span></div>
                    <em>{result.risk.source?.toUpperCase()} ENGINE</em>
                  </div>
                  <div className="risk-gauge" style={{ marginBottom: 16 }}>
                    <div className={`gauge ${(result.risk.severity || 'low').toLowerCase()}`} style={{ '--score': `${result.risk.risk_score != null ? (result.risk.risk_score > 1 ? result.risk.risk_score : result.risk.risk_score * 100) : 0}%` } as any}>
                      <b>{pct(result.risk.risk_score)}</b>
                      <span>SCORE</span>
                    </div>
                    <div className="summary-list">
                      <div><span>Risk Level</span><b style={{ color: sevColor(result.risk.severity) }}>{result.risk.severity?.toUpperCase() || 'LOW'}</b></div>
                      {result.risk.confidence != null && <div><span>Model Confidence</span><b>{pct(result.risk.confidence)}</b></div>}
                      {result.risk.uncertainty != null && <div><span>Uncertainty</span><b>{pct(result.risk.uncertainty)}</b></div>}
                    </div>
                  </div>
                  {result.risk.recommended_action && (
                    <div className="info-panel" style={{ margin: 0 }}>
                      <Shield size={20} style={{ color: 'var(--primary)', flex: 'none' }} />
                      <div>
                        <b>Recommended Action</b>
                        <p>{result.risk.recommended_action}</p>
                      </div>
                    </div>
                  )}
                </section>

                <section className="panel">
                  <div className="panel-head">
                    <div><h2>Contributing Risk Factors</h2><span>Top signals influencing risk score</span></div>
                    <em>SIGNALS</em>
                  </div>
                  {result.risk.contributing_factors?.length ? (
                    <div className="features">
                      {result.risk.contributing_factors.map((f, i) => (
                        <div className="feature" key={i}>
                          <div className="feature-main">
                            <div>
                              <b>{f.factor}</b>
                              <span className="critical-text">+{fmt(f.contribution ?? f.weight ?? 0.2)}</span>
                            </div>
                            <div className="impact-track">
                              <i className="critical" style={{ width: `${Math.min(100, Math.abs(f.contribution ?? f.weight ?? 0.2) * 100)}%` }} />
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="empty">No specific elevated risk factors flagged.</div>
                  )}
                </section>
              </div>
            )}

            {/* World Model Forecast */}
            <section className="panel">
              <div className="panel-head">
                <div>
                  <h2>World Model Attack Forecast</h2>
                  <span>Deep learning future attack probability trajectory (`models/world_model/world_model.pt`)</span>
                </div>
                <em>{result.forecast?.source?.toUpperCase() || 'REAL'} FORECAST</em>
              </div>

              <div className="pcap-result-summary" style={{ marginBottom: 16 }}>
                <div><span>STATUS</span><b>{result.forecast?.forecast_status || 'Ready'}</b></div>
                <div><span>PREDICTED STAGE</span><b>{result.forecast?.predicted_stage || 'N/A'}</b></div>
                <div><span>MAX ATTACK PROBABILITY</span><b>{fmt(result.forecast?.confidence)}</b></div>
              </div>

              {result.forecast?.probability_note && (
                <p style={{ color: '#8ca1b4', fontSize: 12, marginBottom: 16 }}>{result.forecast.probability_note}</p>
              )}

              {result.forecast?.future_attack_probabilities?.length ? (
                <div className="table-wrap">
                  <table className="pcap-table">
                    <thead>
                      <tr>
                        <th>Future Step</th>
                        <th>Attack Probability</th>
                        <th>Alert Threshold</th>
                        <th>Prediction State</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.forecast.future_attack_probabilities.map(item => (
                        <tr key={item.step}>
                          <td><b>Step +{item.step}</b></td>
                          <td className="mono" style={{ color: item.predicted_attack ? 'var(--critical)' : 'var(--safe)' }}>
                            {pct(item.probability)} ({item.probability.toFixed(4)})
                          </td>
                          <td className="mono">{fmt(item.threshold)}</td>
                          <td>
                            <span className={`badge ${item.predicted_attack ? 'critical' : 'low'}`}>
                              <i />{item.predicted_attack ? 'ATTACK LIKELY' : 'NORMAL'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty">
                  {result.forecast?.warning || 'World Model requires consecutive time windows to compute future attack trajectories.'}
                </div>
              )}
            </section>

            {/* Attack Chains Section */}
            {result.attack_chains.length > 0 && (
              <section className="panel">
                <div className="panel-head">
                  <div><h2>Correlated Attack Chains</h2><span>Identified multi-stage attack scenarios</span></div>
                  <em>{result.attack_chains.length} CHAINS</em>
                </div>
                <div className="table-wrap">
                  <table className="pcap-table">
                    <thead>
                      <tr>
                        <th>Chain ID</th>
                        <th>Source Host</th>
                        <th>Destination Host</th>
                        <th>Current Stage</th>
                        <th>Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.attack_chains.map((chain, index) => (
                        <tr key={chain.chain_id || index}>
                          <td className="mono"><b>{chain.chain_id || `CHAIN-${index + 1}`}</b></td>
                          <td className="mono">{chain.src_ip || '—'}</td>
                          <td className="mono">{chain.dst_ip || '—'}</td>
                          <td>
                            <span className="pcap-protocol">{chain.current_stage || 'Reconnaissance'}</span>
                          </td>
                          <td>
                            <span className={`badge ${(chain.severity || 'high').toLowerCase()}`}>
                              <i />{chain.severity?.toUpperCase() || 'HIGH'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            )}

            {/* MITRE ATT&CK Mapping */}
            <section className="panel">
              <div className="panel-head">
                <div><h2>MITRE ATT&amp;CK Mapping</h2><span>Techniques mapped from observed events</span></div>
                <em>{result.mitre?.length || 0} MAPPINGS</em>
              </div>
              {result.mitre?.length ? (
                <div className="table-wrap">
                  <table className="pcap-table">
                    <thead>
                      <tr>
                        <th>Technique ID</th>
                        <th>Name</th>
                        <th>Tactic</th>
                        <th>Confidence</th>
                        <th>Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.mitre.map((m, i) => (
                        <tr key={m.technique_id || i}>
                          <td className="mono" style={{ color: 'var(--primary)' }}><b>{m.technique_id}</b></td>
                          <td><b>{m.name}</b></td>
                          <td><span className="pcap-protocol">{m.tactic}</span></td>
                          <td className="mono">{pct(m.confidence)}</td>
                          <td style={{ color: '#8ca1b4', fontSize: 11 }}>{m.description || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty">No MITRE ATT&amp;CK techniques mapped for this capture window.</div>
              )}
            </section>

            {/* Detections List */}
            <section className="panel">
              <div className="panel-head">
                <div><h2>Detection Events</h2><span>Individual alerts produced by rule &amp; ML engines</span></div>
                <em>{result.detections.length} EVENTS</em>
              </div>
              {result.detections.length === 0 ? (
                <div className="empty">No detection events were triggered for this file.</div>
              ) : (
                <div className="table-wrap">
                  <table className="pcap-table">
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Source IP</th>
                        <th>Destination IP</th>
                        <th>Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.detections.slice(0, 100).map((d, index) => (
                        <tr key={d.event_id || index}>
                          <td><b>{d.detection_type}</b></td>
                          <td className="mono">{d.src_ip || '—'}</td>
                          <td className="mono">{d.dst_ip || '—'}</td>
                          <td className="mono">{pct(d.confidence)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            {/* Warnings */}
            {result.warnings.length > 0 && (
              <div className="pcap-error" role="alert">
                <AlertTriangle size={17} />
                <span>{result.warnings.join(' | ')}</span>
              </div>
            )}
          </>
        )}
      </>
    )}
  </>
}

