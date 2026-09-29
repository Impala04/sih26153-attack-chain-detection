'use client'

import { useRef, useState } from 'react'
import type { ChangeEvent, DragEvent } from 'react'
import { AlertTriangle, FileUp, LoaderCircle, X } from 'lucide-react'

type Detection = {
  event_id?: string
  detection_type?: string
  src_ip?: string
  dst_ip?: string
  confidence?: number
  metadata?: Record<string, unknown>
}

type AnalysisResult = {
  analysis_id: string
  input_source: string
  detections: Detection[]
  attack_chains: Record<string, unknown>[]
  forecast: {
    predicted_stage: string
    confidence: number
    probable_next_stages: { stage: string; probability: number }[]
    source: string
  }
  mitre: Record<string, unknown>[]
  explanation: { summary: string; source: string }
  risk: { risk_score: number; severity: string; source: string }
  warnings: string[]
}

const ACCEPTED = ['.csv', '.pcap', '.pcapng']
const API_BASE = 'http://localhost:8000'
const MAX_UPLOAD_BYTES = 100 * 1024 * 1024
const fmt = (value: unknown) =>
  typeof value === 'number' ? value.toFixed(3) : value == null ? '-' : String(value)

const mlRisk = (metadata?: Record<string, unknown>) => {
  if (metadata?.ml_score_error) return 'error'
  const score = metadata?.ml_score as { anomaly_risk?: unknown } | undefined
  return fmt(score?.anomaly_risk)
}

export function AnalysisUpload() {
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
      setError('Choose a .csv, .pcap, or .pcapng file.')
      return
    }
    if (next.size > MAX_UPLOAD_BYTES) {
      setFile(null)
      setError('Files must be 100 MB or smaller.')
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
      const response = await fetch(`${API_BASE}/api/analyze`, { method: 'POST', body })
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
          ? 'Unable to reach the analysis API at localhost:8000.'
          : cause instanceof Error
            ? cause.message
            : 'Analysis failed.'
      )
    } finally {
      setBusy(false)
    }
  }

  const usesMock =
    result && [result.forecast?.source, result.risk?.source, result.explanation?.source].includes('mock')

  return <>
    <div className="page-title">
      <div>
        <span className="eyebrow">INVESTIGATION / ATTACK CHAIN ANALYSIS</span>
        <h1>Analyze a file</h1>
        <p>Run the full detection, correlation and scoring pipeline on a CSV or capture file.</p>
      </div>
      <div className="title-mark"><FileUp size={28}/></div>
    </div>

    <section className="panel pcap-panel">
      <div className="panel-head"><div><h2>Choose a file</h2><span>CSV, PCAP and PCAPNG files - 100 MB maximum</span></div></div>
      <label className="pcap-drop" onDragOver={event => event.preventDefault()} onDrop={onDrop}>
        <input ref={inputRef} type="file" accept=".csv,.pcap,.pcapng" onChange={onChange}/>
        <span className="pcap-upload-icon"><FileUp size={21}/></span>
        <b>Drop a file here or browse</b>
        <small>Accepted formats: .csv, .pcap, .pcapng</small>
      </label>
      {file && <div className="pcap-file"><div><b>{file.name}</b><small>{(file.size / 1024 / 1024).toFixed(2)} MB</small></div><button type="button" className="icon-btn" onClick={clearFile} aria-label="Remove selected file"><X size={17}/></button></div>}
      {error && <div className="pcap-error" role="alert"><AlertTriangle size={17}/><span>{error}</span></div>}
      <div className="pcap-actions"><span>The file is analysed on the API server and is not stored.</span><button type="button" className="pcap-submit" disabled={!file || busy} onClick={analyze}>{busy && <LoaderCircle size={15} className="pcap-spinner"/>}{busy ? 'Analysing...' : 'Analyze'}</button></div>
    </section>

    {result && <>
      <section className="pcap-result-summary">
        <div><span>SOURCE</span><b>{result.input_source}</b></div>
        <div><span>DETECTIONS</span><b>{result.detections.length.toLocaleString()}</b></div>
        <div><span>ATTACK CHAINS</span><b>{result.attack_chains.length.toLocaleString()}</b></div>
        <div><span>RISK</span><b>{fmt(result.risk?.risk_score)} ({result.risk?.severity})</b></div>
        <div><span>FORECAST</span><b>{result.forecast?.predicted_stage} ({fmt(result.forecast?.confidence)})</b></div>
        {usesMock && <div className="pcap-truncated">Risk, forecast and explanation come from placeholder (mock) providers, not a trained model.</div>}
      </section>

      <section className="panel">
        <div className="panel-head"><div><h2>Detections</h2><span>Showing up to the first 100</span></div><em>{result.detections.length} ROWS</em></div>
        {result.detections.length === 0 ? <div className="empty">No detections were raised for this file.</div> : <div className="table-wrap"><table className="pcap-table"><thead><tr><th>Type</th><th>Source</th><th>Destination</th><th>Confidence</th><th>ML risk</th></tr></thead><tbody>{result.detections.slice(0, 100).map((d, index) => <tr key={d.event_id ?? index}><td>{d.detection_type}</td><td className="mono">{d.src_ip}</td><td className="mono">{d.dst_ip}</td><td>{fmt(d.confidence)}</td><td className="mono">{mlRisk(d.metadata)}</td></tr>)}</tbody></table></div>}
      </section>

      {result.attack_chains.length > 0 && <section className="panel">
        <div className="panel-head"><div><h2>Attack chains</h2><span>Raw output from the correlator</span></div><em>{result.attack_chains.length} CHAINS</em></div>
        <pre className="mono" style={{ overflow: 'auto', maxHeight: 360 }}>{JSON.stringify(result.attack_chains, null, 2)}</pre>
      </section>}

      {result.warnings.length > 0 && <div className="pcap-error" role="alert"><AlertTriangle size={17}/><span>{result.warnings.join(' | ')}</span></div>}
    </>}
  </>
}