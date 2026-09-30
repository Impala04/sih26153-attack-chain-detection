'use client'

import { useRef, useState } from 'react'
import type { ChangeEvent, DragEvent } from 'react'
import { AlertTriangle, FileUp, LoaderCircle, X } from 'lucide-react'

type Packet = {
  timestamp: number
  src_ip: string
  dst_ip: string
  src_port: number | null
  dst_port: number | null
  protocol: string
  packet_length: number
  tcp_flags: string | null
}

type ParseResult = {
  filename: string
  packet_count: number
  truncated: boolean
  packets: Packet[]
}

const ACCEPTED = ['.pcap', '.pcapng', '.cap']
const API_BASE = 'http://127.0.0.1:8000'
const MAX_UPLOAD_BYTES = 100 * 1024 * 1024
const formatPort = (ip: string, port: number | null) => port === null ? ip : `${ip}:${port}`

export function PcapUpload() {
  const inputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<ParseResult | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  function chooseFile(next: File | undefined) {
    if (!next || busy) return
    setResult(null)
    setError('')
    const extension = `.${next.name.split('.').pop()?.toLowerCase()}`
    if (!ACCEPTED.includes(extension)) {
      setFile(null)
      setError('Choose a .pcap, .pcapng, or .cap file.')
      return
    }
    if (next.size > MAX_UPLOAD_BYTES) {
      setFile(null)
      setError('Capture files must be 100 MB or smaller.')
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

  async function parseCapture() {
    if (!file) return
    setBusy(true)
    setError('')
    setResult(null)
    const body = new FormData()
    body.append('file', file)
    try {
      const response = await fetch(`${API_BASE}/api/pcap/parse`, { method: 'POST', body })
      const payload = await response.json()
      if (!response.ok) throw new Error(payload.detail || 'Unable to parse this capture.')
      setResult(payload as ParseResult)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to reach the PCAP parser at localhost:8000.')
    } finally {
      setBusy(false)
    }
  }

  return <>
    <div className="page-title">
      <div><span className="eyebrow">INVESTIGATION / PACKET CAPTURE</span><h1>PCAP preview</h1><p>Inspect IPv4 TCP, UDP, and ICMP packet metadata before sending a capture to full analysis.</p></div>
      <div className="title-mark"><FileUp size={28}/></div>
    </div>

    <section className="panel pcap-panel">
      <div className="panel-head"><div><h2>Choose a capture</h2><span>PCAP and PCAPNG files · 100 MB maximum</span></div><em>SCAPY</em></div>
      <label className="pcap-drop" onDragOver={event => event.preventDefault()} onDrop={onDrop}>
        <input ref={inputRef} type="file" accept=".pcap,.pcapng,.cap" onChange={onChange}/>
        <span className="pcap-upload-icon"><FileUp size={21}/></span>
        <b>Drop a capture here or browse</b>
        <small>Accepted formats: .pcap, .pcapng, .cap</small>
      </label>
      {file && <div className="pcap-file"><div><b>{file.name}</b><small>{(file.size / 1024 / 1024).toFixed(2)} MB</small></div><button type="button" className="icon-btn" onClick={clearFile} aria-label="Remove selected file"><X size={17}/></button></div>}
      {error && <div className="pcap-error" role="alert"><AlertTriangle size={17}/><span>{error}</span></div>}
      <div className="pcap-actions"><span>This preview does not create detections. Use <b>Analyze CSV / PCAP</b> for the real detection, risk, forecast, and MITRE pipeline.</span><button type="button" className="pcap-submit" disabled={!file || busy} onClick={parseCapture}>{busy && <LoaderCircle size={15} className="pcap-spinner"/>}{busy ? 'Parsing…' : 'Parse preview'}</button></div>
    </section>

    {result && <>
      <section className="pcap-result-summary">
        <div><span>CAPTURE</span><b>{result.filename}</b></div>
        <div><span>PARSED PACKETS</span><b>{result.packet_count.toLocaleString()}</b></div>
        {result.truncated && <div className="pcap-truncated">Response limited to the first 10,000 packets.</div>}
      </section>
      <section className="panel">
        <div className="panel-head"><div><h2>Parsed packet preview</h2><span>Showing up to the first 100 packets</span></div><em>{result.packets.length} ROWS</em></div>
        {result.packet_count === 0 ? <div className="empty">No supported IPv4 TCP, UDP, or ICMP packets were found.</div> : <div className="table-wrap"><table className="pcap-table"><thead><tr><th>Timestamp</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>TCP flags</th></tr></thead><tbody>{result.packets.slice(0, 100).map((packet, index) => <tr key={`${packet.timestamp}-${index}`}><td className="mono">{new Date(packet.timestamp * 1000).toISOString()}</td><td className="mono">{formatPort(packet.src_ip, packet.src_port)}</td><td className="mono">{formatPort(packet.dst_ip, packet.dst_port)}</td><td><span className="pcap-protocol">{packet.protocol}</span></td><td>{packet.packet_length} B</td><td className="mono">{packet.tcp_flags || '—'}</td></tr>)}</tbody></table></div>}
      </section>
    </>}
  </>
}
