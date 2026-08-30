import { useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle2, ChevronRight, FileCheck2, FileText, RotateCcw, ShieldCheck, UploadCloud, X } from 'lucide-react'
import './upload-flow.css'
import './ocr-output.css'
const API = 'http://localhost:8000'

const STEPS = ['Uploading document', 'Extracting text using OCR', 'Analyzing document', 'Checking anomalies', 'Generating verification result']

function formatSize(bytes) {
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`
}

export default function UploadFlow({ onComplete }) {
  const [file, setFile] = useState(null)
  const [type, setType] = useState('Invoice')
  const [drag, setDrag] = useState(false)
  const [activeStep, setActiveStep] = useState(-1)
  const [result, setResult] = useState(null)
  const [backendResult, setBackendResult] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (activeStep < 0 || activeStep >= STEPS.length) return undefined
    const timer = setTimeout(() => setActiveStep(step => step + 1), 900)
    return () => clearTimeout(timer)
  }, [activeStep])

  useEffect(() => {
    if (activeStep !== STEPS.length || !backendResult) return
    const fields = backendResult.extractedData || {}
    const anomalyList = fields.anomalies?.length ? fields.anomalies.map(item => item.message) : ['No anomalies detected']
    setResult({ status: backendResult.status === 'VERIFIED' ? 'Verified' : 'Suspicious', confidence: backendResult.confidence, risk: backendResult.riskLevel, vendor: fields.vendor || 'Not detected', number: fields.documentNumber || 'Not detected', amount: fields.totalAmount ? `₹${Number(fields.totalAmount).toLocaleString('en-IN')}` : 'Not detected', date: fields.date || 'Not detected', anomalies: anomalyList, extractedText: backendResult.extractedText || '[No text detected by OCR]', fileType: backendResult.extractedData?.fileType, characterCount: backendResult.extractedData?.characterCount || 0 })
  }, [activeStep, backendResult, type])

  const selectFile = picked => {
    if (!picked) return
    const allowed = ['application/pdf', 'image/jpeg', 'image/png']
    if (!allowed.includes(picked.type)) { setError('Choose a PDF, JPG, or PNG file.'); return }
    if (picked.size > 25 * 1024 * 1024) { setError('Files must be smaller than 25 MB.'); return }
    setError(''); setFile(picked); setResult(null); setBackendResult(null); setActiveStep(-1)
  }

  const start = async () => {
    if (!file) return
    setError(''); setBackendResult(null); setActiveStep(0)
    const form = new FormData(); form.append('file', file); form.append('document_type', type)
    try { const response = await fetch(`${API}/upload`, { method: 'POST', body: form }); const payload = await response.json().catch(() => ({})); if (!response.ok) throw new Error(payload.detail || 'The document could not be processed.'); setBackendResult(payload) } catch (uploadError) { setActiveStep(-1); setError(uploadError.message || 'Could not connect to the verification service.') }
  }

  const reset = () => { setFile(null); setResult(null); setBackendResult(null); setActiveStep(-1); setError('') }
  const processing = activeStep >= 0 && !result
  return <><div className="page-title"><div><div className="eyebrow">DOCUMENT CENTER</div><h1>Upload a document</h1><p>Add an invoice, purchase order, or contract to begin verification.</p></div></div><div className="upload-layout">{!result && <section className="panel upload-panel"><div className={`dropzone ${drag ? 'dragging' : ''}`} onDragOver={event => { event.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)} onDrop={event => { event.preventDefault(); setDrag(false); selectFile(event.dataTransfer.files[0]) }}><div className="upload-symbol"><UploadCloud size={27} /></div><h3>Drop your document here</h3><p>or <label className="browse">browse files<input type="file" accept=".pdf,.jpg,.jpeg,.png" onChange={event => selectFile(event.target.files?.[0])} /></label></p><small>PDF, JPG or PNG · Max 25 MB</small></div>{file && <div className="file-preview"><span className="file-icon"><FileText size={20} /></span><div><b>{file.name}</b><small>{formatSize(file.size)} · Ready to verify</small></div><button className="icon-btn" onClick={reset} disabled={processing}><X size={17} /></button></div>}{error && <p className="upload-error" role="alert">{error}</p>}{processing && <div className="verification-steps"><div className="processing-header"><span className="processing-pulse" /><div><b>AI verification in progress</b><small>Analyzing {file.name}</small></div><strong>{Math.min(activeStep + 1, STEPS.length)}/{STEPS.length}</strong></div>{STEPS.map((step, index) => <div className={index < activeStep ? 'process-step done' : index === activeStep ? 'process-step current' : 'process-step'} key={step}><span>{index < activeStep ? <CheckCircle2 size={15} /> : index === activeStep ? <span className="step-spinner" /> : <span className="step-number">{index + 1}</span>}</span><b>{step}</b>{index < activeStep && <small>Complete</small>}</div>)}</div>}</section>}{!result && <section className="panel upload-settings"><h3>Document details</h3><p>Help VerifyAI apply the right extraction model.</p><label>Document type<select value={type} onChange={event => setType(event.target.value)} disabled={processing}><option>Invoice</option><option>Purchase Order</option><option>Contract</option></select></label><div className="upload-tip"><ShieldCheck size={17} /><div><b>Secure processing</b><small>Your files are encrypted and never shared outside your workspace.</small></div></div><button className="primary full" disabled={!file || processing} onClick={start}>{processing ? 'Processing document...' : 'Start Verification'} <ChevronRight size={17} /></button></section>}{result && <VerificationResult result={result} file={file} reset={reset} onComplete={onComplete} />}</div></>
}

function VerificationResult({ result, file, reset, onComplete }) {
  return <section className="panel verification-result"><div className="result-banner"><div className={`result-icon ${result.status.toLowerCase()}`} >{result.status === 'Verified' ? <CheckCircle2 size={27} /> : <AlertTriangle size={27} />}</div><div><div className="eyebrow">VERIFICATION COMPLETE</div><h2>{result.status}</h2><p>{file.name} has been analyzed by VerifyAI.</p></div><div className="confidence"><strong>{result.confidence}%</strong><small>confidence</small></div></div><div className="result-grid"><div className="result-section"><h3>Extracted document details</h3>{[['Document type', 'Invoice'], ['Vendor', result.vendor], ['Document number', result.number], ['Document date', result.date], ['Total amount', result.amount]].map(([label, value]) => <div className="field" key={label}><span>{label}</span><b>{value}</b></div>)}</div><div className="result-section"><h3>Risk assessment</h3><div className={`risk-card ${result.risk.toLowerCase()}`}><ShieldCheck size={20} /><div><span>Risk level</span><b>{result.risk} RISK</b></div></div><h3 className="anomaly-heading">Detected anomalies</h3>{result.anomalies.map(anomaly => <div className="anomaly" key={anomaly}>{result.status === 'Verified' ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}<span>{anomaly}</span></div>)}</div></div><div className="ocr-output"><div><h3>Extracted text</h3><small>{result.fileType} · {result.characterCount} characters</small></div><pre>{result.extractedText}</pre></div><div className="result-actions"><button className="secondary" onClick={reset}><RotateCcw size={16} /> Verify another document</button><button className="primary" onClick={() => onComplete?.()}><FileCheck2 size={16} /> View verification history</button></div></section>
}
