import React, { useState } from 'react'
import axios from 'axios'

export default function PdfCrackTool({ addLog }) {
  const [file, setFile] = useState(null)
  const [method, setMethod] = useState('dictionary')
  const [loading, setLoading] = useState(false)
  const [password, setPassword] = useState('')

  const handleCrack = async () => {
    if (!file) {
      addLog('[ERROR] Please select a PDF file', 'error')
      return
    }

    setLoading(true)
    setPassword('')
    addLog(`[PDF] Attempting to crack ${file.name} using ${method}...`, 'info')

    const formData = new FormData()
    formData.append('file', file)
    formData.append('method', method)

    try {
      const response = await axios.post('/api/pdf/crack', formData)

      if (response.data.success && response.data.password) {
        setPassword(response.data.password)
        addLog(`[SUCCESS] Password found: ${response.data.password}`, 'success')
      } else {
        addLog(`[INFO] Password not found in wordlist`, 'info')
      }
    } catch (error) {
      addLog(`[ERROR] ${error.message}`, 'error')
      console.error(error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="tool-card">
      <div className="card-header">
        <span style={{ fontSize: '24px' }}>🔓</span>
        <h3>PDF Password Cracker</h3>
      </div>

      <div className="input-group">
        <label>Attack Method</label>
        <div style={{ display: 'flex', gap: '12px' }}>
          <button
            className={`btn ${method === 'dictionary' ? 'success' : ''}`}
            onClick={() => setMethod('dictionary')}
            style={{ flex: 1 }}
          >
            📖 Dictionary
          </button>
          <button
            className={`btn ${method === 'brute' ? 'success' : ''}`}
            onClick={() => setMethod('brute')}
            style={{ flex: 1 }}
          >
            ⚡ Brute Force
          </button>
        </div>
      </div>

      <div className="input-group">
        <label>Select Locked PDF</label>
        <div className="upload-zone">
          <input
            type="file"
            accept=".pdf"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
          />
          <p>{file ? `📄 ${file.name}` : '📄 Drop locked PDF here'}</p>
        </div>
      </div>

      <button 
        className="btn error" 
        onClick={handleCrack} 
        disabled={loading || !file}
      >
        {loading ? '⏳ Cracking...' : '🔓 Start Attack'}
      </button>

      {password && (
        <div className="success-box">
          ✅ Password Found: <strong>{password}</strong>
        </div>
      )}
    </div>
  )
}
