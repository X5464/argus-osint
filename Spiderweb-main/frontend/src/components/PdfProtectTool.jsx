import React, { useState } from 'react'
import axios from 'axios'

export default function PdfProtectTool({ addLog }) {
  const [file, setFile] = useState(null)
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)

  const handleProtect = async () => {
    if (!file) {
      addLog('[ERROR] Please select a PDF file', 'error')
      return
    }

    if (!password.trim()) {
      addLog('[ERROR] Please enter a password', 'error')
      return
    }

    setLoading(true)
    addLog(`[PDF] Encrypting ${file.name}...`, 'info')

    const formData = new FormData()
    formData.append('file', file)
    formData.append('password', password)

    try {
      const response = await axios.post('/api/pdf/protect', formData, {
        responseType: 'blob'
      })

      const url = window.URL.createObjectURL(response.data)
      const link = document.createElement('a')
      link.href = url
      link.download = `protected_${file.name}`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)

      addLog('[SUCCESS] PDF encrypted and downloaded', 'success')
      setFile(null)
      setPassword('')
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
        <span style={{ fontSize: '24px' }}>🔐</span>
        <h3>PDF Protection</h3>
      </div>

      <div className="input-group">
        <label>Select PDF File</label>
        <div className="upload-zone">
          <input
            type="file"
            accept=".pdf"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
          />
          <p>{file ? `📄 ${file.name}` : '📄 Drop PDF or click to upload'}</p>
        </div>
      </div>

      <div className="input-group">
        <label>Encryption Password</label>
        <input
          type="password"
          placeholder="Enter strong password..."
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>

      <button 
        className="btn success" 
        onClick={handleProtect} 
        disabled={loading || !file}
      >
        {loading ? '⏳ Protecting...' : '🔒 Protect PDF'}
      </button>
    </div>
  )
}
