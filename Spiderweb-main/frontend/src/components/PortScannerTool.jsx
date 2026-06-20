import React, { useState } from 'react'
import axios from 'axios'

export default function PortScannerTool({ addLog }) {
  const [ip, setIp] = useState('127.0.0.1')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState([])

  const handleScan = async () => {
    if (!ip.trim()) {
      addLog('[ERROR] Please enter an IP address', 'error')
      return
    }

    setLoading(true)
    addLog(`[PORT_SCAN] Starting scan on ${ip}...`, 'info')

    try {
      const response = await axios.post('/api/scan/ports', { ip })
      setResults(response.data.results || [])
      addLog(`[SUCCESS] Found ${response.data.total_open} open ports`, 'success')
    } catch (error) {
      addLog(`[ERROR] ${error.message}`, 'error')
      console.error(error)
    } finally {
      setLoading(false)
    }
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleScan()
    }
  }

  return (
    <div className="tool-card">
      <div className="card-header">
        <span style={{ fontSize: '24px' }}>🔍</span>
        <h3>Port Scanner</h3>
      </div>

      <div className="input-group">
        <label>Target IP Address</label>
        <div className="input-wrapper">
          <input
            type="text"
            placeholder="192.168.1.1 or 127.0.0.1"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            onKeyPress={handleKeyPress}
          />
          <button 
            className="btn" 
            onClick={handleScan} 
            disabled={loading}
          >
            {loading ? '⏳ Scanning...' : '▶️ Scan'}
          </button>
        </div>
      </div>

      {results.length > 0 && (
        <div className="results-area">
          <h4>Open Ports Found ({results.length})</h4>
          <div className="results-list">
            {results.map((port, i) => (
              <div key={i} className="result-item">
                <strong>Port {port.port}</strong> - {port.service} 
                <span style={{ color: 'var(--success)' }}> {port.status}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
