import React, { useState } from 'react'
import axios from 'axios'

export default function NetworkScannerTool({ addLog }) {
  const [cidr, setCidr] = useState('192.168.1.0/24')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState([])

  const handleScan = async () => {
    if (!cidr.trim()) {
      addLog('[ERROR] Please enter a CIDR range', 'error')
      return
    }

    setLoading(true)
    addLog(`[NETWORK] Scanning ${cidr}...`, 'info')

    try {
      const response = await axios.post('/api/scan/network', { cidr })
      setResults(response.data.results || [])
      addLog(`[SUCCESS] Found ${response.data.total} active hosts`, 'success')
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
        <span style={{ fontSize: '24px' }}>📡</span>
        <h3>Network Scanner</h3>
      </div>

      <div className="input-group">
        <label>CIDR Range</label>
        <div className="input-wrapper">
          <input
            type="text"
            placeholder="192.168.1.0/24"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
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
          <h4>Active Hosts ({results.length})</h4>
          <div className="results-list">
            {results.map((host, i) => (
              <div key={i} className="result-item">
                {host.ip} 
                <span style={{ color: 'var(--accent)' }}> ({host.hostname})</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
