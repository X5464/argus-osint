import React, { useState } from 'react'
import axios from 'axios'

export default function SubdomainTool({ addLog }) {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState([])

  const handleScan = async () => {
    if (!domain.trim()) {
      addLog('[ERROR] Please enter a domain', 'error')
      return
    }

    setLoading(true)
    addLog(`[SUBDOMAIN] Enumerating ${domain}...`, 'info')

    try {
      const response = await axios.post('/api/subdomain', { domain })
      setResults(response.data.results || [])
      addLog(`[SUCCESS] Found ${response.data.total} active subdomains`, 'success')
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
        <span style={{ fontSize: '24px' }}>🌐</span>
        <h3>Subdomain Enumeration</h3>
      </div>

      <div className="input-group">
        <label>Target Domain</label>
        <div className="input-wrapper">
          <input
            type="text"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
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
          <h4>Found Subdomains ({results.length})</h4>
          <div className="results-list">
            {results.map((sub, i) => (
              <div key={i} className="result-item">
                {sub.url} 
                <span style={{ color: 'var(--success)' }}> {sub.status}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
