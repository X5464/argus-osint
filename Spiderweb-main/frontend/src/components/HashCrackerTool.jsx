import React, { useState } from 'react'
import axios from 'axios'

export default function HashCrackerTool({ addLog }) {
  const [hash, setHash] = useState('')
  const [hashType, setHashType] = useState('md5')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState('')

  const handleCrack = async () => {
    if (!hash.trim()) {
      addLog('[ERROR] Please enter a hash value', 'error')
      return
    }

    setLoading(true)
    setResult('')
    addLog(`[HASH] Attempting to crack ${hashType.toUpperCase()} hash...`, 'info')

    try {
      const response = await axios.post('/api/crack/hash', {
        hash: hash.trim(),
        type: hashType
      })

      if (response.data.success && response.data.password) {
        setResult(response.data.password)
        addLog(`[SUCCESS] Hash cracked: ${response.data.password}`, 'success')
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

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleCrack()
    }
  }

  return (
    <div className="tool-card">
      <div className="card-header">
        <span style={{ fontSize: '24px' }}>🔑</span>
        <h3>Hash Cracker</h3>
      </div>

      <div className="input-group">
        <label>Hash Type</label>
        <select 
          value={hashType} 
          onChange={(e) => setHashType(e.target.value)}
        >
          <option value="md5">MD5</option>
          <option value="sha1">SHA1</option>
          <option value="sha256">SHA256</option>
        </select>
      </div>

      <div className="input-group">
        <label>Hash Value</label>
        <textarea
          placeholder="Paste hash here..."
          value={hash}
          onChange={(e) => setHash(e.target.value)}
          onKeyPress={handleKeyPress}
          rows="4"
          style={{ fontFamily: 'monospace', fontSize: '13px' }}
        />
      </div>

      <button 
        className="btn warning" 
        onClick={handleCrack} 
        disabled={loading || !hash}
      >
        {loading ? '⏳ Cracking...' : '🔨 Crack Hash'}
      </button>

      {result && (
        <div className="success-box">
          ✅ Password Found: <strong>{result}</strong>
        </div>
      )}
    </div>
  )
}
