import React, { useState } from 'react'
import './App.css'
import SubdomainTool from './components/SubdomainTool'
import PortScannerTool from './components/PortScannerTool'
import PdfProtectTool from './components/PdfProtectTool'
import PdfCrackTool from './components/PdfCrackTool'
import HashCrackerTool from './components/HashCrackerTool'
import NetworkScannerTool from './components/NetworkScannerTool'
import ConsoleLog from './components/ConsoleLog'

function App() {
  const [activeTool, setActiveTool] = useState('port-scan')
  const [logs, setLogs] = useState([
    { time: new Date().toLocaleTimeString(), message: 'System Ready', type: 'info' },
    { time: new Date().toLocaleTimeString(), message: 'Backend Connected', type: 'success' }
  ])

  const addLog = (message, type = 'info') => {
    const newLog = {
      time: new Date().toLocaleTimeString(),
      message,
      type
    }
    setLogs(prev => [...prev.slice(-19), newLog])
  }

  const tools = [
    { id: 'port-scan', name: 'Port Scanner', desc: 'Scan 1-1024 ports', icon: '🔍' },
    { id: 'subdomain', name: 'Subdomain Enum', desc: 'Find subdomains', icon: '🌐' },
    { id: 'network', name: 'Network Scanner', desc: 'Discover hosts', icon: '📡' },
    { id: 'pdf-protect', name: 'PDF Protect', desc: 'Encrypt PDFs', icon: '🔐' },
    { id: 'pdf-crack', name: 'PDF Cracker', desc: 'Crack passwords', icon: '🔓' },
    { id: 'hash-crack', name: 'Hash Cracker', desc: 'Crack hashes', icon: '🔑' },
  ]

  const renderTool = () => {
    switch (activeTool) {
      case 'port-scan': return <PortScannerTool addLog={addLog} />
      case 'subdomain': return <SubdomainTool addLog={addLog} />
      case 'network': return <NetworkScannerTool addLog={addLog} />
      case 'pdf-protect': return <PdfProtectTool addLog={addLog} />
      case 'pdf-crack': return <PdfCrackTool addLog={addLog} />
      case 'hash-crack': return <HashCrackerTool addLog={addLog} />
      default: return null
    }
  }

  return (
    <div className="app-container">
      <div className="sidebar">
        <div className="sidebar-header">
          <div className="logo">😈</div>
          <div className="brand">
            <h1>SpiderWeb</h1>
            <p>v2.0 Pro</p>
          </div>
        </div>

        <nav className="nav-menu">
          {tools.map(tool => (
            <button
              key={tool.id}
              className={`nav-item ${activeTool === tool.id ? 'active' : ''}`}
              onClick={() => setActiveTool(tool.id)}
            >
              <span className="nav-icon">{tool.icon}</span>
              <div className="nav-text">
                <div className="nav-title">{tool.name}</div>
                <div className="nav-desc">{tool.desc}</div>
              </div>
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="system-info">
            <span>⚙️ System Online</span>
          </div>
        </div>
      </div>

      <div className="main-content">
        <div className="top-bar">
          <h2>/ {tools.find(t => t.id === activeTool)?.name}</h2>
          <div className="status-badge">🟢 ACTIVE</div>
        </div>

        <div className="tool-area">
          {renderTool()}
        </div>

        <div className="console-area">
          <ConsoleLog logs={logs} />
        </div>
      </div>
    </div>
  )
}

export default App
