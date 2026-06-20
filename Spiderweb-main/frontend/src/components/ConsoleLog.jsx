import React from 'react'

export default function ConsoleLog({ logs = [] }) {
  const consoleRef = React.useRef(null)

  React.useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight
    }
  }, [logs])

  return (
    <div className="console-container">
      <div className="console-header">
        <span>📡 OUTPUT_CONSOLE</span>
      </div>
      <div className="console-content" ref={consoleRef}>
        {logs.map((log, i) => (
          <div key={i} className={`log-entry ${log.type}`}>
            <span className="timestamp">[{log.time}]</span>
            <span className="message">{log.message}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
