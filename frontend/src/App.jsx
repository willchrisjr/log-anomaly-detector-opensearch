import { useState, useEffect } from 'react'
import './App.css' // We'll add styles here

function App() {
  const [alerts, setAlerts] = useState([])
  const [sshLogs, setSshLogs] = useState([])
  const [webLogs, setWebLogs] = useState([])
  const [isLoadingAlerts, setIsLoadingAlerts] = useState(true)
  const [isLoadingSsh, setIsLoadingSsh] = useState(true)
  const [isLoadingWeb, setIsLoadingWeb] = useState(true)
  const [error, setError] = useState(null)

  // Define API URLs (assuming API runs on port 5001)
  const alertsApiUrl = 'http://localhost:5001/api/alerts?limit=100'; 
  const sshLogsApiUrl = 'http://localhost:5001/api/raw_logs?log_type=ssh&limit=5';
  const webLogsApiUrl = 'http://localhost:5001/api/raw_logs?log_type=web&limit=5';

  const fetchData = async () => {
    setIsLoadingAlerts(true);
    setIsLoadingSsh(true);
    setIsLoadingWeb(true);
    setError(null);

    try {
      // Fetch all data in parallel
      const [alertsResponse, sshResponse, webResponse] = await Promise.all([
        fetch(alertsApiUrl),
        fetch(sshLogsApiUrl),
        fetch(webLogsApiUrl)
      ]);

      // --- Process Alerts ---
      if (!alertsResponse.ok) throw new Error(`Alerts API Error: ${alertsResponse.status}`);
      const alertsData = await alertsResponse.json();
      setAlerts(alertsData.alerts || []);
      setIsLoadingAlerts(false);

      // --- Process SSH Logs ---
      if (!sshResponse.ok) throw new Error(`SSH Logs API Error: ${sshResponse.status}`);
      const sshData = await sshResponse.json();
      setSshLogs(sshData.logs || []);
      setIsLoadingSsh(false);

      // --- Process Web Logs ---
      if (!webResponse.ok) throw new Error(`Web Logs API Error: ${webResponse.status}`);
      const webData = await webResponse.json();
      setWebLogs(webData.logs || []);
      setIsLoadingWeb(false);

    } catch (err) {
      console.error("Failed to fetch data:", err);
      setError(err.message || "Failed to fetch data. Is the API server running?");
      setIsLoadingAlerts(false);
      setIsLoadingSsh(false);
      setIsLoadingWeb(false);
    }
  };

  // Fetch data when component mounts
  useEffect(() => {
    fetchData();
  }, []); // Empty dependency array means run only once on mount

  return (
    <div className="app-container">
      <h1>Security Event Dashboard</h1>
      <button onClick={fetchData} disabled={isLoadingAlerts || isLoadingSsh || isLoadingWeb}>
        Refresh Data
      </button>

      {error && <p className="error-message">Error: {error}</p>}

      <section className="data-section">
        <h2>Recent Alerts</h2>
        {isLoadingAlerts ? <p>Loading alerts...</p> : (
          <table className="alerts-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Alert Type</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length > 0 ? (
                alerts.map((alert, index) => (
                  <tr key={index}>
                    <td>{alert.alert_timestamp ? new Date(alert.alert_timestamp).toLocaleString() : 'N/A'}</td>
                    <td>{alert.alert_type || 'UNKNOWN'}</td>
                    {/* Display nested details nicely */}
                    <td>
                      {alert.summary || ''}
                      {alert.details && Array.isArray(alert.details) && alert.details.length > 0 && (
                        <ul>
                          {alert.details.map((item, idx) => (
                            <li key={idx}>
                              IP: {item.ip || item.client_ip || 'N/A'}, Count: {item.count || 'N/A'}
                            </li>
                          ))}
                        </ul>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr><td colSpan="3">No alerts found.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </section>

      <section className="data-section">
        <h2>Recent SSH Logs (Raw)</h2>
        {isLoadingSsh ? <p>Loading SSH logs...</p> : (
          <pre className="log-display">
            {sshLogs.length > 0 ? sshLogs.map(log => log.log_original || '').join('\n') : 'No recent SSH logs found.'}
          </pre>
        )}
      </section>

      <section className="data-section">
        <h2>Recent Web Logs (Raw)</h2>
        {isLoadingWeb ? <p>Loading Web logs...</p> : (
          <pre className="log-display">
            {webLogs.length > 0 ? webLogs.map(log => log.log_original || '').join('\n') : 'No recent Web logs found.'}
          </pre>
        )}
      </section>
    </div>
  )
}

export default App
