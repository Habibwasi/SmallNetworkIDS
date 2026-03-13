import React, { useState, useEffect } from 'react';
import { AlertTriangle } from 'lucide-react';
import { apiClient } from '../api/client';
import './ThreatsTable.css';

export function ThreatsTable() {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchThreats = async () => {
      try {
        const response = await apiClient.getTopThreats(15);
        setThreats(response.data);
      } catch (err) {
        console.error('Failed to load threats:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchThreats();
    const interval = setInterval(fetchThreats, 5000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityBadge = (severity) => {
    const levels = ['Low', 'Medium', 'High', 'Critical'];
    return levels[severity] || 'Unknown';
  };

  return (
    <div className="threats-table-container">
      <h2>Top Threat Sources</h2>
      {loading ? (
        <div>Loading threats...</div>
      ) : threats.length === 0 ? (
        <div className="no-threats">No threats detected</div>
      ) : (
        <table className="threats-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Alert Count</th>
              <th>Severity</th>
              <th>Types</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {threats.map((threat) => (
              <tr key={threat.ipAddress} className="threat-row">
                <td className="ip-address">
                  <AlertTriangle size={16} className="threat-icon" />
                  {threat.ipAddress}
                </td>
                <td className="alert-count">{threat.alertCount}</td>
                <td>
                  <span className={`severity-badge severity-${threat.highestSeverity}`}>
                    {getSeverityBadge(threat.highestSeverity)}
                  </span>
                </td>
                <td className="threat-types">{threat.types}</td>
                <td className="last-seen">{new Date(threat.lastSeen).toLocaleTimeString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
