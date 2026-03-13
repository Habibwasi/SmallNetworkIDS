import React, { useState, useEffect } from 'react';
import { AlertCircle, AlertTriangle, Zap, Activity } from 'lucide-react';
import { apiClient } from '../api/client';
import './AlertsPanel.css';

export function AlertsPanel() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const response = await apiClient.getRecentAlerts(50);
        setAlerts(response.data);
        setError(null);
      } catch (err) {
        setError('Failed to load alerts');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchAlerts();
    const interval = setInterval(fetchAlerts, 3000); // Refresh every 3 seconds
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div className="alerts-panel loading">Loading alerts...</div>;
  }

  const getSeverityClass = (severity) => {
    const severityMap = { Low: 'low', Medium: 'medium', High: 'high', Critical: 'critical' };
    return severityMap[severity] || 'medium';
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'PortScan':
        return <AlertCircle size={16} />;
      case 'DDoSFlood':
        return <Zap size={16} />;
      default:
        return <AlertTriangle size={16} />;
    }
  };

  return (
    <div className="alerts-panel">
      <h2>Recent Alerts</h2>
      {error && <div className="error">{error}</div>}
      <div className="alerts-list">
        {alerts.length === 0 ? (
          <div className="no-alerts">No alerts detected</div>
        ) : (
          alerts.map((alert) => (
            <div key={alert.id} className={`alert-item severity-${getSeverityClass(alert.severity)}`}>
              <div className="alert-icon">{getTypeIcon(alert.type)}</div>
              <div className="alert-content">
                <div className="alert-type">{alert.type}</div>
                <div className="alert-description">{alert.description}</div>
                <div className="alert-ips">
                  {alert.sourceIp} → {alert.destinationIp}
                </div>
              </div>
              <div className="alert-score">{(alert.anomalyScore * 100).toFixed(0)}%</div>
              <div className="alert-time">{new Date(alert.timestamp).toLocaleTimeString()}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
