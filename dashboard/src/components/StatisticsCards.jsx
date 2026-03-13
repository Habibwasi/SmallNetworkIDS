import React, { useState, useEffect } from 'react';
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { apiClient } from '../api/client';
import './StatisticsCards.css';

export function StatisticsCards() {
  const [stats, setStats] = useState(null);
  const [flowStats, setFlowStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [alertRes, flowRes] = await Promise.all([
          apiClient.getAlertStats(),
          apiClient.getFlowStats(),
        ]);
        setStats(alertRes.data);
        setFlowStats(flowRes.data);
      } catch (err) {
        console.error('Failed to load statistics:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div className="stats-container">Loading statistics...</div>;
  }

  return (
    <div className="stats-container">
      <div className="stats-grid">
        <div className="stat-card high">
          <div className="stat-label">Total Alerts</div>
          <div className="stat-value">{stats?.totalAlerts || 0}</div>
          <div className="stat-subtext">Last hour: {stats?.alertsLastHour || 0}</div>
        </div>

        <div className="stat-card warning">
          <div className="stat-label">Active Flows</div>
          <div className="stat-value">{flowStats?.totalFlows || 0}</div>
          <div className="stat-subtext">Unique sources: {flowStats?.uniqueSourceIps || 0}</div>
        </div>

        <div className="stat-card info">
          <div className="stat-label">Traffic Volume</div>
          <div className="stat-value">{(flowStats?.totalBytes / 1_000_000).toFixed(1)} MB</div>
          <div className="stat-subtext">Packets: {flowStats?.totalPackets?.toLocaleString() || 0}</div>
        </div>

        <div className="stat-card danger">
          <div className="stat-label">Port Scans</div>
          <div className="stat-value">{stats?.portScanCount || 0}</div>
          <div className="stat-subtext">DDoS Floods: {stats?.ddosFloodCount || 0}</div>
        </div>
      </div>

      <div className="charts-grid">
        <div className="chart-container">
          <h3>Alert Types Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={[
              { name: 'Port Scans', value: stats?.portScanCount || 0 },
              { name: 'DDoS Floods', value: stats?.ddosFloodCount || 0 },
            ]}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="value" fill="#ef4444" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-container">
          <h3>Traffic Statistics</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={[
              { name: 'Total Flows', value: flowStats?.totalFlows || 0 },
              { name: 'Unique Sources', value: flowStats?.uniqueSourceIps || 0 },
              { name: 'Unique Dests', value: flowStats?.uniqueDestIps || 0 },
            ]}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="value" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
