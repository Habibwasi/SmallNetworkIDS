import React, { useState, useEffect } from 'react';
import { AlertCircle, Activity } from 'lucide-react';
import { AlertsPanel } from './components/AlertsPanel';
import { StatisticsCards } from './components/StatisticsCards';
import { ThreatsTable } from './components/ThreatsTable';
import { apiClient } from './api/client';
import './App.css';

function App() {
  const [health, setHealth] = useState(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const response = await apiClient.getHealth();
        setHealth(response.data);
        setConnected(true);
      } catch (err) {
        setConnected(false);
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-left">
          <h1>SmallNetworkIDS Dashboard</h1>
          <div className={`status ${connected ? 'connected' : 'disconnected'}`}>
            <Activity size={16} />
            {connected ? 'Connected' : 'Disconnected'}
          </div>
        </div>
        <div className="header-right">
          {health && (
            <div className="uptime">Uptime: {health.uptime}</div>
          )}
        </div>
      </header>

      <main className="app-main">
        <section className="dashboard-section">
          <StatisticsCards />
        </section>

        <section className="dashboard-section">
          <div className="section-grid">
            <div className="section-full">
              <AlertsPanel />
            </div>
          </div>
        </section>

        <section className="dashboard-section">
          <ThreatsTable />
        </section>
      </main>

      <footer className="app-footer">
        <p>SmallNetworkIDS © 2026 - Real-time Network Intrusion Detection</p>
      </footer>
    </div>
  );
}

export default App;
