import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const client = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const apiClient = {
  // Alerts
  getRecentAlerts: (limit = 100) => client.get(`/alerts/recent?limit=${limit}`),
  getAlertStats: () => client.get('/alerts/stats'),
  getAlertsByType: (type, limit = 50) => client.get(`/alerts/by-type/${type}?limit=${limit}`),

  // Flows
  getRecentFlows: (limit = 500) => client.get(`/flows/recent?limit=${limit}`),
  getFlowStats: () => client.get('/flows/stats'),

  // Threats
  getTopThreats: (limit = 10) => client.get(`/threats/top?limit=${limit}`),

  // System
  getHealth: () => client.get('/system/health'),
};

export default client;
