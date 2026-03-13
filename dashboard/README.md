# Dashboard Setup

## Quick Start

### Backend API

```bash
cd src/SmallNetworkIDS.Api
dotnet run
```

API will be available at `http://localhost:5000`

### Frontend Dashboard

```bash
cd dashboard
npm install
npm start
```

Dashboard will open at `http://localhost:3000`

## Features

- **Real-time Alerts**: Live feed of detected security threats
- **Network Statistics**: Flow counts, traffic volume, unique IPs
- **Anomaly Detection**: Charts showing alert distributions and traffic patterns
- **Top Threats**: Table of most aggressive source IPs with severity levels
- **System Health**: Connection status and uptime tracking

## API Endpoints

- `GET /api/alerts/recent?limit=100` - Recent alerts
- `GET /api/alerts/stats` - Alert statistics
- `GET /api/flows/recent?limit=500` - Recent flows
- `GET /api/flows/stats` - Network statistics
- `GET /api/threats/top?limit=10` - Top threat sources
- `GET /api/system/health` - System health status

## Environment Variables

### Frontend (.env)

```
REACT_APP_API_URL=http://localhost:5000/api
```

## Tech Stack

- **Backend**: ASP.NET Core 10.0, C#
- **Frontend**: React 18, Recharts, Lucide Icons
- **Styling**: CSS3 with gradients and backdrop filters
