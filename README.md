# SmallNetworkIDS

A lightweight network intrusion detection system (IDS) that uses machine learning to detect port scans and DDoS-like floods.

## Features

- **Real-time packet capture** using SharpPcap/Npcap
- **ML-based anomaly detection** using ONNX Runtime with Isolation Forest
- **Rule-based fallback** when no ML model is available
- **Flow-based analysis** tracking connections by 5-tuple
- **Data export** to CSV/JSON for training and analysis

## Requirements

- .NET 10.0+
- [Npcap](https://npcap.com/) (install with "WinPcap API-compatible Mode")
- Python 3.10+ (for model training)

## Quick Start

```bash
# Build and run IDS core
cd src/SmallNetworkIDS.Core
dotnet run

# Select network interface and optional BPF filter
# Press Ctrl+C to stop and export data
```

## Dashboard & Web API

A modern web-based dashboard for real-time monitoring of the IDS with REST API backend.

### Running the API Server

```bash
cd src/SmallNetworkIDS.Api
dotnet run
```

API runs at `http://localhost:5000` with Swagger UI at `/swagger/ui`

### Running the Dashboard

```bash
cd dashboard
npm install
npm start
```

Dashboard opens at `http://localhost:3000`

### Dashboard Features

- 📊 **Real-time Alerts**: Live feed of detected threats with severity levels
- 📈 **Network Statistics**: Flow counts, traffic volume, and unique IPs
- 🎯 **Top Threats**: Ranking of most aggressive source IPs
- 📉 **Anomaly Charts**: Distribution of alert types and network patterns
- 🏥 **System Health**: Connection status and uptime monitoring

### API Endpoints

**Alerts**
- `GET /api/alerts/recent` - Recent alerts (limit query param)
- `GET /api/alerts/stats` - Alert statistics
- `GET /api/alerts/by-type/{type}` - Filter by alert type

**Flows**
- `GET /api/flows/recent` - Recent network flows
- `GET /api/flows/stats` - Network statistics

**Threats**
- `GET /api/threats/top` - Top threat sources

**System**
- `GET /api/system/health` - Health and uptime

## Testing

The project includes a comprehensive test suite with 50 unit tests covering all core components.

### Running Tests

```bash
# Run all tests
dotnet test

# Run with verbose output
dotnet test -v detailed

# Run specific test class
dotnet test --filter "ClassName=FeatureExtractorTests"
```

### Test Coverage

- **Model Tests** (10): NetworkFlow, FeatureVector, AnomalyResult
- **Service Tests** (29): FeatureExtractor, MlInferenceEngine, AlertManager, DataExporter
- **Integration Tests** (11): End-to-end detection pipelines, port scan detection, data export

Test project location: `src/SmallNetworkIDS.Core.Tests/`

## Training a Model

1. Run the IDS to collect training data (exported on exit)
2. Install Python dependencies:
   ```bash
   pip install scikit-learn skl2onnx pandas numpy
   ```
3. Train the model:
   ```bash
   python scripts/train_model.py training_data.csv
   ```
4. Copy `model.onnx` to the working directory

## Project Structure

```
SmallNetworkIDS/
├── src/SmallNetworkIDS.Core/
│   ├── Models/           # Data models (NetworkFlow, FeatureVector, etc.)
│   ├── Services/         # Core services
│   │   ├── PacketSniffer.cs      # Packet capture
│   │   ├── FeatureExtractor.cs   # Feature engineering
│   │   ├── MlInferenceEngine.cs  # ONNX inference
│   │   ├── AlertManager.cs       # Alert handling
│   │   └── DataExporter.cs       # CSV/JSON export
│   └── Program.cs
├── scripts/
│   └── train_model.py    # ML model training
└── docs/
    ├── ThreatModel.md
    └── Architecture/
```

## Detection Capabilities

| Threat | Detection Method |
|--------|------------------|
| Port Scans | High unique ports ratio, SYN flood patterns |
| DDoS Floods | Abnormal packets/bytes per second |
| Anomalies | Isolation Forest outlier detection |

## License

MIT
