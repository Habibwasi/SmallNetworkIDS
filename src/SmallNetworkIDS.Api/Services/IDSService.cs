using SmallNetworkIDS.Core.Models;
using SmallNetworkIDS.Core.Services;

namespace SmallNetworkIDS.Api.Services;

/// <summary>
/// Service that manages IDS operations for the API
/// </summary>
public class IDSService
{
    private readonly AlertManager _alertManager;
    private readonly FeatureExtractor _featureExtractor;
    private readonly MlInferenceEngine _mlEngine;
    private readonly DataExporter _dataExporter;
    
    private readonly List<AlertEvent> _recentAlerts = new();
    private readonly List<NetworkFlow> _recentFlows = new();
    private DateTime _startTime = DateTime.UtcNow;

    public IDSService(AlertManager alertManager, FeatureExtractor featureExtractor, 
                      MlInferenceEngine mlEngine, DataExporter dataExporter)
    {
        _alertManager = alertManager;
        _featureExtractor = featureExtractor;
        _mlEngine = mlEngine;
        _dataExporter = dataExporter;

        // Subscribe to alerts
        _alertManager.AlertRaised += (s, alert) =>
        {
            lock (_recentAlerts)
            {
                _recentAlerts.Add(alert);
                if (_recentAlerts.Count > 1000)
                    _recentAlerts.RemoveAt(0);
            }
        };
    }

    public void AddFlow(NetworkFlow flow)
    {
        lock (_recentFlows)
        {
            _recentFlows.Add(flow);
            if (_recentFlows.Count > 5000)
                _recentFlows.RemoveAt(0);
        }
    }

    public List<AlertEvent> GetRecentAlerts(int limit = 100)
    {
        lock (_recentAlerts)
        {
            return _recentAlerts.OrderByDescending(a => a.Timestamp).Take(limit).ToList();
        }
    }

    public List<NetworkFlow> GetRecentFlows(int limit = 500)
    {
        lock (_recentFlows)
        {
            return _recentFlows.OrderByDescending(f => f.LastSeen).Take(limit).ToList();
        }
    }

    public AlertStats GetAlertStats()
    {
        lock (_recentAlerts)
        {
            var now = DateTime.UtcNow;
            var last5Min = now.AddMinutes(-5);
            var last1Hour = now.AddHours(-1);

            return new AlertStats
            {
                TotalAlerts = _recentAlerts.Count,
                AlertsLast5Min = _recentAlerts.Count(a => a.Timestamp > last5Min),
                AlertsLastHour = _recentAlerts.Count(a => a.Timestamp > last1Hour),
                HighestSeverity = _recentAlerts.Any() 
                    ? _recentAlerts.Max(a => (int)a.Severity) 
                    : 0,
                PortScanCount = _recentAlerts.Count(a => a.Type == AlertType.PortScan),
                DDoSFloodCount = _recentAlerts.Count(a => a.Type == AlertType.DDoSFlood)
            };
        }
    }

    public NetworkStats GetNetworkStats()
    {
        lock (_recentFlows)
        {
            if (!_recentFlows.Any())
                return new NetworkStats();

            return new NetworkStats
            {
                TotalFlows = _recentFlows.Count,
                TotalPackets = _recentFlows.Sum(f => f.PacketCount),
                TotalBytes = _recentFlows.Sum(f => f.ByteCount),
                AvgPacketsPerFlow = _recentFlows.Average(f => f.PacketCount),
                AvgBytesPerFlow = _recentFlows.Average(f => f.ByteCount),
                UniqueSourceIps = _recentFlows.Select(f => f.SourceIp).Distinct().Count(),
                UniqueDestIps = _recentFlows.Select(f => f.DestinationIp).Distinct().Count()
            };
        }
    }

    public List<ThreatIP> GetTopThreats(int limit = 10)
    {
        lock (_recentAlerts)
        {
            return _recentAlerts
                .GroupBy(a => a.SourceIp)
                .Select(g => new ThreatIP
                {
                    IpAddress = g.Key,
                    AlertCount = g.Count(),
                    HighestSeverity = (int)g.Max(a => a.Severity),
                    LastSeen = g.Max(a => a.Timestamp),
                    Types = string.Join(", ", g.Select(a => a.Type).Distinct())
                })
                .OrderByDescending(t => t.AlertCount)
                .Take(limit)
                .ToList();
        }
    }

    public TimeSpan GetUptime()
    {
        return DateTime.UtcNow - _startTime;
    }
}

public class AlertStats
{
    public int TotalAlerts { get; set; }
    public int AlertsLast5Min { get; set; }
    public int AlertsLastHour { get; set; }
    public int HighestSeverity { get; set; }
    public int PortScanCount { get; set; }
    public int DDoSFloodCount { get; set; }
}

public class NetworkStats
{
    public int TotalFlows { get; set; }
    public long TotalPackets { get; set; }
    public long TotalBytes { get; set; }
    public double AvgPacketsPerFlow { get; set; }
    public double AvgBytesPerFlow { get; set; }
    public int UniqueSourceIps { get; set; }
    public int UniqueDestIps { get; set; }
}

public class ThreatIP
{
    public string IpAddress { get; set; } = string.Empty;
    public int AlertCount { get; set; }
    public int HighestSeverity { get; set; }
    public DateTime LastSeen { get; set; }
    public string Types { get; set; } = string.Empty;
}
