using SmallNetworkIDS.Core.Models;
using System.Collections.Concurrent;
using System.Text.Json;

namespace SmallNetworkIDS.Core.Services;

/// <summary>
/// Manages alerts, logging, and suggested firewall rules
/// </summary>
public class AlertManager
{
    private readonly ConcurrentQueue<AlertEvent> _recentAlerts = new();
    private readonly string _logPath;
    private readonly object _fileLock = new();
    
    public event EventHandler<AlertEvent>? AlertRaised;
    
    public double AnomalyThreshold { get; set; } = 0.6;
    public int MaxRecentAlerts { get; } = 1000;
    
    public AlertManager(string logPath = "alerts.json")
    {
        _logPath = logPath;
    }
    
    /// <summary>
    /// Process inference result and raise alert if needed
    /// </summary>
    public AlertEvent? ProcessInferenceResult(NetworkFlow flow, FeatureVector features, AnomalyResult result)
    {
        if (!result.IsAnomaly || result.SuggestedAlertType == null)
        {
            return null;
        }
        
        var alert = new AlertEvent
        {
            Type = result.SuggestedAlertType.Value,
            Severity = GetSeverity(result.AnomalyScore),
            SourceIp = flow.SourceIp,
            DestinationIp = flow.DestinationIp,
            Description = GenerateDescription(result.SuggestedAlertType.Value, flow, features),
            AnomalyScore = result.AnomalyScore,
            SuggestedAction = GenerateFirewallRule(result.SuggestedAlertType.Value, flow),
            RelatedFlow = flow
        };
        
        RaiseAlert(alert);
        return alert;
    }

    /// <summary>
    /// Process inference result and raise alert if needed (legacy overload)
    /// </summary>
    public AlertEvent? ProcessInferenceResult(
        NetworkFlow flow, 
        FeatureVector features, 
        double anomalyScore, 
        AlertType? suggestedType)
    {
        if (anomalyScore < AnomalyThreshold || suggestedType == null)
        {
            return null;
        }
        
        var alert = new AlertEvent
        {
            Type = suggestedType.Value,
            Severity = GetSeverity(anomalyScore),
            SourceIp = flow.SourceIp,
            DestinationIp = flow.DestinationIp,
            Description = GenerateDescription(suggestedType.Value, flow, features),
            AnomalyScore = anomalyScore,
            SuggestedAction = GenerateFirewallRule(suggestedType.Value, flow),
            RelatedFlow = flow
        };
        
        RaiseAlert(alert);
        return alert;
    }
    
    /// <summary>
    /// Raise an alert
    /// </summary>
    public void RaiseAlert(AlertEvent alert)
    {
        _recentAlerts.Enqueue(alert);
        
        // Trim queue if too large
        while (_recentAlerts.Count > MaxRecentAlerts)
        {
            _recentAlerts.TryDequeue(out _);
        }
        
        // Log to file
        LogAlert(alert);
        
        // Notify subscribers
        AlertRaised?.Invoke(this, alert);
        
        // Console output
        PrintAlert(alert);
    }
    
    public IEnumerable<AlertEvent> GetRecentAlerts(int count = 100)
    {
        return _recentAlerts.Reverse().Take(count);
    }
    
    public IEnumerable<AlertEvent> GetAlertsBySource(string sourceIp)
    {
        return _recentAlerts.Where(a => a.SourceIp == sourceIp);
    }
    
    private void LogAlert(AlertEvent alert)
    {
        try
        {
            lock (_fileLock)
            {
                var json = JsonSerializer.Serialize(new
                {
                    alert.Id,
                    alert.Timestamp,
                    Type = alert.Type.ToString(),
                    Severity = alert.Severity.ToString(),
                    alert.SourceIp,
                    alert.DestinationIp,
                    alert.Description,
                    alert.AnomalyScore,
                    alert.SuggestedAction
                });
                
                File.AppendAllText(_logPath, json + Environment.NewLine);
            }
        }
        catch
        {
            // Silently fail logging
        }
    }
    
    private static void PrintAlert(AlertEvent alert)
    {
        var color = alert.Severity switch
        {
            AlertSeverity.Critical => ConsoleColor.Red,
            AlertSeverity.High => ConsoleColor.DarkRed,
            AlertSeverity.Medium => ConsoleColor.Yellow,
            _ => ConsoleColor.Gray
        };
        
        var origColor = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine($"\n⚠ ALERT: {alert}");
        if (alert.SuggestedAction != null)
        {
            Console.WriteLine($"  → Suggested: {alert.SuggestedAction}");
        }
        Console.ForegroundColor = origColor;
    }
    
    private static AlertSeverity GetSeverity(double score) => score switch
    {
        >= 0.9 => AlertSeverity.Critical,
        >= 0.75 => AlertSeverity.High,
        >= 0.6 => AlertSeverity.Medium,
        _ => AlertSeverity.Low
    };
    
    private static string GenerateDescription(AlertType type, NetworkFlow flow, FeatureVector features)
    {
        return type switch
        {
            AlertType.PortScan => 
                $"Port scan detected from {flow.SourceIp} - {features.UniquePortsRatio * 100:F0}+ unique ports targeted",
            AlertType.SynFlood => 
                $"SYN flood from {flow.SourceIp} to {flow.DestinationIp}:{flow.DestinationPort} - {features.SynRatio * 100:F0}% SYN packets",
            AlertType.DDoSFlood => 
                $"Traffic flood: {flow.PacketsPerSecond:F0} pkt/s, {flow.BytesPerSecond / 1024:F0} KB/s",
            AlertType.AnomalousTraffic => 
                $"Anomalous traffic pattern from {flow.SourceIp} to {flow.DestinationIp}",
            _ => "Unknown anomaly detected"
        };
    }
    
    private static string GenerateFirewallRule(AlertType type, NetworkFlow flow)
    {
        return type switch
        {
            AlertType.PortScan or AlertType.SynFlood or AlertType.DDoSFlood =>
                $"netsh advfirewall firewall add rule name=\"Block {flow.SourceIp}\" dir=in action=block remoteip={flow.SourceIp}",
            _ => $"Monitor traffic from {flow.SourceIp}"
        };
    }
}
