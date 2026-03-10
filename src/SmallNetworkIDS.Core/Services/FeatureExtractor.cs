using SmallNetworkIDS.Core.Models;
using System.Collections.Concurrent;

namespace SmallNetworkIDS.Core.Services;

/// <summary>
/// Extracts normalized features from network flows for ML inference
/// </summary>
public class FeatureExtractor
{
    // Baseline statistics for normalization
    private readonly ConcurrentDictionary<string, double> _baselines = new();
    
    // Normalization bounds (adjust based on your network)
    private const double MaxPacketsPerSecond = 10000.0;
    private const double MaxBytesPerSecond = 1_000_000_000.0; // 1 Gbps
    private const double MaxPacketSize = 1500.0; // MTU
    private const double MaxFlowDuration = 3600.0; // 1 hour
    
    // Port scan detection
    private readonly ConcurrentDictionary<string, HashSet<ushort>> _sourcePortHistory = new();
    private readonly TimeSpan _portHistoryWindow = TimeSpan.FromMinutes(5);
    private DateTime _lastPortHistoryCleanup = DateTime.UtcNow;
    
    /// <summary>
    /// Extract features from a network flow
    /// </summary>
    public FeatureVector ExtractFeatures(NetworkFlow flow)
    {
        CleanupPortHistoryIfNeeded();
        
        // Track unique destination ports per source IP (for port scan detection)
        var portSet = _sourcePortHistory.GetOrAdd(flow.SourceIp, _ => []);
        lock (portSet)
        {
            portSet.Add(flow.DestinationPort);
        }
        
        int uniquePorts;
        lock (portSet)
        {
            uniquePorts = portSet.Count;
        }
        
        var totalPackets = flow.PacketCount > 0 ? flow.PacketCount : 1;
        
        return new FeatureVector
        {
            FlowId = flow.FlowId,
            Timestamp = DateTime.UtcNow,
            
            // Normalize features to 0-1 range
            PacketsPerSecond = Normalize(flow.PacketsPerSecond, MaxPacketsPerSecond),
            BytesPerSecond = Normalize(flow.BytesPerSecond, MaxBytesPerSecond),
            AvgPacketSize = Normalize((double)flow.ByteCount / totalPackets, MaxPacketSize),
            
            // TCP flag ratios
            SynRatio = (float)flow.SynCount / totalPackets,
            AckRatio = (float)flow.AckCount / totalPackets,
            FinRstRatio = (float)(flow.FinCount + flow.RstCount) / totalPackets,
            
            // Port scan indicator
            UniquePortsRatio = Math.Min(1.0f, uniquePorts / 100.0f),
            
            // Flow duration
            FlowDuration = Normalize(flow.DurationSeconds, MaxFlowDuration)
        };
    }
    
    /// <summary>
    /// Detect port scan patterns from source IP
    /// </summary>
    public (bool IsPortScan, int UniquePortCount) CheckPortScan(string sourceIp, int threshold = 20)
    {
        if (_sourcePortHistory.TryGetValue(sourceIp, out var portSet))
        {
            int count;
            lock (portSet)
            {
                count = portSet.Count;
            }
            return (count >= threshold, count);
        }
        return (false, 0);
    }
    
    /// <summary>
    /// Update baseline with normal traffic sample
    /// </summary>
    public void UpdateBaseline(string metric, double value)
    {
        _baselines.AddOrUpdate(metric, value, (_, old) => old * 0.9 + value * 0.1);
    }
    
    public double? GetBaseline(string metric)
    {
        return _baselines.TryGetValue(metric, out var value) ? value : null;
    }
    
    private static float Normalize(double value, double max)
    {
        return (float)Math.Clamp(value / max, 0.0, 1.0);
    }
    
    private void CleanupPortHistoryIfNeeded()
    {
        if (DateTime.UtcNow - _lastPortHistoryCleanup < _portHistoryWindow) return;
        
        _lastPortHistoryCleanup = DateTime.UtcNow;
        _sourcePortHistory.Clear();
    }
}
