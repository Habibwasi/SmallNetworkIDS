namespace SmallNetworkIDS.Core.Models;

/// <summary>
/// Represents a network flow (5-tuple) with aggregated statistics
/// </summary>
public class NetworkFlow
{
    public string FlowId { get; set; } = string.Empty;
    public string SourceIp { get; set; } = string.Empty;
    public string DestinationIp { get; set; } = string.Empty;
    public ushort SourcePort { get; set; }
    public ushort DestinationPort { get; set; }
    public string Protocol { get; set; } = "TCP";
    
    // Timestamps
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    
    // Counters
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
    public int SynCount { get; set; }
    public int AckCount { get; set; }
    public int FinCount { get; set; }
    public int RstCount { get; set; }
    
    // Computed properties
    public double DurationSeconds => (LastSeen - FirstSeen).TotalSeconds;
    public double PacketsPerSecond => DurationSeconds > 0 ? PacketCount / DurationSeconds : PacketCount;
    public double BytesPerSecond => DurationSeconds > 0 ? ByteCount / DurationSeconds : ByteCount;
    
    public static string GenerateFlowId(string srcIp, string dstIp, ushort srcPort, ushort dstPort, string protocol)
    {
        return $"{srcIp}:{srcPort}->{dstIp}:{dstPort}:{protocol}";
    }
}
