namespace SmallNetworkIDS.Core.Models;

/// <summary>
/// Feature vector for ML inference
/// </summary>
public class FeatureVector
{
    public string FlowId { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    
    // Normalized features (0-1 range)
    public float PacketsPerSecond { get; set; }
    public float BytesPerSecond { get; set; }
    public float AvgPacketSize { get; set; }
    public float SynRatio { get; set; }
    public float AckRatio { get; set; }
    public float FinRstRatio { get; set; }
    public float UniquePortsRatio { get; set; }
    public float FlowDuration { get; set; }
    
    /// <summary>
    /// Convert to float array for ML inference
    /// </summary>
    public float[] ToArray()
    {
        return
        [
            PacketsPerSecond,
            BytesPerSecond,
            AvgPacketSize,
            SynRatio,
            AckRatio,
            FinRstRatio,
            UniquePortsRatio,
            FlowDuration
        ];
    }
    
    public static int FeatureCount => 8;
}
