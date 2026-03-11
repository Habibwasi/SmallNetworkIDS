namespace SmallNetworkIDS.Core.Models;

/// <summary>
/// Result of ML anomaly detection inference
/// </summary>
public class AnomalyResult
{
    /// <summary>
    /// True if the flow is classified as anomalous
    /// </summary>
    public bool IsAnomaly { get; init; }
    
    /// <summary>
    /// Anomaly score between 0.0 (normal) and 1.0 (highly anomalous)
    /// </summary>
    public double AnomalyScore { get; init; }
    
    /// <summary>
    /// Suggested alert type based on feature analysis
    /// </summary>
    public AlertType? SuggestedAlertType { get; init; }
    
    /// <summary>
    /// Confidence level of the classification (0-1)
    /// </summary>
    public double Confidence { get; init; }
    
    /// <summary>
    /// Whether the result came from ML model or rule-based fallback
    /// </summary>
    public bool FromModel { get; init; }
    
    public override string ToString()
    {
        var source = FromModel ? "ML" : "Rules";
        return $"IsAnomaly={IsAnomaly}, Score={AnomalyScore:F3}, Type={SuggestedAlertType}, Source={source}";
    }
}
