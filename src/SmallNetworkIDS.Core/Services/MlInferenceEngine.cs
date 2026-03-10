using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using SmallNetworkIDS.Core.Models;

namespace SmallNetworkIDS.Core.Services;

/// <summary>
/// ML inference engine using ONNX runtime for anomaly detection
/// </summary>
public class MlInferenceEngine : IDisposable
{
    private InferenceSession? _session;
    private bool _modelLoaded;
    
    // Fallback rule-based detection when no model is loaded
    private readonly FeatureExtractor _featureExtractor;
    
    public bool IsModelLoaded => _modelLoaded;
    
    public MlInferenceEngine(FeatureExtractor featureExtractor)
    {
        _featureExtractor = featureExtractor;
    }
    
    /// <summary>
    /// Load ONNX model from file
    /// </summary>
    public void LoadModel(string modelPath)
    {
        if (!File.Exists(modelPath))
        {
            Console.WriteLine($"[ML] Model not found at {modelPath}. Using rule-based detection.");
            return;
        }
        
        try
        {
            _session = new InferenceSession(modelPath);
            _modelLoaded = true;
            Console.WriteLine($"[ML] Loaded model: {modelPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ML] Failed to load model: {ex.Message}. Using rule-based detection.");
        }
    }
    
    /// <summary>
    /// Run inference on feature vector and return anomaly score (0-1)
    /// </summary>
    public (double AnomalyScore, AlertType? SuggestedType) Predict(FeatureVector features)
    {
        if (_modelLoaded && _session != null)
        {
            return PredictWithModel(features);
        }
        
        return PredictWithRules(features);
    }
    
    private (double AnomalyScore, AlertType? SuggestedType) PredictWithModel(FeatureVector features)
    {
        try
        {
            var inputTensor = new DenseTensor<float>(features.ToArray(), [1, FeatureVector.FeatureCount]);
            var inputs = new List<NamedOnnxValue>
            {
                NamedOnnxValue.CreateFromTensor("input", inputTensor)
            };
            
            using var results = _session!.Run(inputs);
            var output = results.First().AsEnumerable<float>().First();
            
            // Assume model outputs anomaly score 0-1
            var score = Math.Clamp(output, 0, 1);
            var type = ClassifyAnomaly(features, score);
            
            return (score, type);
        }
        catch
        {
            return PredictWithRules(features);
        }
    }
    
    private (double AnomalyScore, AlertType? SuggestedType) PredictWithRules(FeatureVector features)
    {
        double score = 0;
        AlertType? type = null;
        
        // Port scan detection: high unique ports ratio, low ACK ratio
        if (features.UniquePortsRatio > 0.2f && features.AckRatio < 0.3f)
        {
            score = Math.Max(score, 0.5 + features.UniquePortsRatio * 0.5);
            type = AlertType.PortScan;
        }
        
        // SYN flood: high SYN ratio, very low ACK ratio
        if (features.SynRatio > 0.8f && features.AckRatio < 0.1f)
        {
            score = Math.Max(score, 0.7 + features.SynRatio * 0.3);
            type = AlertType.SynFlood;
        }
        
        // DDoS flood: very high packets/bytes per second
        if (features.PacketsPerSecond > 0.5f || features.BytesPerSecond > 0.5f)
        {
            var floodScore = Math.Max(features.PacketsPerSecond, features.BytesPerSecond);
            if (floodScore > score)
            {
                score = floodScore;
                type = AlertType.DDoSFlood;
            }
        }
        
        // General anomaly: unusual flag combinations
        if (features.FinRstRatio > 0.5f && features.PacketCount() < 10)
        {
            score = Math.Max(score, 0.4 + features.FinRstRatio * 0.3);
            type ??= AlertType.AnomalousTraffic;
        }
        
        return (score, type);
    }
    
    private static AlertType? ClassifyAnomaly(FeatureVector features, double score)
    {
        if (score < 0.5) return null;
        
        if (features.UniquePortsRatio > 0.3f) return AlertType.PortScan;
        if (features.SynRatio > 0.7f) return AlertType.SynFlood;
        if (features.PacketsPerSecond > 0.6f) return AlertType.DDoSFlood;
        
        return AlertType.AnomalousTraffic;
    }
    
    public void Dispose()
    {
        _session?.Dispose();
    }
}

// Extension method for FeatureVector
file static class FeatureVectorExtensions
{
    public static int PacketCount(this FeatureVector _) => 10; // Placeholder
}
