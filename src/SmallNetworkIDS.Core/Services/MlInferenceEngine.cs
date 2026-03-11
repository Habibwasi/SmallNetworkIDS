using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using SmallNetworkIDS.Core.Models;

namespace SmallNetworkIDS.Core.Services;

/// <summary>
/// ML inference engine using ONNX runtime for anomaly detection.
/// Supports loading Scikit-learn models exported as ONNX.
/// </summary>
public class MlInferenceEngine : IDisposable
{
    private InferenceSession? _session;
    private bool _modelLoaded;
    private string? _inputName;
    
    // Fallback rule-based detection when no model is loaded
    private readonly FeatureExtractor _featureExtractor;
    
    /// <summary>
    /// Threshold above which a flow is considered anomalous
    /// </summary>
    public double AnomalyThreshold { get; set; } = 0.6;
    
    public bool IsModelLoaded => _modelLoaded;
    
    public MlInferenceEngine(FeatureExtractor featureExtractor)
    {
        _featureExtractor = featureExtractor;
    }
    
    /// <summary>
    /// Load ONNX model exported from Scikit-learn
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
            _inputName = _session.InputMetadata.Keys.FirstOrDefault() ?? "input";
            _modelLoaded = true;
            
            Console.WriteLine($"[ML] Loaded model: {modelPath}");
            Console.WriteLine($"[ML] Input: {_inputName}, Features: {_session.InputMetadata[_inputName].Dimensions.Length}D");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ML] Failed to load model: {ex.Message}. Using rule-based detection.");
        }
    }
    
    /// <summary>
    /// Run inference on feature vector and return anomaly detection result
    /// </summary>
    public AnomalyResult Predict(FeatureVector features)
    {
        if (_modelLoaded && _session != null)
        {
            return PredictWithModel(features);
        }
        
        return PredictWithRules(features);
    }
    
    /// <summary>
    /// Legacy method for backward compatibility
    /// </summary>
    public (double AnomalyScore, AlertType? SuggestedType) PredictLegacy(FeatureVector features)
    {
        var result = Predict(features);
        return (result.AnomalyScore, result.SuggestedAlertType);
    }
    
    private AnomalyResult PredictWithModel(FeatureVector features)
    {
        try
        {
            var featureArray = features.ToArray();
            var inputTensor = new DenseTensor<float>(featureArray, [1, FeatureVector.FeatureCount]);
            var inputs = new List<NamedOnnxValue>
            {
                NamedOnnxValue.CreateFromTensor(_inputName ?? "input", inputTensor)
            };
            
            using var results = _session!.Run(inputs);
            var outputName = results.First().Name;
            
            double score;
            
            // Handle different Scikit-learn model output formats
            if (outputName.Contains("label", StringComparison.OrdinalIgnoreCase))
            {
                // Classification model: -1 = anomaly, 1 = normal (e.g., IsolationForest, OneClassSVM)
                var label = results.First().AsEnumerable<long>().FirstOrDefault();
                score = label == -1 ? 0.8 : 0.2;
                
                // Try to get probability/score if available
                var probResult = results.FirstOrDefault(r => r.Name.Contains("score", StringComparison.OrdinalIgnoreCase));
                if (probResult != null)
                {
                    var scores = probResult.AsEnumerable<float>().ToArray();
                    // IsolationForest: lower score = more anomalous
                    score = 1.0 - Math.Clamp(scores.FirstOrDefault(), 0, 1);
                }
            }
            else
            {
                // Direct score output
                var output = results.First().AsEnumerable<float>().First();
                score = Math.Clamp(output, 0, 1);
            }
            
            var alertType = ClassifyAnomaly(features, score);
            
            return new AnomalyResult
            {
                IsAnomaly = score >= AnomalyThreshold,
                AnomalyScore = score,
                SuggestedAlertType = alertType,
                Confidence = Math.Abs(score - 0.5) * 2, // Higher confidence near 0 or 1
                FromModel = true
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ML] Inference error: {ex.Message}. Falling back to rules.");
            return PredictWithRules(features);
        }
    }
    
    private AnomalyResult PredictWithRules(FeatureVector features)
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
            var floodScore = (double)Math.Max(features.PacketsPerSecond, features.BytesPerSecond);
            if (floodScore > score)
            {
                score = floodScore;
                type = AlertType.DDoSFlood;
            }
        }
        
        // General anomaly: unusual flag combinations
        if (features.FinRstRatio > 0.5f)
        {
            score = Math.Max(score, 0.4 + features.FinRstRatio * 0.3);
            type ??= AlertType.AnomalousTraffic;
        }
        
        return new AnomalyResult
        {
            IsAnomaly = score >= AnomalyThreshold,
            AnomalyScore = score,
            SuggestedAlertType = type,
            Confidence = score > 0.5 ? score : 1 - score,
            FromModel = false
        };
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
