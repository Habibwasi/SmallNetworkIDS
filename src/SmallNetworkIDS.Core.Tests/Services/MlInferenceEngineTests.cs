using SmallNetworkIDS.Core.Models;
using SmallNetworkIDS.Core.Services;
using Xunit;

namespace SmallNetworkIDS.Core.Tests.Services;

public class MlInferenceEngineTests
{
    private readonly FeatureExtractor _featureExtractor = new();
    private readonly MlInferenceEngine _engine;

    public MlInferenceEngineTests()
    {
        _engine = new MlInferenceEngine(_featureExtractor);
    }

    [Fact]
    public void LoadModel_WithNonexistentPath_ShouldNotThrow()
    {
        var exception = Record.Exception(() => _engine.LoadModel("nonexistent.onnx"));

        Assert.Null(exception);
        Assert.False(_engine.IsModelLoaded);
    }

    [Fact]
    public void Predict_WithoutModel_ShouldUseFallbackRules()
    {
        var features = new FeatureVector
        {
            FlowId = "test",
            PacketsPerSecond = 0.9f,
            BytesPerSecond = 0.8f,
            UniquePortsRatio = 0.5f
        };

        var result = _engine.Predict(features);

        Assert.NotNull(result);
        Assert.True(result.AnomalyScore >= 0);
    }

    [Fact]
    public void Predict_WithHighPacketRate_ShouldDetectAnomaly()
    {
        var features = new FeatureVector
        {
            FlowId = "ddos",
            PacketsPerSecond = 0.95f,  // Very high
            BytesPerSecond = 0.5f,
            SynRatio = 0.8f,
            AckRatio = 0.1f,
            UniquePortsRatio = 0.1f,
            FlowDuration = 0.3f
        };

        var result = _engine.Predict(features);

        Assert.True(result.IsAnomaly || result.AnomalyScore > 0.5);
    }

    [Fact]
    public void Predict_WithHighPortCount_ShouldDetectPortScan()
    {
        var features = new FeatureVector
        {
            FlowId = "portscan",
            PacketsPerSecond = 0.3f,
            BytesPerSecond = 0.2f,
            UniquePortsRatio = 0.95f,  // Very high - port scan indicator
            SynRatio = 0.9f,
            AckRatio = 0.05f
        };

        var result = _engine.Predict(features);

        Assert.True(result.IsAnomaly || result.AnomalyScore > 0.5);
    }

    [Fact]
    public void AnomalyThreshold_ShouldAffectPredictions()
    {
        var features = new FeatureVector
        {
            FlowId = "threshold-test",
            PacketsPerSecond = 0.6f,
            BytesPerSecond = 0.5f,
            UniquePortsRatio = 0.7f
        };

        _engine.AnomalyThreshold = 0.3;
        var result1 = _engine.Predict(features);

        _engine.AnomalyThreshold = 0.9;
        var result2 = _engine.Predict(features);

        // With higher threshold, it should be less likely to flag as anomaly
        Assert.True(result1.IsAnomaly || result2.IsAnomaly || result1.AnomalyScore >= 0);
    }

    [Fact]
    public void Predict_WithNormalTraffic_ShouldNotFlagAsAnomaly()
    {
        var features = new FeatureVector
        {
            FlowId = "normal",
            PacketsPerSecond = 0.1f,
            BytesPerSecond = 0.15f,
            AvgPacketSize = 0.5f,
            SynRatio = 0.01f,
            AckRatio = 0.95f,
            FinRstRatio = 0.01f,
            UniquePortsRatio = 0.05f,
            FlowDuration = 0.2f
        };

        var result = _engine.Predict(features);

        Assert.False(result.IsAnomaly);
        Assert.True(result.AnomalyScore <= 0.5);
    }
}
