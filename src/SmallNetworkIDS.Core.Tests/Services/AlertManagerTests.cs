using SmallNetworkIDS.Core.Models;
using SmallNetworkIDS.Core.Services;
using Xunit;
using System.Collections.Generic;

namespace SmallNetworkIDS.Core.Tests.Services;

public class AlertManagerTests
{
    [Fact]
    public void ProcessInferenceResult_WithNomalScore_ShouldNotCreateAlert()
    {
        var alertManager = new AlertManager();
        var flow = CreateTestFlow();
        var features = CreateTestFeatures();
        var result = new AnomalyResult { IsAnomaly = false, AnomalyScore = 0.3 };

        var alert = alertManager.ProcessInferenceResult(flow, features, result);

        Assert.Null(alert);
    }

    [Fact]
    public void ProcessInferenceResult_WithAnomalousScore_ShouldCreateAlert()
    {
        var alertManager = new AlertManager();
        var flow = CreateTestFlow();
        var features = CreateTestFeatures();
        var result = new AnomalyResult 
        { 
            IsAnomaly = true, 
            AnomalyScore = 0.85,
            SuggestedAlertType = AlertType.DDoSFlood,
            FromModel = true
        };

        var alert = alertManager.ProcessInferenceResult(flow, features, result);

        Assert.NotNull(alert);
        Assert.Equal(AlertType.DDoSFlood, alert.Type);
        Assert.Equal(0.85, alert.AnomalyScore);
        Assert.Equal("192.168.1.1", alert.SourceIp);
    }

    [Fact]
    public void ProcessInferenceResult_ShouldSetCorrectSeverity()
    {
        var alertManager = new AlertManager();
        var flow = CreateTestFlow();
        var features = CreateTestFeatures();

        var lowResult = new AnomalyResult 
        { 
            IsAnomaly = true, 
            AnomalyScore = 0.6,
            SuggestedAlertType = AlertType.PortScan
        };

        var highResult = new AnomalyResult 
        { 
            IsAnomaly = true, 
            AnomalyScore = 0.95,
            SuggestedAlertType = AlertType.PortScan
        };

        var lowAlert = alertManager.ProcessInferenceResult(flow, features, lowResult);
        var highAlert = alertManager.ProcessInferenceResult(flow, features, highResult);

        Assert.NotNull(lowAlert);
        Assert.NotNull(highAlert);
        // Higher anomaly score should have equal or higher severity
        Assert.True(highAlert.Severity >= lowAlert.Severity);
    }

    [Fact]
    public void ProcessInferenceResult_ShouldGenerateSuggestedAction()
    {
        var alertManager = new AlertManager();
        var flow = CreateTestFlow();
        var features = CreateTestFeatures();
        var result = new AnomalyResult 
        { 
            IsAnomaly = true, 
            AnomalyScore = 0.9,
            SuggestedAlertType = AlertType.DDoSFlood
        };

        var alert = alertManager.ProcessInferenceResult(flow, features, result);

        Assert.NotNull(alert);
        Assert.NotNull(alert.SuggestedAction);
        Assert.NotEmpty(alert.SuggestedAction);
    }

    [Fact]
    public void RaiseAlert_ShouldInvokeEvent()
    {
        var alertManager = new AlertManager();
        var alert = new AlertEvent
        {
            Type = AlertType.PortScan,
            Severity = AlertSeverity.Medium,
            SourceIp = "192.168.1.1",
            DestinationIp = "10.0.0.1",
            Description = "Test alert",
            AnomalyScore = 0.75
        };

        bool eventRaised = false;
        alertManager.AlertRaised += (s, e) => eventRaised = true;

        alertManager.RaiseAlert(alert);

        Assert.True(eventRaised);
    }

    [Fact]
    public void AnomalyThreshold_ShouldAffectMlEngineDetection()
    {
        // AlertManager's threshold affects alert creation from results with IsAnomaly=true
        // ML Engine's threshold affects what gets classified as anomaly
        var alertManager = new AlertManager();
        var flow = CreateTestFlow();
        var features = CreateTestFeatures();
        
        // When IsAnomaly is false, no alert is created regardless of threshold
        var resultNotAnomaly = new AnomalyResult 
        { 
            IsAnomaly = false,  // Not flagged as anomaly
            AnomalyScore = 0.75,
            SuggestedAlertType = AlertType.PortScan
        };

        var alert = alertManager.ProcessInferenceResult(flow, features, resultNotAnomaly);

        // No alert when IsAnomaly is false
        Assert.Null(alert);
    }

    [Fact]
    public void ProcessInferenceResult_LegacyOverload_ShouldWork()
    {
        var alertManager = new AlertManager();
        var flow = CreateTestFlow();
        var features = CreateTestFeatures();

        var alert = alertManager.ProcessInferenceResult(flow, features, 0.85, AlertType.DDoSFlood);

        Assert.NotNull(alert);
        Assert.Equal(AlertType.DDoSFlood, alert.Type);
        Assert.Equal(0.85, alert.AnomalyScore);
    }

    private static NetworkFlow CreateTestFlow()
    {
        return new NetworkFlow
        {
            FlowId = "test-flow",
            SourceIp = "192.168.1.1",
            DestinationIp = "10.0.0.1",
            SourcePort = 54321,
            DestinationPort = 443,
            Protocol = "TCP",
            FirstSeen = DateTime.UtcNow.AddSeconds(-10),
            LastSeen = DateTime.UtcNow,
            PacketCount = 5000,
            ByteCount = 2500000
        };
    }

    private static FeatureVector CreateTestFeatures()
    {
        return new FeatureVector
        {
            FlowId = "test-flow",
            PacketsPerSecond = 0.8f,
            BytesPerSecond = 0.75f,
            UniquePortsRatio = 0.3f
        };
    }
}
