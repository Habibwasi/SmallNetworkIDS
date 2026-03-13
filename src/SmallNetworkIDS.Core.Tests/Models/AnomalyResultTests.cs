using SmallNetworkIDS.Core.Models;
using Xunit;

namespace SmallNetworkIDS.Core.Tests.Models;

public class AnomalyResultTests
{
    [Fact]
    public void AnomalyResult_ShouldInitializeWithDefaults()
    {
        var result = new AnomalyResult();

        Assert.False(result.IsAnomaly);
        Assert.Equal(0, result.AnomalyScore);
        Assert.Null(result.SuggestedAlertType);
    }

    [Fact]
    public void AnomalyResult_ShouldSetAllProperties()
    {
        var result = new AnomalyResult
        {
            IsAnomaly = true,
            AnomalyScore = 0.85,
            SuggestedAlertType = AlertType.DDoSFlood,
            Confidence = 0.92,
            FromModel = true
        };

        Assert.True(result.IsAnomaly);
        Assert.Equal(0.85, result.AnomalyScore);
        Assert.Equal(AlertType.DDoSFlood, result.SuggestedAlertType);
        Assert.Equal(0.92, result.Confidence);
        Assert.True(result.FromModel);
    }

    [Fact]
    public void IsAnomaly_ShouldBeIndependentOfScore()
    {
        var normalWithScore = new AnomalyResult 
        { 
            IsAnomaly = false, 
            AnomalyScore = 0.9 
        };

        var anomalyWithLowScore = new AnomalyResult 
        { 
            IsAnomaly = true, 
            AnomalyScore = 0.3 
        };

        Assert.False(normalWithScore.IsAnomaly);
        Assert.True(anomalyWithLowScore.IsAnomaly);
    }

    [Fact]
    public void SuggestedAlertType_ShouldBeNullableWhenNotSet()
    {
        var result = new AnomalyResult { IsAnomaly = false };

        Assert.Null(result.SuggestedAlertType);
    }

    [Fact]
    public void SuggestedAlertType_ShouldSupportAllAlertTypes()
    {
        var alertTypes = new[] 
        { 
            AlertType.PortScan, 
            AlertType.DDoSFlood, 
            AlertType.AnomalousTraffic 
        };

        foreach (var alertType in alertTypes)
        {
            var result = new AnomalyResult 
            { 
                IsAnomaly = true, 
                SuggestedAlertType = alertType 
            };

            Assert.Equal(alertType, result.SuggestedAlertType);
        }
    }
}
