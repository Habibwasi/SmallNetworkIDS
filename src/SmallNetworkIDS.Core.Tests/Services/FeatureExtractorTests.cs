using SmallNetworkIDS.Core.Models;
using SmallNetworkIDS.Core.Services;
using Xunit;

namespace SmallNetworkIDS.Core.Tests.Services;

public class FeatureExtractorTests
{
    private readonly FeatureExtractor _extractor = new();

    [Fact]
    public void ExtractFeatures_ShouldReturnValidFeatureVector()
    {
        var flow = new NetworkFlow
        {
            FlowId = "test-flow",
            SourceIp = "192.168.1.1",
            DestinationIp = "10.0.0.1",
            SourcePort = 54321,
            DestinationPort = 443,
            Protocol = "TCP",
            FirstSeen = DateTime.UtcNow.AddSeconds(-10),
            LastSeen = DateTime.UtcNow,
            PacketCount = 100,
            ByteCount = 50000,
            SynCount = 5,
            AckCount = 90,
            FinCount = 1,
            RstCount = 0
        };

        var features = _extractor.ExtractFeatures(flow);

        Assert.NotNull(features);
        Assert.Equal("test-flow", features.FlowId);
        Assert.True(features.PacketsPerSecond >= 0 && features.PacketsPerSecond <= 1);
        Assert.True(features.BytesPerSecond >= 0 && features.BytesPerSecond <= 1);
        Assert.True(features.AvgPacketSize >= 0 && features.AvgPacketSize <= 1);
    }

    [Fact]
    public void ExtractFeatures_ShouldNormalizeValuesToZeroOneRange()
    {
        var flow = new NetworkFlow
        {
            FlowId = "test",
            SourceIp = "192.168.1.1",
            DestinationIp = "10.0.0.1",
            FirstSeen = DateTime.UtcNow.AddSeconds(-1),
            LastSeen = DateTime.UtcNow,
            PacketCount = 100,
            ByteCount = 50000,
            SynCount = 10,
            AckCount = 85,
            FinCount = 2,
            RstCount = 3
        };

        var features = _extractor.ExtractFeatures(flow);

        Assert.True(features.SynRatio >= 0 && features.SynRatio <= 1);
        Assert.True(features.AckRatio >= 0 && features.AckRatio <= 1);
        Assert.True(features.FinRstRatio >= 0 && features.FinRstRatio <= 1);
        Assert.True(features.FlowDuration >= 0 && features.FlowDuration <= 1);
    }

    [Fact]
    public void CheckPortScan_ShouldDetectMultiplePorts()
    {
        var flow1 = CreateFlowWithPort("192.168.1.1", "10.0.0.1", 80);
        var flow2 = CreateFlowWithPort("192.168.1.1", "10.0.0.2", 443);
        var flow3 = CreateFlowWithPort("192.168.1.1", "10.0.0.3", 22);

        _extractor.ExtractFeatures(flow1);
        _extractor.ExtractFeatures(flow2);
        _extractor.ExtractFeatures(flow3);

        var (isPortScan, portCount) = _extractor.CheckPortScan("192.168.1.1", threshold: 2);

        Assert.True(isPortScan);
        Assert.True(portCount >= 2);
    }

    [Fact]
    public void CheckPortScan_ShouldReturnFalseForUnknownIp()
    {
        var (isPortScan, portCount) = _extractor.CheckPortScan("1.2.3.4", threshold: 1);

        Assert.False(isPortScan);
        Assert.Equal(0, portCount);
    }

    [Fact]
    public void UpdateBaseline_ShouldStoreMetricValue()
    {
        _extractor.UpdateBaseline("metric1", 100.0);

        var value = _extractor.GetBaseline("metric1");

        Assert.NotNull(value);
        Assert.Equal(100.0, value.Value, 1);
    }

    [Fact]
    public void UpdateBaseline_ShouldApplyExponentialMovingAverage()
    {
        _extractor.UpdateBaseline("metric2", 100.0);
        _extractor.UpdateBaseline("metric2", 200.0);

        var value = _extractor.GetBaseline("metric2");

        Assert.NotNull(value);
        // 100 * 0.9 + 200 * 0.1 = 90 + 20 = 110
        Assert.True(value.Value > 100 && value.Value < 200);
    }

    [Fact]
    public void GetBaseline_ShouldReturnNullForNonexistentMetric()
    {
        var value = _extractor.GetBaseline("nonexistent");

        Assert.Null(value);
    }

    private static NetworkFlow CreateFlowWithPort(string srcIp, string dstIp, ushort dstPort)
    {
        return new NetworkFlow
        {
            FlowId = $"{srcIp}:{dstIp}:{dstPort}",
            SourceIp = srcIp,
            DestinationIp = dstIp,
            DestinationPort = dstPort,
            FirstSeen = DateTime.UtcNow,
            LastSeen = DateTime.UtcNow.AddSeconds(1),
            PacketCount = 10
        };
    }
}
