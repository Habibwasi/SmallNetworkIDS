using SmallNetworkIDS.Core.Models;
using Xunit;

namespace SmallNetworkIDS.Core.Tests.Models;

public class FeatureVectorTests
{
    [Fact]
    public void FeatureVector_ShouldInitializeWithDefaults()
    {
        var fv = new FeatureVector();

        Assert.Equal(string.Empty, fv.FlowId);
        Assert.Equal(default(float), fv.PacketsPerSecond);
        Assert.Equal(default(float), fv.BytesPerSecond);
    }

    [Fact]
    public void FeatureVector_ShouldSetAllProperties()
    {
        var fv = new FeatureVector
        {
            FlowId = "test-flow",
            Timestamp = DateTime.UtcNow,
            PacketsPerSecond = 0.5f,
            BytesPerSecond = 0.6f,
            AvgPacketSize = 0.4f,
            SynRatio = 0.1f,
            AckRatio = 0.8f,
            FinRstRatio = 0.05f,
            UniquePortsRatio = 0.2f,
            FlowDuration = 0.3f
        };

        Assert.Equal("test-flow", fv.FlowId);
        Assert.Equal(0.5f, fv.PacketsPerSecond);
        Assert.Equal(0.6f, fv.BytesPerSecond);
        Assert.Equal(0.4f, fv.AvgPacketSize);
    }

    [Fact]
    public void ToArray_ShouldReturnCorrectLength()
    {
        var fv = new FeatureVector
        {
            PacketsPerSecond = 0.1f,
            BytesPerSecond = 0.2f,
            AvgPacketSize = 0.3f,
            SynRatio = 0.05f,
            AckRatio = 0.85f,
            FinRstRatio = 0.05f,
            UniquePortsRatio = 0.1f,
            FlowDuration = 0.5f
        };

        var array = fv.ToArray();

        Assert.Equal(FeatureVector.FeatureCount, array.Length);
        Assert.Equal(8, array.Length);
    }

    [Fact]
    public void ToArray_ShouldContainAllFeatures()
    {
        var fv = new FeatureVector
        {
            PacketsPerSecond = 0.1f,
            BytesPerSecond = 0.2f,
            AvgPacketSize = 0.3f,
            SynRatio = 0.05f,
            AckRatio = 0.85f,
            FinRstRatio = 0.05f,
            UniquePortsRatio = 0.1f,
            FlowDuration = 0.5f
        };

        var array = fv.ToArray();

        Assert.Equal(0.1f, array[0]);
        Assert.Equal(0.2f, array[1]);
        Assert.Equal(0.3f, array[2]);
        Assert.Equal(0.05f, array[3]);
        Assert.Equal(0.85f, array[4]);
        Assert.Equal(0.05f, array[5]);
        Assert.Equal(0.1f, array[6]);
        Assert.Equal(0.5f, array[7]);
    }
}
