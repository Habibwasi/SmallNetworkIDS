using SmallNetworkIDS.Core.Models;
using Xunit;

namespace SmallNetworkIDS.Core.Tests.Models;

public class NetworkFlowTests
{
    [Fact]
    public void GenerateFlowId_ShouldCreateCorrectFormat()
    {
        var flowId = NetworkFlow.GenerateFlowId("192.168.1.100", "10.0.0.1", 54321, 443, "TCP");
        
        Assert.Equal("192.168.1.100:54321->10.0.0.1:443:TCP", flowId);
    }

    [Fact]
    public void DurationSeconds_ShouldCalculateCorrectly()
    {
        var flow = new NetworkFlow
        {
            FlowId = "test",
            SourceIp = "192.168.1.1",
            DestinationIp = "10.0.0.1",
            FirstSeen = new DateTime(2026, 3, 13, 10, 0, 0),
            LastSeen = new DateTime(2026, 3, 13, 10, 0, 10)
        };

        Assert.Equal(10, flow.DurationSeconds);
    }

    [Fact]
    public void PacketsPerSecond_ShouldCalculateFromPacketCount()
    {
        var flow = new NetworkFlow
        {
            FirstSeen = new DateTime(2026, 3, 13, 10, 0, 0),
            LastSeen = new DateTime(2026, 3, 13, 10, 0, 2),
            PacketCount = 100
        };

        Assert.Equal(50, flow.PacketsPerSecond);
    }

    [Fact]
    public void PacketsPerSecond_ShouldReturnPacketCountWhenDurationIsZero()
    {
        var now = DateTime.UtcNow;
        var flow = new NetworkFlow
        {
            FirstSeen = now,
            LastSeen = now,
            PacketCount = 100
        };

        // When duration is 0, formula returns PacketCount
        // DurationSeconds will be 0 or very close to 0
        Assert.Equal(100, flow.PacketsPerSecond, precision: 0);
    }

    [Fact]
    public void BytesPerSecond_ShouldCalculateFromByteCount()
    {
        var flow = new NetworkFlow
        {
            FirstSeen = new DateTime(2026, 3, 13, 10, 0, 0),
            LastSeen = new DateTime(2026, 3, 13, 10, 0, 5),
            ByteCount = 5000
        };

        Assert.Equal(1000, flow.BytesPerSecond);
    }
}
