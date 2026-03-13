using SmallNetworkIDS.Core.Models;
using SmallNetworkIDS.Core.Services;
using Xunit;
using System.Globalization;

namespace SmallNetworkIDS.Core.Tests.Services;

public class DataExporterTests : IDisposable
{
    private readonly DataExporter _exporter = new();
    private readonly List<string> _tempFiles = new();

    [Fact]
    public void ExportToCsv_ShouldCreateValidFile()
    {
        var flows = CreateTestFlows();
        var filePath = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.csv");
        _tempFiles.Add(filePath);

        _exporter.ExportToCsv(flows, filePath, "normal");

        Assert.True(File.Exists(filePath));
        var content = File.ReadAllText(filePath);
        Assert.NotEmpty(content);
    }

    [Fact]
    public void ExportToCsv_ShouldIncludeHeader()
    {
        var flows = CreateTestFlows();
        var filePath = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.csv");
        _tempFiles.Add(filePath);

        _exporter.ExportToCsv(flows, filePath);

        var lines = File.ReadAllLines(filePath);
        Assert.NotEmpty(lines);
        
        var header = lines[0];
        Assert.Contains("src_ip", header);
        Assert.Contains("dst_ip", header);
        Assert.Contains("packet_count", header);
        Assert.Contains("label", header);
    }

    [Fact]
    public void ExportToCsv_ShouldIncludeFlowData()
    {
        var flows = CreateTestFlows();
        var filePath = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.csv");
        _tempFiles.Add(filePath);

        _exporter.ExportToCsv(flows, filePath);

        var lines = File.ReadAllLines(filePath);
        Assert.Equal(2, lines.Length); // Header + 1 flow
        
        var dataLine = lines[1];
        Assert.Contains("192.168.1.1", dataLine);
        Assert.Contains("10.0.0.1", dataLine);
    }

    [Fact]
    public void ExportToCsv_ShouldApplyLabel()
    {
        var flows = CreateTestFlows();
        var filePath = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.csv");
        _tempFiles.Add(filePath);

        _exporter.ExportToCsv(flows, filePath, "attack");

        var lines = File.ReadAllLines(filePath);
        var dataLine = lines[1];
        
        Assert.EndsWith("attack", dataLine);
    }

    [Fact]
    public void ExportToJson_ShouldCreateValidFile()
    {
        var flows = CreateTestFlows();
        var filePath = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.json");
        _tempFiles.Add(filePath);

        _exporter.ExportToJson(flows, filePath);

        Assert.True(File.Exists(filePath));
        var content = File.ReadAllText(filePath);
        Assert.NotEmpty(content);
        Assert.Contains("[", content);
    }

    [Fact]
    public void ExportToJson_ShouldcontainFlowData()
    {
        var flows = CreateTestFlows();
        var filePath = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.json");
        _tempFiles.Add(filePath);

        _exporter.ExportToJson(flows, filePath);

        var content = File.ReadAllText(filePath);
        Assert.Contains("192.168.1.1", content);
        Assert.Contains("10.0.0.1", content);
        Assert.Contains("packet_count", content);
    }

    [Fact]
    public void ExportFeaturesToCsv_ShouldCreateValidFile()
    {
        var features = CreateTestFeatures();
        var filePath = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.csv");
        _tempFiles.Add(filePath);

        _exporter.ExportFeaturesToCsv(features, filePath);

        Assert.True(File.Exists(filePath));
        var content = File.ReadAllText(filePath);
        Assert.NotEmpty(content);
    }

    [Fact]
    public void ExportFeaturesToCsv_ShouldIncludeNormalizedValues()
    {
        var features = CreateTestFeatures();
        var filePath = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.csv");
        _tempFiles.Add(filePath);

        _exporter.ExportFeaturesToCsv(features, filePath);

        var lines = File.ReadAllLines(filePath);
        Assert.True(lines.Length > 1);

        var header = lines[0];
        Assert.Contains("packets_per_sec", header);
        Assert.Contains("bytes_per_sec", header);
        Assert.Contains("label", header);
    }

    [Fact]
    public void ExportToCsv_WithMultipleFlaws_ShouldExportAll()
    {
        var flows = new[]
        {
            CreateFlow("192.168.1.1", "10.0.0.1", 443),
            CreateFlow("192.168.1.2", "10.0.0.2", 80),
            CreateFlow("192.168.1.3", "10.0.0.3", 22)
        };
        
        var filePath = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.csv");
        _tempFiles.Add(filePath);

        _exporter.ExportToCsv(flows, filePath);

        var lines = File.ReadAllLines(filePath);
        Assert.Equal(4, lines.Length); // Header + 3 flows
    }

    [Fact]
    public void ExportToCsv_ShouldVerifyFloatFormatting()
    {
        var flow = new NetworkFlow
        {
            SourceIp = "192.168.1.1",
            DestinationIp = "10.0.0.1",
            FirstSeen = DateTime.UtcNow,
            LastSeen = DateTime.UtcNow.AddSeconds(3.333)
        };

        var filePath = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.csv");
        _tempFiles.Add(filePath);

        _exporter.ExportToCsv(new[] { flow }, filePath);

        var lines = File.ReadAllLines(filePath);
        var dataLine = lines[1];
        
        // Should contain properly formatted float (3 decimals)
        Assert.Contains(",3.3", dataLine);
    }

    private static List<NetworkFlow> CreateTestFlows()
    {
        return new List<NetworkFlow>
        {
            CreateFlow("192.168.1.1", "10.0.0.1", 443)
        };
    }

    private static NetworkFlow CreateFlow(string srcIp, string dstIp, ushort dstPort)
    {
        return new NetworkFlow
        {
            FlowId = $"{srcIp}:{dstIp}:{dstPort}",
            SourceIp = srcIp,
            DestinationIp = dstIp,
            SourcePort = 54321,
            DestinationPort = dstPort,
            Protocol = "TCP",
            FirstSeen = DateTime.UtcNow.AddSeconds(-10),
            LastSeen = DateTime.UtcNow,
            PacketCount = 150,
            ByteCount = 75000,
            SynCount = 2,
            AckCount = 140,
            FinCount = 1,
            RstCount = 0
        };
    }

    private static List<(FeatureVector Features, string Label)> CreateTestFeatures()
    {
        return new List<(FeatureVector, string)>
        {
            (new FeatureVector 
            { 
                PacketsPerSecond = 0.5f,
                BytesPerSecond = 0.4f,
                AvgPacketSize = 0.6f,
                SynRatio = 0.05f,
                AckRatio = 0.9f,
                FinRstRatio = 0.02f,
                UniquePortsRatio = 0.1f,
                FlowDuration = 0.3f
            }, "normal")
        };
    }

    public void Dispose()
    {
        foreach (var file in _tempFiles)
        {
            if (File.Exists(file))
            {
                File.Delete(file);
            }
        }
    }
}
