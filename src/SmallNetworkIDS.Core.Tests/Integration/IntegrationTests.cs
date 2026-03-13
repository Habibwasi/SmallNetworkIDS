using SmallNetworkIDS.Core.Models;
using SmallNetworkIDS.Core.Services;
using Xunit;

namespace SmallNetworkIDS.Core.Tests.Integration;

public class IntegrationTests
{
    [Fact]
    public void CompleteDetectionPipeline_NormalTraffic_ShouldNotRaiseAlert()
    {
        var featureExtractor = new FeatureExtractor();
        var mlEngine = new MlInferenceEngine(featureExtractor);
        var alertManager = new AlertManager();

        var normalFlow = new NetworkFlow
        {
            FlowId = "normal-flow",
            SourceIp = "192.168.1.100",
            DestinationIp = "8.8.8.8",
            SourcePort = 54321,
            DestinationPort = 53,
            Protocol = "UDP",
            FirstSeen = DateTime.UtcNow.AddSeconds(-5),
            LastSeen = DateTime.UtcNow,
            PacketCount = 5,
            ByteCount = 500,
            SynCount = 0,
            AckCount = 0,
            FinCount = 0,
            RstCount = 0
        };

        var features = featureExtractor.ExtractFeatures(normalFlow);
        var result = mlEngine.Predict(features);
        var alert = alertManager.ProcessInferenceResult(normalFlow, features, result);

        Assert.Null(alert);
    }

    [Fact]
    public void CompleteDetectionPipeline_DDoSTraffic_ShouldRaiseAlert()
    {
        var featureExtractor = new FeatureExtractor();
        var mlEngine = new MlInferenceEngine(featureExtractor);
        var alertManager = new AlertManager();

        var ddosFlow = new NetworkFlow
        {
            FlowId = "ddos-flow",
            SourceIp = "192.0.2.1",
            DestinationIp = "192.168.1.10",
            SourcePort = 12345,
            DestinationPort = 80,
            Protocol = "TCP",
            FirstSeen = DateTime.UtcNow.AddSeconds(-5),
            LastSeen = DateTime.UtcNow,
            PacketCount = 50000,
            ByteCount = 25_000_000,
            SynCount = 40000,
            AckCount = 5000,
            FinCount = 0,
            RstCount = 0
        };

        var features = featureExtractor.ExtractFeatures(ddosFlow);
        var result = mlEngine.Predict(features);

        Assert.True(result.IsAnomaly || result.AnomalyScore > 0.5);
    }

    [Fact]
    public void CompleteDetectionPipeline_PortScan_ShouldDetectMultiplePorts()
    {
        var featureExtractor = new FeatureExtractor();

        var sourceIp = "192.0.2.100";
        var targetIp = "192.168.1.1";

        // Simulate port scan across multiple ports
        var ports = new[] { 22, 80, 443, 3306, 5432, 8080 };

        foreach (var port in ports)
        {
            var scanFlow = new NetworkFlow
            {
                FlowId = $"{sourceIp}:{port}",
                SourceIp = sourceIp,
                DestinationIp = targetIp,
                DestinationPort = (ushort)port,
                FirstSeen = DateTime.UtcNow,
                LastSeen = DateTime.UtcNow.AddSeconds(1),
                PacketCount = 1,
                SynCount = 1
            };

            featureExtractor.ExtractFeatures(scanFlow);
        }

        var (isPortScan, portCount) = featureExtractor.CheckPortScan(sourceIp, threshold: 5);

        Assert.True(isPortScan);
        Assert.True(portCount >= 5);
    }

    [Fact]
    public void DataExportAndReimport_ShouldPreserveData()
    {
        var exporter = new DataExporter();
        var tempFile = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.csv");

        try
        {
            var flows = new[]
            {
                new NetworkFlow
                {
                    SourceIp = "192.168.1.1",
                    DestinationIp = "10.0.0.1",
                    SourcePort = 54321,
                    DestinationPort = 443,
                    Protocol = "TCP",
                    PacketCount = 100,
                    ByteCount = 50000,
                    FirstSeen = DateTime.UtcNow.AddSeconds(-10),
                    LastSeen = DateTime.UtcNow
                }
            };

            exporter.ExportToCsv(flows, tempFile, "normal");

            var lines = File.ReadAllLines(tempFile);
            
            Assert.True(lines.Length > 1);
            var dataLine = lines[1];
            Assert.Contains("192.168.1.1", dataLine);
            Assert.Contains("10.0.0.1", dataLine);
            Assert.Contains("100", dataLine); // packet count
            Assert.Contains("normal", dataLine); // label
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void AlertManager_ShouldTrackMultipleAlerts()
    {
        var alertManager = new AlertManager();
        var alertCount = 0;

        alertManager.AlertRaised += (s, e) => alertCount++;

        var alertTypes = new[] { AlertType.PortScan, AlertType.DDoSFlood, AlertType.SynFlood };

        foreach (var alertType in alertTypes)
        {
            var alert = new AlertEvent
            {
                Type = alertType,
                Severity = AlertSeverity.High,
                SourceIp = "192.0.2.1",
                DestinationIp = "192.168.1.1",
                Description = "Test alert",
                AnomalyScore = 0.75
            };

            alertManager.RaiseAlert(alert);
        }

        Assert.Equal(3, alertCount);
    }

    private static (string SourceIp, string DestinationIp, AlertType Type) CreateAttackFlow(
        string srcIp, string dstIp, AlertType alertType)
    {
        return (srcIp, dstIp, alertType);
    }

    [Fact]
    public void AlertManager_ShouldSupportAllAlertTypes()
    {
        var alertManager = new AlertManager();
        var alertTypes = new[] { AlertType.PortScan, AlertType.DDoSFlood, AlertType.SynFlood, AlertType.AnomalousTraffic };

        foreach (var alertType in alertTypes)
        {
            var alert = new AlertEvent
            {
                Type = alertType,
                Severity = AlertSeverity.High,
                SourceIp = "192.0.2.1",
                DestinationIp = "192.168.1.1",
                Description = $"Test {alertType} alert",
                AnomalyScore = 0.75
            };

            alertManager.RaiseAlert(alert);
        }
    }
}
