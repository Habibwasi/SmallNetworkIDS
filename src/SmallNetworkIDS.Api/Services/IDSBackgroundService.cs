using SmallNetworkIDS.Core.Models;
using SmallNetworkIDS.Core.Services;

namespace SmallNetworkIDS.Api.Services;

/// <summary>
/// Background service that runs the packet sniffer and IDS analysis
/// </summary>
public class IDSBackgroundService : BackgroundService
{
    private readonly ILogger<IDSBackgroundService> _logger;
    private readonly FeatureExtractor _featureExtractor;
    private readonly MlInferenceEngine _mlEngine;
    private readonly AlertManager _alertManager;
    private readonly IDSService _idsService;
    private PacketSniffer? _sniffer;

    public IDSBackgroundService(
        ILogger<IDSBackgroundService> logger,
        FeatureExtractor featureExtractor,
        MlInferenceEngine mlEngine,
        AlertManager alertManager,
        IDSService idsService)
    {
        _logger = logger;
        _featureExtractor = featureExtractor;
        _mlEngine = mlEngine;
        _alertManager = alertManager;
        _idsService = idsService;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("IDS Background Service starting...");
        await Task.Delay(2000, stoppingToken); // Let the API start first

        try
        {
            _sniffer = new PacketSniffer();
            
            // Get available devices
            var devices = PacketSniffer.ListDevices().ToList();
            _logger.LogInformation("Found {deviceCount} network interfaces", devices.Count);
            
            if (!devices.Any())
            {
                _logger.LogWarning("No network interfaces available for packet capture - generating test data");
                await GenerateTestDataAsync(stoppingToken);
                return;
            }

            // Use first available device
            var (deviceIndex, _, desc) = devices.First();
            _logger.LogInformation("Starting packet capture on device {device}: {description}", deviceIndex, desc);

            // Start capture in background with timeout
            var captureTask = Task.Run(() =>
            {
                try
                {
                    _logger.LogInformation("Initializing packet capture...");
                    _sniffer.StartCapture(deviceIndex, null);
                    _logger.LogInformation("Packet capture initialized successfully");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during packet capture initialization");
                }
            }, stoppingToken);

            // Analysis loop - runs periodically
            int analysisCount = 0;
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
                    analysisCount++;

                    if (_sniffer?.ActiveFlows?.Count > 0)
                    {
                        // Harvest and analyze expired flows
                        var expiredFlows = _sniffer.HarvestExpiredFlows(TimeSpan.FromSeconds(30)).ToList();
                        _logger.LogDebug("Analysis #{count}: Found {expiredCount} expired flows, {activeCount} active flows", 
                            analysisCount, expiredFlows.Count, _sniffer.ActiveFlows.Count);
                        
                        foreach (var flow in expiredFlows)
                        {
                            _idsService.AddFlow(flow);
                            var features = _featureExtractor.ExtractFeatures(flow);
                            var result = _mlEngine.Predict(features);
                            _alertManager.ProcessInferenceResult(flow, features, result);
                        }

                        // Analyze active flows for ongoing attacks
                        var activeFlows = _sniffer.ActiveFlows.Values.Where(f => f.DurationSeconds > 5).ToList();
                        foreach (var flow in activeFlows)
                        {
                            _idsService.AddFlow(flow);
                            var features = _featureExtractor.ExtractFeatures(flow);
                            var result = _mlEngine.Predict(features);

                            if (result.IsAnomaly)
                            {
                                _logger.LogWarning("Anomaly detected: {sourceIp} -> {destIp}, Score: {score}", 
                                    flow.SourceIp, flow.DestinationIp, result.AnomalyScore);
                                _alertManager.ProcessInferenceResult(flow, features, result);
                            }
                        }
                    }
                    else if (analysisCount % 6 == 0) // Log every 30 seconds
                    {
                        _logger.LogDebug("Analysis #{count}: No active flows captured yet", analysisCount);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in IDS analysis loop");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Fatal error in IDS background service");
        }
        finally
        {
            _sniffer?.Dispose();
            _logger.LogInformation("IDS Background Service stopped");
        }
    }

    private async Task GenerateTestDataAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Starting test data generation mode");
        int testCount = 0;
        
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(3), stoppingToken);
                testCount++;

                // Generate synthetic test flow
                var flow = new NetworkFlow
                {
                    SourceIp = $"192.168.1.{10 + (testCount % 10)}",
                    DestinationIp = $"10.0.0.{100 + (testCount % 50)}",
                    SourcePort = (ushort)(50000 + (testCount % 1000)),
                    DestinationPort = (ushort)(80 + (testCount % 3)), // 80, 443, 22
                    Protocol = "TCP",
                    PacketCount = 10 + (testCount % 100),
                    ByteCount = 1000 + (testCount % 10000),
                    FirstSeen = DateTime.UtcNow.AddSeconds(-5),
                    LastSeen = DateTime.UtcNow,
                    SynCount = 1,
                    AckCount = 1
                };
                
                flow.FlowId = NetworkFlow.GenerateFlowId(flow.SourceIp, flow.DestinationIp, flow.SourcePort, flow.DestinationPort, flow.Protocol);

                _idsService.AddFlow(flow);
                var features = _featureExtractor.ExtractFeatures(flow);
                var result = _mlEngine.Predict(features);
                _alertManager.ProcessInferenceResult(flow, features, result);

                _logger.LogInformation("Generated test flow #{count}: {source} -> {dest}", 
                    testCount, flow.SourceIp, flow.DestinationIp);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in test data generation");
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("IDS Background Service stopping...");
        _sniffer?.Dispose();
        await base.StopAsync(cancellationToken);
    }
}
