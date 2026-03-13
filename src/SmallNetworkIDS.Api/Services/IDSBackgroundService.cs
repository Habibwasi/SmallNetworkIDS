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

        try
        {
            _sniffer = new PacketSniffer();
            
            // Get available devices
            var devices = PacketSniffer.ListDevices().ToList();
            if (!devices.Any())
            {
                _logger.LogWarning("No network interfaces available for packet capture");
                return;
            }

            // Use first available device
            var (deviceIndex, _, desc) = devices.First();
            _logger.LogInformation("Starting packet capture on device {device}: {description}", deviceIndex, desc);

            // Start capture in background
            var captureTask = Task.Run(() =>
            {
                try
                {
                    _sniffer.StartCapture(deviceIndex, null);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during packet capture");
                }
            });

            // Analysis loop - runs periodically
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);

                    // Harvest and analyze expired flows
                    var expiredFlows = _sniffer.HarvestExpiredFlows(TimeSpan.FromSeconds(30));
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
                            _alertManager.ProcessInferenceResult(flow, features, result);
                        }
                    }

                    _logger.LogDebug("Active flows: {count}", _sniffer.ActiveFlows.Count);
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

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("IDS Background Service stopping...");
        _sniffer?.Dispose();
        await base.StopAsync(cancellationToken);
    }
}
