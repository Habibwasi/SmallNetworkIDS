using SmallNetworkIDS.Core.Services;

namespace SmallNetworkIDS.Core;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("╔══════════════════════════════════════════╗");
        Console.WriteLine("║     SmallNetworkIDS - Intrusion Detector ║");
        Console.WriteLine("║     Port Scan & DDoS Detection           ║");
        Console.WriteLine("╚══════════════════════════════════════════╝");
        Console.WriteLine();
        
        // Initialize services
        var featureExtractor = new FeatureExtractor();
        var mlEngine = new MlInferenceEngine(featureExtractor);
        var alertManager = new AlertManager();
        
        // Try to load ML model if exists
        var modelPath = args.Length > 0 ? args[0] : "model.onnx";
        mlEngine.LoadModel(modelPath);
        
        // List available network interfaces
        Console.WriteLine("Available network interfaces:");
        foreach (var (index, name, desc) in PacketSniffer.ListDevices())
        {
            Console.WriteLine($"  [{index}] {desc}");
            Console.WriteLine($"      {name}");
        }
        Console.WriteLine();
        
        // Select interface
        Console.Write("Select interface number (or press Enter for 0): ");
        var input = Console.ReadLine();
        var deviceIndex = string.IsNullOrWhiteSpace(input) ? 0 : int.Parse(input);
        
        // Optional filter
        Console.Write("BPF filter (e.g., 'tcp', 'port 80', or press Enter for all): ");
        var filter = Console.ReadLine();
        
        Console.WriteLine();
        Console.WriteLine($"[*] Starting capture on interface {deviceIndex}...");
        Console.WriteLine("[*] Press Ctrl+C to stop");
        Console.WriteLine();
        
        using var sniffer = new PacketSniffer();
        var cts = new CancellationTokenSource();
        
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        
        // Analysis task - runs periodically
        var analysisTask = Task.Run(async () =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(5), cts.Token).ConfigureAwait(false);
                
                // Harvest and analyze flows
                foreach (var flow in sniffer.HarvestExpiredFlows(TimeSpan.FromSeconds(30)))
                {
                    var features = featureExtractor.ExtractFeatures(flow);
                    var (score, alertType) = mlEngine.Predict(features);
                    alertManager.ProcessInferenceResult(flow, features, score, alertType);
                }
                
                // Also check active flows for ongoing attacks
                foreach (var flow in sniffer.ActiveFlows.Values.Where(f => f.DurationSeconds > 5))
                {
                    var features = featureExtractor.ExtractFeatures(flow);
                    var (score, alertType) = mlEngine.Predict(features);
                    
                    if (score >= alertManager.AnomalyThreshold)
                    {
                        alertManager.ProcessInferenceResult(flow, features, score, alertType);
                    }
                }
                
                // Status update
                Console.Write($"\r[{DateTime.Now:HH:mm:ss}] Active flows: {sniffer.ActiveFlows.Count}    ");
            }
        }, cts.Token);
        
        // Start capture
        try
        {
            sniffer.StartCapture(deviceIndex, string.IsNullOrWhiteSpace(filter) ? null : filter);
            
            await analysisTask;
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n[ERROR] {ex.Message}");
            Console.WriteLine("\nNote: Packet capture requires administrator/root privileges.");
            Console.WriteLine("Run: dotnet run -- as Administrator");
        }
        finally
        {
            sniffer.StopCapture();
        }
        
        Console.WriteLine("\n[*] Capture stopped.");
        
        // Print summary
        var alerts = alertManager.GetRecentAlerts(10).ToList();
        if (alerts.Count != 0)
        {
            Console.WriteLine($"\n[*] Last {alerts.Count} alerts:");
            foreach (var alert in alerts)
            {
                Console.WriteLine($"    {alert}");
            }
        }
        
        mlEngine.Dispose();
    }
}
