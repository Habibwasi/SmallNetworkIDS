using SmallNetworkIDS.Core.Models;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace SmallNetworkIDS.Core.Services;

/// <summary>
/// Exports flow data to CSV/JSON for ML model training
/// </summary>
public class DataExporter
{
    /// <summary>
    /// Export flows to CSV format for Scikit-learn training
    /// </summary>
    public void ExportToCsv(IEnumerable<NetworkFlow> flows, string filePath, string? label = null)
    {
        var flowList = flows.ToList();
        var sb = new StringBuilder();
        
        // Header matching Scikit-learn expectations
        sb.AppendLine("src_ip,dst_ip,src_port,dst_port,protocol,packet_count,byte_count,duration_sec,packets_per_sec,bytes_per_sec,syn_count,ack_count,fin_count,rst_count,label");
        
        foreach (var flow in flowList)
        {
            sb.AppendLine(string.Join(",",
                flow.SourceIp,
                flow.DestinationIp,
                flow.SourcePort,
                flow.DestinationPort,
                flow.Protocol,
                flow.PacketCount,
                flow.ByteCount,
                flow.DurationSeconds.ToString("F3", CultureInfo.InvariantCulture),
                flow.PacketsPerSecond.ToString("F3", CultureInfo.InvariantCulture),
                flow.BytesPerSecond.ToString("F3", CultureInfo.InvariantCulture),
                flow.SynCount,
                flow.AckCount,
                flow.FinCount,
                flow.RstCount,
                label ?? "normal"
            ));
        }
        
        File.WriteAllText(filePath, sb.ToString());
        Console.WriteLine($"[Export] Saved {flowList.Count} flows to {filePath}");
    }

    /// <summary>
    /// Export flows to JSON format
    /// </summary>
    public void ExportToJson(IEnumerable<NetworkFlow> flows, string filePath, string? label = null)
    {
        var records = flows.Select(f => new
        {
            src_ip = f.SourceIp,
            dst_ip = f.DestinationIp,
            src_port = f.SourcePort,
            dst_port = f.DestinationPort,
            protocol = f.Protocol,
            packet_count = f.PacketCount,
            byte_count = f.ByteCount,
            duration_sec = f.DurationSeconds,
            packets_per_sec = f.PacketsPerSecond,
            bytes_per_sec = f.BytesPerSecond,
            syn_count = f.SynCount,
            ack_count = f.AckCount,
            fin_count = f.FinCount,
            rst_count = f.RstCount,
            label = label ?? "normal"
        }).ToList();

        var json = JsonSerializer.Serialize(records, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(filePath, json);
        Console.WriteLine($"[Export] Saved {records.Count} flows to {filePath}");
    }

    /// <summary>
    /// Export normalized feature vectors for direct ML input
    /// </summary>
    public void ExportFeaturesToCsv(IEnumerable<(FeatureVector Features, string Label)> data, string filePath)
    {
        var dataList = data.ToList();
        var sb = new StringBuilder();
        sb.AppendLine("packets_per_sec,bytes_per_sec,avg_packet_size,syn_ratio,ack_ratio,fin_rst_ratio,unique_ports_ratio,flow_duration,label");

        foreach (var (f, label) in dataList)
        {
            sb.AppendLine(string.Join(",",
                f.PacketsPerSecond.ToString("F6", CultureInfo.InvariantCulture),
                f.BytesPerSecond.ToString("F6", CultureInfo.InvariantCulture),
                f.AvgPacketSize.ToString("F6", CultureInfo.InvariantCulture),
                f.SynRatio.ToString("F6", CultureInfo.InvariantCulture),
                f.AckRatio.ToString("F6", CultureInfo.InvariantCulture),
                f.FinRstRatio.ToString("F6", CultureInfo.InvariantCulture),
                f.UniquePortsRatio.ToString("F6", CultureInfo.InvariantCulture),
                f.FlowDuration.ToString("F6", CultureInfo.InvariantCulture),
                label
            ));
        }

        File.WriteAllText(filePath, sb.ToString());
        Console.WriteLine($"[Export] Saved {dataList.Count} feature vectors to {filePath}");
    }

    /// <summary>
    /// Append flows to existing CSV (for continuous data collection)
    /// </summary>
    public void AppendToCsv(IEnumerable<NetworkFlow> flows, string filePath, string? label = null)
    {
        var flowList = flows.ToList();
        if (flowList.Count == 0) return;

        var sb = new StringBuilder();
        
        // Add header only if file doesn't exist
        if (!File.Exists(filePath))
        {
            sb.AppendLine("src_ip,dst_ip,src_port,dst_port,protocol,packet_count,byte_count,duration_sec,packets_per_sec,bytes_per_sec,syn_count,ack_count,fin_count,rst_count,label");
        }
        
        foreach (var flow in flowList)
        {
            sb.AppendLine(string.Join(",",
                flow.SourceIp,
                flow.DestinationIp,
                flow.SourcePort,
                flow.DestinationPort,
                flow.Protocol,
                flow.PacketCount,
                flow.ByteCount,
                flow.DurationSeconds.ToString("F3", CultureInfo.InvariantCulture),
                flow.PacketsPerSecond.ToString("F3", CultureInfo.InvariantCulture),
                flow.BytesPerSecond.ToString("F3", CultureInfo.InvariantCulture),
                flow.SynCount,
                flow.AckCount,
                flow.FinCount,
                flow.RstCount,
                label ?? "normal"
            ));
        }
        
        File.AppendAllText(filePath, sb.ToString());
    }
}
