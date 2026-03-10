using SharpPcap;
using PacketDotNet;
using SmallNetworkIDS.Core.Models;
using System.Collections.Concurrent;

namespace SmallNetworkIDS.Core.Services;

/// <summary>
/// Captures network packets using SharpPcap and maintains flow state
/// </summary>
public class PacketSniffer : IDisposable
{
    private ILiveDevice? _device;
    private readonly ConcurrentDictionary<string, NetworkFlow> _flows = new();
    private bool _isCapturing;
    
    public event EventHandler<NetworkFlow>? FlowUpdated;
    public event EventHandler<string>? PacketCaptured;
    
    public IReadOnlyDictionary<string, NetworkFlow> ActiveFlows => _flows;
    
    /// <summary>
    /// List available network devices
    /// </summary>
    public static IEnumerable<(int Index, string Name, string Description)> ListDevices()
    {
        var devices = CaptureDeviceList.Instance;
        return devices.Select((d, i) => (i, d.Name, d.Description ?? "No description"));
    }
    
    /// <summary>
    /// Start capturing on the specified device
    /// </summary>
    public void StartCapture(int deviceIndex, string? filter = null)
    {
        var devices = CaptureDeviceList.Instance;
        
        if (deviceIndex < 0 || deviceIndex >= devices.Count)
            throw new ArgumentException($"Invalid device index. Available: 0-{devices.Count - 1}");
        
        _device = devices[deviceIndex];
        _device.OnPacketArrival += OnPacketArrival;
        
        _device.Open(DeviceModes.Promiscuous, 1000);
        
        if (!string.IsNullOrWhiteSpace(filter))
        {
            _device.Filter = filter;
        }
        
        _isCapturing = true;
        _device.StartCapture();
    }
    
    /// <summary>
    /// Stop capturing
    /// </summary>
    public void StopCapture()
    {
        if (_device == null || !_isCapturing) return;
        
        _isCapturing = false;
        _device.StopCapture();
        _device.Close();
    }
    
    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket == null) return;
            
            var tcpPacket = packet.Extract<TcpPacket>();
            var udpPacket = packet.Extract<UdpPacket>();
            
            string srcIp = ipPacket.SourceAddress.ToString();
            string dstIp = ipPacket.DestinationAddress.ToString();
            ushort srcPort = 0;
            ushort dstPort = 0;
            string protocol = "IP";
            
            bool isSyn = false, isAck = false, isFin = false, isRst = false;
            
            if (tcpPacket != null)
            {
                srcPort = tcpPacket.SourcePort;
                dstPort = tcpPacket.DestinationPort;
                protocol = "TCP";
                isSyn = tcpPacket.Synchronize;
                isAck = tcpPacket.Acknowledgment;
                isFin = tcpPacket.Finished;
                isRst = tcpPacket.Reset;
            }
            else if (udpPacket != null)
            {
                srcPort = udpPacket.SourcePort;
                dstPort = udpPacket.DestinationPort;
                protocol = "UDP";
            }
            
            var flowId = NetworkFlow.GenerateFlowId(srcIp, dstIp, srcPort, dstPort, protocol);
            var now = DateTime.UtcNow;
            
            var flow = _flows.AddOrUpdate(
                flowId,
                _ => new NetworkFlow
                {
                    FlowId = flowId,
                    SourceIp = srcIp,
                    DestinationIp = dstIp,
                    SourcePort = srcPort,
                    DestinationPort = dstPort,
                    Protocol = protocol,
                    FirstSeen = now,
                    LastSeen = now,
                    PacketCount = 1,
                    ByteCount = rawPacket.Data.Length,
                    SynCount = isSyn ? 1 : 0,
                    AckCount = isAck ? 1 : 0,
                    FinCount = isFin ? 1 : 0,
                    RstCount = isRst ? 1 : 0
                },
                (_, existing) =>
                {
                    existing.LastSeen = now;
                    existing.PacketCount++;
                    existing.ByteCount += rawPacket.Data.Length;
                    if (isSyn) existing.SynCount++;
                    if (isAck) existing.AckCount++;
                    if (isFin) existing.FinCount++;
                    if (isRst) existing.RstCount++;
                    return existing;
                });
            
            PacketCaptured?.Invoke(this, $"{srcIp}:{srcPort} -> {dstIp}:{dstPort} [{protocol}]");
            FlowUpdated?.Invoke(this, flow);
        }
        catch
        {
            // Silently ignore malformed packets
        }
    }
    
    /// <summary>
    /// Get and clear flows older than specified duration
    /// </summary>
    public IEnumerable<NetworkFlow> HarvestExpiredFlows(TimeSpan maxAge)
    {
        var cutoff = DateTime.UtcNow - maxAge;
        var expired = _flows.Where(kv => kv.Value.LastSeen < cutoff).ToList();
        
        foreach (var kv in expired)
        {
            if (_flows.TryRemove(kv.Key, out var flow))
            {
                yield return flow;
            }
        }
    }
    
    public void Dispose()
    {
        StopCapture();
        _device?.Dispose();
    }
}
