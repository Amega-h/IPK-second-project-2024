using PacketDotNet;
using SharpPcap;

namespace Sniffer;

public class Packets
{
    public RawCapture? RawPacket = null;
    public TcpPacket? Tcp = null;
    public UdpPacket? Udp = null;
    public IcmpV4Packet? Icmp4 = null;
    public IcmpV6Packet? Icmp6 = null;
    public ArpPacket? Arp = null;
    public NdpPacket? Ndp = null;
    public IgmpPacket? Igmp = null;
    public IcmpV6Packet? Mld = null;
    
}