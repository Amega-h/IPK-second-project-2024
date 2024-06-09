using PacketDotNet;
using SharpPcap;

namespace Sniffer;

public class SnifferHandler
{
    public void SniffPacket(Packets packets, Packet packet, PacketCapture e)
    {
        packets.RawPacket = e.GetPacket();
        //packet specified by type extraction
        packets.Tcp = packet.Extract<TcpPacket>();
        if (packets.Tcp != null)
        {
            //packet to parse send
            ParsePacket.Parse(packets.Tcp,packets.RawPacket);
            return;
        }
        packets.Udp = packet.Extract<UdpPacket>();
        if (packets.Udp != null)
        {
            ParsePacket.Parse(packets.Udp,packets.RawPacket);
            return;
        }
        packets.Ndp = packet.Extract<NdpPacket>();
        if (packets.Ndp != null)
        {
            ParsePacket.Parse(packets.Ndp,packets.RawPacket);
            return;
        }
        packets.Arp = packet.Extract<ArpPacket>();
        if (packets.Arp != null)
        {
            ParsePacket.Parse(packets.Arp,packets.RawPacket);
            return;
        }
        packets.Icmp6 = packet.Extract<IcmpV6Packet>();
        if (packets.Icmp6 != null)
        {
            ParsePacket.Parse(packets.Icmp6,packets.RawPacket);
            return;
        }
        packets.Icmp4 = packet.Extract<IcmpV4Packet>();
        if (packets.Icmp4 != null)
        {
            ParsePacket.Parse(packets.Icmp4,packets.RawPacket);
            return;
        }
            
        packets.Igmp = packet.Extract<IgmpPacket>();
        if (packets.Igmp != null)
        {
            ParsePacket.Parse(packets.Igmp,packets.RawPacket);
        }
    }
}