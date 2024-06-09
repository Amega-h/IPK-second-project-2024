using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet;
using SharpPcap;

namespace Sniffer;

public static class ParsePacket
{
    //counter needed to trace number of packets printed
    public static int Counter = 0;
    public static void Parse(TcpPacket packet,RawCapture rawPacket)
    {
        if (Arguments.Tcp)
        {
            //necessary data to print extraction
            DateTime arrivalTime = rawPacket.Timeval.Date;
            int packetLength = rawPacket.PacketLength;
            byte[]? data = rawPacket.Data;
            var ipvBasePacket = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            IPv4Packet ipv4Packet = ipvBasePacket.Extract<IPv4Packet>();
            IPv6Packet ipv6Packet = ipvBasePacket.Extract<IPv6Packet>();
            IPAddress srcAddress;
            IPAddress dstAddress;
            //IP version check
            if (ipv4Packet == null)
            {
                srcAddress = ipv6Packet.SourceAddress;
                dstAddress = ipv6Packet.DestinationAddress;
            }
            else
            {
                srcAddress = ipv4Packet.SourceAddress;
                dstAddress = ipv4Packet.DestinationAddress; 
            }
            ushort srcPort = packet.SourcePort;
            ushort dstPort = packet.DestinationPort;
            //print itself
            Console.WriteLine($"timestamp :{arrivalTime.ToString("yyyy-MM-ddT:HH:mm:ss.fffzzz",DateTimeFormatInfo.CurrentInfo)}\n");
            Console.WriteLine($"frame length: {packetLength} bytes\n");
            Console.WriteLine($"src IP: {srcAddress.ToString()}\n");
            Console.WriteLine($"dst IP: {dstAddress.ToString()}\n");
            Console.WriteLine($"src port: {srcPort}\n");
            Console.WriteLine($"dst port: {dstPort}\n");
            DataHandler.PrintData(data);

            Counter++;
        }
    }
    //Parse function override by packet type it gets
    public static void Parse(UdpPacket packet,RawCapture rawPacket)
    {
        if (Arguments.Udp)
        {
            //necessary data to print extraction
            DateTime arrivalTime = rawPacket.Timeval.Date;
            int packetLength = rawPacket.PacketLength;
            byte[]? data = rawPacket.Data;
            var ipvBasePacket = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            IPv4Packet ipv4Packet = ipvBasePacket.Extract<IPv4Packet>();
            IPv6Packet ipv6Packet = ipvBasePacket.Extract<IPv6Packet>();
            IPAddress srcAddress;
            IPAddress dstAddress;
            //IP version check
            if (ipv4Packet == null)
            {
                srcAddress = ipv6Packet.SourceAddress;
                dstAddress = ipv6Packet.DestinationAddress;
            }
            else
            {
                srcAddress = ipv4Packet.SourceAddress;
                dstAddress = ipv4Packet.DestinationAddress; 
            }
            ushort srcPort = packet.SourcePort;
            ushort dstPort = packet.DestinationPort;
            //print itself
            Console.WriteLine($"timestamp :{arrivalTime.ToString("yyyy-MM-ddT:HH:mm:ss.fffzzz",DateTimeFormatInfo.CurrentInfo)}\n");
            Console.WriteLine($"frame length: {packetLength} bytes\n");
            Console.WriteLine($"src IP: {srcAddress.ToString()}\n");
            Console.WriteLine($"dst IP: {dstAddress.ToString()}\n");
            Console.WriteLine($"src port: {srcPort}\n");
            Console.WriteLine($"dst port: {dstPort}\n");
            DataHandler.PrintData(data);
            Counter++;
        }
    }
    //Parse function override by packet type it gets
    public static void Parse(NdpPacket packet,RawCapture rawPacket)
    {
        if (Arguments.Ndp)
        {
            //necessary data to print extraction
            DateTime arrivalTime = rawPacket.Timeval.Date;
            int packetLength = rawPacket.PacketLength;
            byte[]? data = rawPacket.Data;
            var ipv6BasePacket = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            IPv6Packet ipv6Packet = ipv6BasePacket.Extract<IPv6Packet>();
            IPAddress srcAddress = ipv6Packet.SourceAddress;
            IPAddress dstAddress = ipv6Packet.DestinationAddress;
            //print itself
            Console.WriteLine($"timestamp :{arrivalTime.ToString("yyyy-MM-ddT:HH:mm:ss.fffzzz",DateTimeFormatInfo.CurrentInfo)}\n");
            Console.WriteLine($"frame length: {packetLength} bytes\n");
            Console.WriteLine($"src IP: {srcAddress.ToString()}\n");
            Console.WriteLine($"dst IP: {dstAddress.ToString()}\n");
            DataHandler.PrintData(data);
            Counter++;
        }
    }
    //Parse function override by packet type it gets
    public static void Parse(ArpPacket packet,RawCapture rawPacket)
    {
        if (Arguments.Arp)
        {
            //necessary data to print extraction
            DateTime arrivalTime = rawPacket.Timeval.Date;
            int packetLength = rawPacket.PacketLength;
            byte[]? data = rawPacket.Data;
            IPAddress srcAddress = packet.SenderProtocolAddress;
            IPAddress dstAddress = packet.TargetProtocolAddress;
            PhysicalAddress srcMACAdress = packet.SenderHardwareAddress;
            PhysicalAddress dstMACAdress = packet.TargetHardwareAddress;
            //print itself
            Console.WriteLine($"timestamp :{arrivalTime.ToString("yyyy-MM-ddT:HH:mm:ss.fffzzz",DateTimeFormatInfo.CurrentInfo)}\n");
            Console.WriteLine($"frame length: {packetLength} bytes\n");
            Console.WriteLine($"src IP: {srcAddress.ToString()}\n");
            Console.WriteLine($"dst IP: {dstAddress.ToString()}\n");
            Console.WriteLine($"src MAC: {DataHandler.GetMACString(srcMACAdress)}\n");
            Console.WriteLine($"dst MAC: {DataHandler.GetMACString(dstMACAdress)}\n");
            DataHandler.PrintData(data);
            Counter++;
        }
    }
    //Parse function override by packet type it gets
    public static void Parse(IcmpV6Packet packet,RawCapture rawPacket)
    {
        if (Arguments.Icmp6 || Arguments.Mld)
        {
            if (((packet.Type == IcmpV6Type.MulticastListenerReport) ||
                 (packet.Type == IcmpV6Type.Version2MulticastListenerReport)))
            {
                if (Arguments.Mld)
                {
                    //necessary data to print extraction
                    DateTime arrivalTime_mld = rawPacket.Timeval.Date; 
                    int packetLength_mld = rawPacket.PacketLength;
                    byte[]? data_mld = rawPacket.Data;
                    var ipv6BasePacket_mld = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                    IPv6Packet ipv6Packet_mld = ipv6BasePacket_mld.Extract<IPv6Packet>();
                    IPAddress srcAddress_mld = ipv6Packet_mld.SourceAddress;
                    IPAddress dstAddress_mld = ipv6Packet_mld.DestinationAddress;
                    //print itself
                    Console.WriteLine($"timestamp :{arrivalTime_mld.ToString("yyyy-MM-ddT:HH:mm:ss.fffzzz",DateTimeFormatInfo.CurrentInfo)}\n");
                    Console.WriteLine($"frame length: {packetLength_mld} bytes\n");
                    Console.WriteLine($"src IP: {srcAddress_mld.ToString()}\n");
                    Console.WriteLine($"dst IP: {dstAddress_mld.ToString()}\n");
                    DataHandler.PrintData(data_mld);
                    return;
                } else return;
            }
            //necessary data to print extraction
            DateTime arrivalTime = rawPacket.Timeval.Date;
            int packetLength = rawPacket.PacketLength;
            byte[]? data = rawPacket.Data;
            var ipv6BasePacket = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            IPv6Packet ipv6Packet = ipv6BasePacket.Extract<IPv6Packet>();
            IPAddress srcAddress = ipv6Packet.SourceAddress;
            IPAddress dstAddress = ipv6Packet.DestinationAddress;
            //print itself
            Console.WriteLine($"timestamp :{arrivalTime.ToString("yyyy-MM-ddT:HH:mm:ss.fffzzz",DateTimeFormatInfo.CurrentInfo)}\n");
            Console.WriteLine($"frame length: {packetLength} bytes\n");
            Console.WriteLine($"src IP: {srcAddress.ToString()}\n");
            Console.WriteLine($"dst IP: {dstAddress.ToString()}\n");
            DataHandler.PrintData(data);
        }
    }
    //Parse function override by packet type it gets
    public static void Parse(IcmpV4Packet packet,RawCapture rawPacket)
    {
        if (Arguments.Icmp4)
        {
            //necessary data to print extraction
            DateTime arrivalTime = rawPacket.Timeval.Date;
            int packetLength = rawPacket.PacketLength;
            byte[]? data = rawPacket.Data;
            var ipv4BasePacket = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            IPv4Packet ipv4Packet = ipv4BasePacket.Extract<IPv4Packet>();
            IPAddress srcAddress = ipv4Packet.SourceAddress;
            IPAddress dstAddress = ipv4Packet.DestinationAddress;
            //print itself
            Console.WriteLine($"timestamp :{arrivalTime.ToString("yyyy-MM-ddT:HH:mm:ss.fffzzz",DateTimeFormatInfo.CurrentInfo)}\n");
            Console.WriteLine($"frame length: {packetLength} bytes\n");
            Console.WriteLine($"src IP: {srcAddress.ToString()}\n");
            Console.WriteLine($"dst IP: {dstAddress.ToString()}\n");
            DataHandler.PrintData(data);
        }
    }
    //Parse function override by packet type it gets
    public static void Parse(IgmpPacket packet,RawCapture rawPacket)
    {
        if (Arguments.Igmp)
        {
            //necessary data to print extraction
            DateTime arrivalTime = rawPacket.Timeval.Date;
            int packetLength = rawPacket.PacketLength;
            byte[]? data = rawPacket.Data;
            var ipv4BasePacket = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            IPv4Packet ipv4Packet = ipv4BasePacket.Extract<IPv4Packet>();
            IPAddress srcAddress = ipv4Packet.SourceAddress;
            IPAddress dstAddress = ipv4Packet.DestinationAddress;
            //print itself
            Console.WriteLine($"timestamp :{arrivalTime.ToString("yyyy-MM-ddT:HH:mm:ss.fffzzz",DateTimeFormatInfo.CurrentInfo)}\n");
            Console.WriteLine($"frame length: {packetLength} bytes\n");
            Console.WriteLine($"src IP: {srcAddress.ToString()}\n");
            Console.WriteLine($"dst IP: {dstAddress.ToString()}\n");
            DataHandler.PrintData(data);
        }
    }
}