namespace Sniffer;

public static class Arguments
{
    public static string? I = null;
    public static bool I_Device = false;
    public static int N = 1;
    public static bool Tcp = false;
    public static bool Udp = false;
    public static int? P = null;
    public static int? PortDst = null;
    public static int? PortSrc = null;
    public static bool Icmp4 = false;
    public static bool Icmp6 = false;
    public static bool Arp = false;
    public static bool Ndp = false;
    public static bool Igmp = false;
    public static bool Mld = false;

    public static void PrintHelp()
    {
        Console.WriteLine("./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n"+
                          "-i [eth0] (just one interface to sniff) or --interface. If this parameter is not specified (and any other parameters as well), or if only -i/--interface is specified without a value "+
                          "(and any other parameters are unspecified), a list of active interfaces is printed (additional information beyond the interface list is welcome but not required).\n" +
                          "-t|--tcp will display TCP segments and is optionally complemented by -p or --port-* functionality.\n"+
                          "-u|--udp will display UDP datagrams and is optionally complemented by-p or --port-* functionality.\n"+
                          "-p|--port-destination|--port-source [port] extends previous two parameters to filter TCP/UDP based on port number; if this parameter is not present, then no filtering by port number occurs; if the parameter is given, the given port can occur in source OR destination part of TCP/UDP headers.\n"+
                          "--icmp4 will display only ICMPv4 packets.\n"+
                          "--icmp6 will display only ICMPv6 echo request/response.\n"+
                          "--arp will display only ARP frames.\n"+
                          "--ndp will display only NDP packets, subset of ICMPv6.\n"+
                          "--igmp will display only IGMP packets.\n"+
                          "--mld will display only MLD packets, subset of ICMPv6.\n"+
                          "-n 10 specifies the number of packets to display, i.e., the \"time\" the program runs; if not specified, consider displaying only one packet, i.e., as if -n 1\n"+
                          "All arguments can be in any order.\n");
    }

    public static void DebugPrintArgs()
    {
        Console.WriteLine($"I: {Arguments.I}\n"+
                          $"I_Device : {Arguments.I_Device}\n"+
                          $"N: {Arguments.N}\n"+
                          $"TCP: {Arguments.Tcp}\n"+
                          $"UDP: {Arguments.Udp}\n"+
                          $"P: {Arguments.P}\n"+
                          $"PortDst: {Arguments.PortDst}\n"+
                          $"PortSrc: {Arguments.PortSrc}\n"+
                          $"Icmp4: {Arguments.Icmp4}\n"+
                          $"Icmp6: {Arguments.Icmp6}\n"+
                          $"Arp: {Arguments.Arp}\n"+
                          $"Ndp: {Arguments.Ndp}\n"+
                          $"Igmp: {Arguments.Igmp}\n"+
                          $"Mld: {Arguments.Mld}\n");
    }
    
}