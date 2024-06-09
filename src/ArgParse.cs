namespace Sniffer;

public static class ArgParse
{
    //default switch .. case type of argument parsing
    public static bool Parse(string[] args)
    {
        bool noError = true;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h":
                    Arguments.PrintHelp();
                    break;
                case "--interface":
                case "-i" :
                    if ((i + 1) == args.Length)
                    {
                        Arguments.I_Device = true;
                        break;
                    }
                    if (args[i + 1][0] == '-')
                    {
                        Arguments.I_Device = true;
                        break;
                    }
                    Arguments.I = args[i + 1];
                    i++;
                    break;
                case "-t":
                case "--tcp":
                    Arguments.Tcp = true;
                    break;
                case "-u":
                case "--udp":
                    Arguments.Udp = true;
                    break;
                case "-p":
                    if (Arguments.PortDst != null || Arguments.PortSrc != null)
                    {
                        noError = false;
                        break;
                    }
                    if ((i + 2) > args.Length)
                    {
                        noError = false;
                        break;
                    }
                    int number_p;
                    bool check_p = int.TryParse(args[i+1],out number_p);
                    if (!check_p)
                    {
                        noError = false;
                        break;
                    }
                    Arguments.P = number_p;
                    i++;
                    break;
                case "--port-destination":
                    if (Arguments.P != null)
                    {
                        noError = false;
                        break;
                    }
                    if ((i + 2) > args.Length)
                    {
                        noError = false;
                        break;
                    }
                    int number_pd;
                    bool check_pd = int.TryParse(args[i+1],out number_pd);
                    if (!check_pd)
                    {
                        noError = false;
                        break;
                    }
                    Arguments.PortDst = number_pd;
                    i++;
                    break;
                case "--port-source":
                    if (Arguments.P != null)
                    {
                        noError = false;
                        break;
                    }
                    if ((i + 2) > args.Length)
                    {
                        noError = false;
                        break;
                    }
                    int number_src;
                    bool check_src = int.TryParse(args[i+1],out number_src);
                    if (!check_src)
                    {
                        noError = false;
                        break;
                    }
                    Arguments.PortSrc = number_src;
                    i++;
                    break;
                case "--icmp4":
                    Arguments.Icmp4 = true;
                    break;
                case "--icmp6":
                    Arguments.Icmp6 = true;
                    break;
                case "--arp":
                    Arguments.Arp = true;
                    break;
                case "--ndp":
                    Arguments.Ndp = true;
                    break;
                case "--igmp":
                    Arguments.Igmp = true;
                    break;
                case "--mld":
                    Arguments.Mld = true;
                    break;
                case "-n":
                    if ((i + 2) > args.Length)
                    {
                        noError = false;
                        break;
                    }
                    int number_n;
                    bool check_n = int.TryParse(args[i+1],out number_n);
                    if (!check_n)
                    {
                        noError = false;
                        break;
                    }
                    if (number_n < 1)
                    {
                        noError = false;
                        break;
                    }
                    Arguments.N = number_n;
                    i++;
                    break;
                default:
                    noError = false;
                    break;
            }
        }

        if (!Arguments.Tcp && !Arguments.Udp && !Arguments.Icmp6 && !Arguments.Icmp4 && !Arguments.Arp
            && !Arguments.Ndp && !Arguments.Igmp && !Arguments.Mld)
        {
            Arguments.Tcp = true;
            Arguments.Udp = true;
            Arguments.Icmp6 = true;
            Arguments.Icmp4 = true;
            Arguments.Arp = true;
            Arguments.Ndp = true;
            Arguments.Igmp = true;
            Arguments.Mld = true;
        }
        return noError;
    }
}