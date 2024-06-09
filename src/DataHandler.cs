using System.Net.NetworkInformation;

namespace Sniffer;

public static class DataHandler
{
    //print data in right format
    public static void PrintData(byte[]? data)
    {
        if (data == null)
            return;
        for (int i = 0; i < data.Length; i += 16)
        {
            Console.Write($"{i:X8} : ");
                
            for (int j = i; j < Math.Min(i + 16, data.Length); j++)
            {
                Console.Write($"{data[j]:X2} ");
            }

            int remainingBytes = Math.Min(16, data.Length - i);
            for (int j = remainingBytes; j < 16; j++)
            {
                Console.Write("   ");
            }

            for (int j = i; j < Math.Min(i + 16, data.Length); j++)
            {
                char symbol = (char)data[j];
                if (char.IsControl(symbol))
                {
                    Console.Write(".");
                }
                else
                {
                    Console.Write(symbol);
                }
            }

            Console.WriteLine();
        }
    }
    public static string GetMACString(PhysicalAddress address)
    {
        //MAC address formatting 
        string MACAddressString = BitConverter.ToString(address.GetAddressBytes());
        MACAddressString = MACAddressString.Replace("-", ":");
        return MACAddressString;
    }
}