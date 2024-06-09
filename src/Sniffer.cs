using PacketDotNet;
using SharpPcap;
namespace Sniffer;

public class Sniffer
{
    public static ILiveDevice? DeviceStatic;
    public void Sniff()
    {
        //if only -i is given as argument , print all available interfaces
        if (Arguments.I_Device == true)
        {
            PrintAllDevices();
            Environment.Exit(0);
            return;
        }

        //no argument -i set check
        if (Arguments.I == null)
        {
            Console.WriteLine("There is no I argument set! \n");
            Environment.Exit(1);
            return;
        }
        
        //Gets particular interface by given name
        var device = GetDeviceByName(Arguments.I);
        if (device == null)
        {
            Console.WriteLine("There is no device set! (device = null)! \n");
            Environment.Exit(1);
            return;
        }
        
        //helping static variable
        DeviceStatic = device;
        
        //subscription on OnPacketArrival event
        device.OnPacketArrival += (sender, e) =>
        {
            //checks if number of packets is already reached
            if (ParsePacket.Counter == Arguments.N)
            {
                StopSniffing();
                return;
            }
            Packets packets = new Packets();
            var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
            SnifferHandler snifferHandler = new SnifferHandler();
            //sniff packet calling
            snifferHandler.SniffPacket(packets,packet,e);
        };
        
        //device set to mode,in which we can 'sniff' packets
        device.Open(DeviceModes.Promiscuous);
        device.StartCapture();
        
        //if exited by concole (Ctrl + C) write message and close device
        Console.CancelKeyPress += new ConsoleCancelEventHandler(StopProgrammOnConsole);
        //infinite cycle till N is reached
        while (ParsePacket.Counter < Arguments.N)
        {
            
        }
    
        //device closure
        device.StopCapture();
        device.Close();
    }

    public ILiveDevice? GetDeviceByName(string name)
    {
        var deviceList = CaptureDeviceList.Instance;
        if (deviceList.Count < 1)
        {
            Console.WriteLine("Network devices not found!\n");
            Environment.Exit(1);
        }
        for (int i = 0; i < deviceList.Count; i++)
        {
            if (deviceList[i].Name.Equals(name))
            {
                return deviceList[i];
            }
        }
        Console.WriteLine("Such interface not found!\n");
        Environment.Exit(1);
        return null;
    }
    
    public void PrintAllDevices()
    {
        var deviceList = CaptureDeviceList.Instance;
        if (deviceList.Count < 1)
        {
            Console.WriteLine("Network devices not found!\n");
            Environment.Exit(1);
        }
        for (int i = 0; i < deviceList.Count; i++)
        {
            Console.WriteLine(deviceList[i].Name);
        }
    }

    public void StopProgrammOnConsole(object? obj,ConsoleCancelEventArgs args)
    {
        DeviceStatic.StopCapture();
        DeviceStatic.Close();
        Console.WriteLine("\nSniffer closed!\n");
    }
    public void StopSniffing()
    {
        DeviceStatic.StopCapture();
        DeviceStatic.Close();
        Console.WriteLine("\nSniffer ended!\n");
    }
}