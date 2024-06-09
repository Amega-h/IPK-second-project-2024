namespace Sniffer;
class Program
{
    static async Task Main(string[] args)
    {
        bool noError = ArgParse.Parse(args);
        
        //Arguments error check
        if (!noError)
        {
            Console.Error.WriteLine("Some error occured during argument parsing!\n");
            Environment.Exit(1);
        }
        
        Sniffer sniffer = new Sniffer(); 
        sniffer.Sniff();
    }
}