using Microsoft.Extensions.Logging;
using SecureChat.Server;
using System.Text;

class Program
{
    static async Task Main()
    {
        Console.InputEncoding = Encoding.UTF8;
        Console.OutputEncoding = Encoding.UTF8;
        using ILoggerFactory loggerFactory =
            LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });
        ILogger<ChatServer> logger =
            loggerFactory.CreateLogger<ChatServer>();
        ChatServer server = new ChatServer(9000, logger);
        Console.WriteLine("=== SecureChat Server ===");
        Console.WriteLine("Đang khởi động Server Chat trên cổng 9000...");
        await server.StartAsync();
    }
}
