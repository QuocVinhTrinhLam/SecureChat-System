using Microsoft.Extensions.Logging;
using SecureChat.Server;
using System.Text;

class Program
{
    static async Task Main()
    {
        Console.InputEncoding = Encoding.Unicode;
        Console.OutputEncoding = Encoding.Unicode;
        using ILoggerFactory loggerFactory =
            LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });

        ILogger<ChatServer> logger =
            loggerFactory.CreateLogger<ChatServer>();

        ChatServer server = new ChatServer(9000, logger);

        Console.WriteLine("Đang khởi động Server Chat ...");
        await server.StartAsync();
    }
}
