using Microsoft.Extensions.Logging;
using SecureChat.Server;

class Program
{
    static async Task Main(string[] args)
    {
        using ILoggerFactory loggerFactory =
            LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });

        ILogger<ChatServer> logger =
            loggerFactory.CreateLogger<ChatServer>();

        ChatServer server = new ChatServer(9000, logger);

        await server.StartAsync();
    }
}
