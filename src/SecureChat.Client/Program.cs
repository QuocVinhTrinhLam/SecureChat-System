using SecureChat.Core.Utilities;

namespace SecureChat.Client;

/// <summary>
/// Entry point for the SecureChat Client application.
/// 
/// Security Considerations:
/// - No credentials stored in code
/// - Graceful shutdown for clean connection termination
/// - Foundation phase: No encryption (security warning displayed)
/// </summary>
public static class Program
{
    private const string DefaultHost = "localhost";
    private const int DefaultPort = 5000;
    
    private static readonly ILogger Logger = new ConsoleLogger(LogLevel.Info);
    
    public static async Task Main(string[] args)
    {
        Console.Title = "SecureChat Client";
        
        Logger.Info("===========================================");
        Logger.Info("       SecureChat Client - Foundation      ");
        Logger.Info("===========================================");
        Logger.Security("Foundation Phase - Messages are NOT encrypted!");
        Console.WriteLine();
        
        // Parse host and port from arguments
        var host = args.Length > 0 ? args[0] : DefaultHost;
        var port = DefaultPort;
        if (args.Length > 1 && int.TryParse(args[1], out var parsedPort))
        {
            port = parsedPort;
        }
        
        // Get username from user
        Console.Write("Enter your username: ");
        var username = Console.ReadLine()?.Trim();
        
        if (string.IsNullOrWhiteSpace(username))
        {
            Logger.Error("Username cannot be empty.");
            return;
        }
        
        // Set up cancellation
        using var cts = new CancellationTokenSource();
        
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            Logger.Info("Disconnecting...");
            cts.Cancel();
        };
        
        try
        {
            var client = new ChatClient(host, port, username, Logger);
            await client.ConnectAndRunAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            Logger.Info("Disconnected.");
        }
        catch (Exception ex)
        {
            Logger.Exception(ex, "Connection error");
        }
        
        Console.WriteLine("Press any key to exit...");
        Console.ReadKey(true);
    }
}
