using SecureChat.Core.Utilities;

namespace SecureChat.Server;

/// <summary>
/// Entry point for the SecureChat Server application.
/// 
/// Security Considerations:
/// - Server runs with minimal privileges needed
/// - Configuration loaded from environment/config (not hardcoded)
/// - Graceful shutdown ensures cleanup of resources
/// </summary>
public static class Program
{
    // Default port - can be overridden via command line or config
    private const int DefaultPort = 5000;
    
    // Logger instance for the application
    private static readonly ILogger Logger = new ConsoleLogger(LogLevel.Debug);
    
    public static async Task Main(string[] args)
    {
        Console.Title = "SecureChat Server";
        
        Logger.Info("===========================================");
        Logger.Info("       SecureChat Server - Foundation      ");
        Logger.Info("===========================================");
        Logger.Security("Server starting up - Foundation Phase (No encryption)");
        
        // Parse port from command line arguments
        var port = DefaultPort;
        if (args.Length > 0 && int.TryParse(args[0], out var parsedPort))
        {
            port = parsedPort;
        }
        
        // Validate port range
        if (port < 1024 || port > 65535)
        {
            Logger.Error("Invalid port number. Use a port between 1024 and 65535.");
            return;
        }
        
        // Set up cancellation for graceful shutdown
        using var cts = new CancellationTokenSource();
        
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true; // Prevent immediate termination
            Logger.Info("Shutdown signal received. Stopping server...");
            cts.Cancel();
        };
        
        try
        {
            // Create and start the chat server
            var server = new ChatServer(port, Logger);
            await server.StartAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            Logger.Info("Server shutdown completed gracefully.");
        }
        catch (Exception ex)
        {
            Logger.Exception(ex, "Fatal server error");
            Environment.ExitCode = 1;
        }
        
        Logger.Security("Server has stopped.");
    }
}
