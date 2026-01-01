using SecureChat.Core.Models;
using SecureChat.Core.Utilities;

namespace SecureChat.Client;

/// <summary>
/// High-level chat client that orchestrates connection and messaging.
/// 
/// Security Design:
/// - Separates UI/input handling from network operations
/// - Prepared for future security provider integration
/// - Event-based message notification for clean UI separation
/// </summary>
public sealed class ChatClient : IDisposable
{
    private readonly string _host;
    private readonly int _port;
    private readonly User _user;
    private readonly ILogger _logger;
    private ServerConnection? _connection;
    private bool _disposed;
    
    /// <summary>
    /// Creates a new chat client.
    /// </summary>
    /// <param name="host">Server hostname or IP.</param>
    /// <param name="port">Server port.</param>
    /// <param name="username">Username for this client.</param>
    /// <param name="logger">Logger for events.</param>
    public ChatClient(string host, int port, string username, ILogger logger)
    {
        _host = host;
        _port = port;
        _logger = logger;
        _user = User.Create(username);
    }
    
    /// <summary>
    /// Connects to the server and runs the chat session.
    /// </summary>
    public async Task ConnectAndRunAsync(CancellationToken cancellationToken)
    {
        _logger.Info("Connecting to {0}:{1}...", _host, _port);
        
        _connection = new ServerConnection(_host, _port, _logger);
        await _connection.ConnectAsync(cancellationToken);
        
        _logger.Info("Connected! Type messages and press Enter to send. Ctrl+C to quit.");
        _logger.Info("---");
        
        // Subscribe to incoming messages
        _connection.MessageReceived += OnMessageReceived;
        
        // Start receiving messages in background
        var receiveTask = _connection.StartReceivingAsync(cancellationToken);
        
        // Send join message
        await SendJoinMessageAsync(cancellationToken);
        
        // Main input loop
        await RunInputLoopAsync(cancellationToken);
        
        // Send leave message before disconnecting
        await SendLeaveMessageAsync();
        
        // Wait for receive task to complete
        try
        {
            await receiveTask;
        }
        catch (OperationCanceledException)
        {
            // Expected
        }
    }
    
    /// <summary>
    /// Sends the initial join message to the server.
    /// </summary>
    private async Task SendJoinMessageAsync(CancellationToken cancellationToken)
    {
        var joinMessage = Message.CreateJoinMessage(_user.Id, _user.Username);
        await _connection!.SendMessageAsync(joinMessage, cancellationToken);
        _logger.Security("Join message sent for user: {0}", _user.Username);
    }
    
    /// <summary>
    /// Sends a leave message before disconnecting.
    /// </summary>
    private async Task SendLeaveMessageAsync()
    {
        try
        {
            var leaveMessage = Message.CreateLeaveMessage(_user.Id, _user.Username);
            await _connection!.SendMessageAsync(leaveMessage, CancellationToken.None);
        }
        catch
        {
            // Ignore errors when disconnecting
        }
    }
    
    /// <summary>
    /// Main loop for reading user input and sending messages.
    /// </summary>
    private async Task RunInputLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                // Non-blocking read with cancellation support
                var input = await ReadLineAsync(cancellationToken);
                
                if (string.IsNullOrWhiteSpace(input))
                {
                    continue;
                }
                
                // Create and send text message
                var message = Message.CreateTextMessage(_user.Id, _user.Username, input);
                await _connection!.SendMessageAsync(message, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
    
    /// <summary>
    /// Reads a line from console with cancellation support.
    /// </summary>
    private static async Task<string?> ReadLineAsync(CancellationToken cancellationToken)
    {
        // Use a simple polling approach for console input with cancellation
        while (!cancellationToken.IsCancellationRequested)
        {
            if (Console.KeyAvailable)
            {
                return Console.ReadLine();
            }
            
            await Task.Delay(50, cancellationToken);
        }
        
        return null;
    }
    
    /// <summary>
    /// Handles received messages.
    /// </summary>
    private void OnMessageReceived(object? sender, Message message)
    {
        DisplayMessage(message);
    }
    
    /// <summary>
    /// Displays a message to the console.
    /// </summary>
    private void DisplayMessage(Message message)
    {
        var originalColor = Console.ForegroundColor;
        
        switch (message.Type)
        {
            case MessageType.Text:
                if (message.SenderId == _user.Id)
                {
                    // Own message - display in different color
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"[You]: {message.Content}");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[{message.SenderName}]: {message.Content}");
                }
                break;
                
            case MessageType.Join:
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($">>> {message.SenderName} joined the chat");
                break;
                
            case MessageType.Leave:
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"<<< {message.SenderName} left the chat");
                break;
                
            case MessageType.System:
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine($"[System]: {message.Content}");
                break;
                
            case MessageType.Error:
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[Error]: {message.Content}");
                break;
                
            default:
                Console.WriteLine($"[{message.Type}]: {message.Content}");
                break;
        }
        
        Console.ForegroundColor = originalColor;
    }
    
    /// <summary>
    /// Disposes client resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        
        _connection?.Dispose();
        _disposed = true;
    }
}
