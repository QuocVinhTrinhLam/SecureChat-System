using System.Net;
using System.Net.Sockets;
using SecureChat.Core.Networking;
using SecureChat.Core.Utilities;

namespace SecureChat.Server;

/// <summary>
/// Main TCP chat server that listens for client connections.
/// 
/// Security Design:
/// - Async/await pattern for scalable client handling
/// - Per-client isolation via separate ClientHandler tasks
/// - Centralized message routing through ClientManager
/// - Prepared for future TLS integration
/// 
/// Architecture:
/// TcpListener -> Accept -> ClientHandler (per client) -> ClientManager (broadcasts)
/// </summary>
public sealed class ChatServer : IDisposable
{
    private readonly int _port;
    private readonly ILogger _logger;
    private readonly ClientManager _clientManager;
    private readonly IMessageSerializer _serializer;
    private TcpListener? _listener;
    private bool _disposed;
    
    /// <summary>
    /// Creates a new chat server instance.
    /// </summary>
    /// <param name="port">TCP port to listen on.</param>
    /// <param name="logger">Logger for server events.</param>
    public ChatServer(int port, ILogger logger)
    {
        _port = port;
        _logger = logger;
        _clientManager = new ClientManager(logger);
        _serializer = new JsonMessageSerializer();
    }
    
    /// <summary>
    /// Starts the server and begins accepting client connections.
    /// </summary>
    /// <param name="cancellationToken">Token to signal shutdown.</param>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // Bind to all interfaces - in production, consider binding to specific IP
        // Security Note: Binding to 0.0.0.0 makes server accessible from all networks
        _listener = new TcpListener(IPAddress.Any, _port);
        
        try
        {
            _listener.Start();
            _logger.Info("Server listening on port {0}", _port);
            _logger.Security("TCP listener started - accepting connections from any interface");
            
            // Main accept loop
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // Async accept with cancellation support
                    var client = await _listener.AcceptTcpClientAsync(cancellationToken);
                    
                    var endpoint = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
                    _logger.Security("New connection from {0}", endpoint);
                    
                    // Handle client in a separate task (fire-and-forget with error handling)
                    _ = HandleClientAsync(client, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    // Expected during shutdown
                    break;
                }
                catch (SocketException ex)
                {
                    // Log but continue accepting other clients
                    _logger.Exception(ex, "Socket error during accept");
                }
            }
        }
        finally
        {
            _listener.Stop();
            _logger.Info("Server stopped listening.");
        }
    }
    
    /// <summary>
    /// Handles a single client connection.
    /// </summary>
    private async Task HandleClientAsync(TcpClient tcpClient, CancellationToken cancellationToken)
    {
        var clientHandler = new ClientHandler(tcpClient, _clientManager, _serializer, _logger);
        
        try
        {
            await clientHandler.ProcessAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Exception(ex, "Error handling client");
        }
        finally
        {
            clientHandler.Dispose();
        }
    }
    
    /// <summary>
    /// Disposes server resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        
        _listener?.Stop();
        _clientManager.Dispose();
        _disposed = true;
    }
}
