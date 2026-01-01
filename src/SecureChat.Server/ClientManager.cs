using System.Collections.Concurrent;
using SecureChat.Core.Models;
using SecureChat.Core.Utilities;

namespace SecureChat.Server;

/// <summary>
/// Manages connected clients and handles message broadcasting.
/// 
/// Security Design:
/// - Thread-safe using ConcurrentDictionary
/// - Isolated client failures don't affect other clients
/// - Centralized point for future access control
/// 
/// Architecture:
/// All message routing goes through this manager, enabling:
/// - Message filtering/moderation
/// - Per-user encryption (future)
/// - Access control/banning
/// </summary>
public sealed class ClientManager : IDisposable
{
    private readonly ConcurrentDictionary<string, ClientHandler> _clients = new();
    private readonly ILogger _logger;
    private bool _disposed;
    
    /// <summary>
    /// Gets the number of connected clients.
    /// </summary>
    public int ClientCount => _clients.Count;
    
    /// <summary>
    /// Creates a new client manager.
    /// </summary>
    /// <param name="logger">Logger for events.</param>
    public ClientManager(ILogger logger)
    {
        _logger = logger;
    }
    
    /// <summary>
    /// Adds a client to the manager.
    /// </summary>
    /// <param name="client">The client handler to add.</param>
    public void AddClient(ClientHandler client)
    {
        if (_clients.TryAdd(client.User.Id, client))
        {
            _logger.Debug("Client added: {0} ({1}). Total: {2}", 
                client.User.Username, client.User.Id, _clients.Count);
        }
        else
        {
            _logger.Warning("Failed to add client: {0} - ID already exists", client.User.Id);
        }
    }
    
    /// <summary>
    /// Removes a client from the manager.
    /// </summary>
    /// <param name="clientId">The client ID to remove.</param>
    public void RemoveClient(string clientId)
    {
        if (_clients.TryRemove(clientId, out var removed))
        {
            _logger.Debug("Client removed: {0} ({1}). Total: {2}", 
                removed.User.Username, clientId, _clients.Count);
        }
    }
    
    /// <summary>
    /// Gets a client by their ID.
    /// </summary>
    /// <param name="clientId">The client ID to find.</param>
    /// <returns>The client handler, or null if not found.</returns>
    public ClientHandler? GetClient(string clientId)
    {
        _clients.TryGetValue(clientId, out var client);
        return client;
    }
    
    /// <summary>
    /// Broadcasts a message to all connected clients.
    /// </summary>
    /// <param name="message">The message to broadcast.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task BroadcastAsync(Message message, CancellationToken cancellationToken)
    {
        var sendTasks = new List<Task>();
        
        foreach (var client in _clients.Values)
        {
            // Send to all clients (including sender for echo)
            sendTasks.Add(SendToClientSafeAsync(client, message, cancellationToken));
        }
        
        await Task.WhenAll(sendTasks);
        
        _logger.Debug("Broadcast message type {0} to {1} clients", message.Type, sendTasks.Count);
    }
    
    /// <summary>
    /// Broadcasts a message to all clients except the specified sender.
    /// </summary>
    /// <param name="message">The message to broadcast.</param>
    /// <param name="excludeSenderId">The sender ID to exclude.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task BroadcastExceptAsync(
        Message message, 
        string excludeSenderId, 
        CancellationToken cancellationToken)
    {
        var sendTasks = new List<Task>();
        
        foreach (var client in _clients.Values)
        {
            if (client.User.Id != excludeSenderId)
            {
                sendTasks.Add(SendToClientSafeAsync(client, message, cancellationToken));
            }
        }
        
        await Task.WhenAll(sendTasks);
    }
    
    /// <summary>
    /// Sends a message to a specific client by ID.
    /// </summary>
    /// <param name="clientId">The target client ID.</param>
    /// <param name="message">The message to send.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the client was found and message sent.</returns>
    public async Task<bool> SendToClientAsync(
        string clientId, 
        Message message, 
        CancellationToken cancellationToken)
    {
        if (_clients.TryGetValue(clientId, out var client))
        {
            await SendToClientSafeAsync(client, message, cancellationToken);
            return true;
        }
        
        return false;
    }
    
    /// <summary>
    /// Safely sends a message to a client, handling any errors.
    /// Security: Ensures one client's failure doesn't affect others.
    /// </summary>
    private async Task SendToClientSafeAsync(
        ClientHandler client, 
        Message message, 
        CancellationToken cancellationToken)
    {
        try
        {
            await client.SendMessageAsync(message, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Log but don't throw - other clients should still receive the message
            _logger.Debug("Failed to send to client {0}: {1}", 
                client.User.Username, ex.Message);
        }
    }
    
    /// <summary>
    /// Gets a list of all connected user names.
    /// </summary>
    public IEnumerable<string> GetConnectedUserNames()
    {
        return _clients.Values.Select(c => c.User.Username);
    }
    
    /// <summary>
    /// Disposes all client connections.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        
        foreach (var client in _clients.Values)
        {
            try
            {
                client.Dispose();
            }
            catch
            {
                // Ignore disposal errors
            }
        }
        
        _clients.Clear();
        _disposed = true;
    }
}
