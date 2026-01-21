using SecureChat.Core.Models;
using SecureChat.Core.Networking;
using SecureChat.Core.Security.Implementations;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace SecureChat.Tests;

/// <summary>
/// Integration tests for server-side key exchange
/// Tests the handshake protocol between client and server sessions
/// </summary>
public class ServerKeyExchangeTests
{
    private readonly JsonMessageSerializer _serializer = new();
    [Fact]
    public async Task ServerClientKeyExchange_FullHandshake_EstablishesBothSessions()
    {
        // Arrange - Simulate client and server sessions
        using var clientSession = new SecureSession();
        using var serverSession = new SecureSession();
        await clientSession.InitializeAsync();
        await serverSession.InitializeAsync();
        // Act - Client sends key exchange to server
        var clientKeyMessage = clientSession.GetKeyExchangeMessage("client-1", "TestClient");
        // Server processes client key and responds
        await serverSession.ProcessKeyExchangeMessageAsync(clientKeyMessage);
        var serverKeyMessage = serverSession.GetKeyExchangeMessage("server", "Server");
        // Client processes server key
        await clientSession.ProcessKeyExchangeMessageAsync(serverKeyMessage);
        // Assert - Both sessions should be established
        Assert.True(clientSession.IsEstablished);
        Assert.True(serverSession.IsEstablished);
    }
    [Fact]
    public async Task EncryptedMessage_AfterKeyExchange_RoundTripsSuccessfully()
    {
        // Arrange
        using var clientSession = new SecureSession();
        using var serverSession = new SecureSession();
        await clientSession.InitializeAsync();
        await serverSession.InitializeAsync();
        // Perform key exchange
        var clientKey = clientSession.GetKeyExchangeMessage("client-1", "Client");
        await serverSession.ProcessKeyExchangeMessageAsync(clientKey);
        var serverKey = serverSession.GetKeyExchangeMessage("server", "Server");
        await clientSession.ProcessKeyExchangeMessageAsync(serverKey);
        // Act - Client sends encrypted message
        var originalMessage = Message.CreateTextMessage("client-1", "Client", "Hello, secure server!");
        var encrypted = await clientSession.EncryptMessageAsync(originalMessage);
        // Serialize/deserialize to simulate network transfer
        var bytes = _serializer.Serialize(encrypted);
        var received = _serializer.Deserialize(bytes);
        // Server decrypts
        var decrypted = await serverSession.DecryptMessageAsync(received);
        // Assert
        Assert.Equal(MessageType.Encrypted, encrypted.Type);
        Assert.Equal(originalMessage.Content, decrypted.Content);
        Assert.Equal(originalMessage.SenderId, decrypted.SenderId);
        Assert.NotEqual(originalMessage.Content, encrypted.Content); // Content was encrypted
    }
    [Fact]
    public async Task KeyExchangeMessage_Serialization_RoundTripsCorrectly()
    {
        // Arrange
        using var session = new SecureSession();
        await session.InitializeAsync();
        var keyMessage = session.GetKeyExchangeMessage("user-123", "TestUser");
        // Act - Serialize and deserialize
        var bytes = _serializer.Serialize(keyMessage);
        var deserialized = _serializer.Deserialize(bytes);
        // Assert
        Assert.Equal(MessageType.KeyExchange, deserialized.Type);
        Assert.Equal("user-123", deserialized.SenderId);
        Assert.Equal("TestUser", deserialized.SenderName);
        Assert.Equal(keyMessage.Content, deserialized.Content); // Public key preserved
        Assert.NotNull(deserialized.SecurityMetadata);
        Assert.Equal("ECDH-P256", deserialized.SecurityMetadata!.Algorithm);
    }
    [Fact]
    public async Task InvalidPublicKey_InKeyExchange_ThrowsSecurityException()
    {
        // Arrange
        using var session = new SecureSession();
        await session.InitializeAsync();
        var invalidKeyMessage = new Message
        {
            Type = MessageType.KeyExchange,
            SenderId = "attacker",
            SenderName = "Attacker",
            Content = "this-is-not-a-valid-public-key!!!",
            SecurityMetadata = new SecurityMetadata { Algorithm = "ECDH-P256" }
        };
        // Act and Assert
        await Assert.ThrowsAsync<SecurityException>(
            () => session.ProcessKeyExchangeMessageAsync(invalidKeyMessage));
    }
    [Fact]
    public async Task BidirectionalEncryption_ClientAndServer_BothCanEncryptDecrypt()
    {
        // Arrange
        using var clientSession = new SecureSession();
        using var serverSession = new SecureSession();
        await clientSession.InitializeAsync();
        await serverSession.InitializeAsync();
        // Key exchange
        var clientKey = clientSession.GetKeyExchangeMessage("client", "Client");
        await serverSession.ProcessKeyExchangeMessageAsync(clientKey);
        var serverKey = serverSession.GetKeyExchangeMessage("server", "Server");
        await clientSession.ProcessKeyExchangeMessageAsync(serverKey);
        // Act - Client to Server
        var clientMsg = Message.CreateTextMessage("client", "Client", "Hello Server!");
        var encryptedFromClient = await clientSession.EncryptMessageAsync(clientMsg);
        var decryptedByServer = await serverSession.DecryptMessageAsync(encryptedFromClient);
        // Act - Server to Client
        var serverMsg = Message.CreateTextMessage("server", "Server", "Hello Client!");
        var encryptedFromServer = await serverSession.EncryptMessageAsync(serverMsg);
        var decryptedByClient = await clientSession.DecryptMessageAsync(encryptedFromServer);
        // Assert
        Assert.Equal("Hello Server!", decryptedByServer.Content);
        Assert.Equal("Hello Client!", decryptedByClient.Content);
    }
}
