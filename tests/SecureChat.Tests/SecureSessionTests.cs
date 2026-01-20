using SecureChat.Core.Security.Implementations;
using SecureChat.Core.Security.Interfaces;
using SecureChat.Core.Models;
using Xunit;

namespace SecureChat.Tests;
/// <summary>
/// Tests for the SecureSession orchestrator
/// </summary>
public class SecureSessionTests
{
    [Fact]
    public async Task KeyExchange_BetweenTwoSessions_EstablishesSessions()
    {
        // Arrange
        using var clientSession = new SecureSession();
        using var serverSession = new SecureSession();       
        await clientSession.InitializeAsync();
        await serverSession.InitializeAsync();        
        // Act - Exchange keys
        var clientKeyMsg = clientSession.GetKeyExchangeMessage("client1", "Client");
        var serverKeyMsg = serverSession.GetKeyExchangeMessage("server", "Server");        
        await clientSession.ProcessKeyExchangeMessageAsync(serverKeyMsg);
        await serverSession.ProcessKeyExchangeMessageAsync(clientKeyMsg);        
        // Assert
        Assert.True(clientSession.IsEstablished);
        Assert.True(serverSession.IsEstablished);
    }
    [Fact]
    public async Task EncryptDecrypt_AfterKeyExchange_RoundTripsMessage()
    {
        // Arrange
        using var clientSession = new SecureSession();
        using var serverSession = new SecureSession(); 
        await clientSession.InitializeAsync();
        await serverSession.InitializeAsync(); 
        // Key exchange
        var clientKeyMsg = clientSession.GetKeyExchangeMessage("client1", "Client");
        var serverKeyMsg = serverSession.GetKeyExchangeMessage("server", "Server");
        await clientSession.ProcessKeyExchangeMessageAsync(serverKeyMsg);
        await serverSession.ProcessKeyExchangeMessageAsync(clientKeyMsg);
        // Create message
        var originalMessage = Message.CreateTextMessage("client1", "Client", "Hello, secure world!");
        // Act
        var encrypted = await clientSession.EncryptMessageAsync(originalMessage);
        var decrypted = await serverSession.DecryptMessageAsync(encrypted); 
        // Assert
        Assert.Equal(MessageType.Encrypted, encrypted.Type);
        Assert.NotEqual(originalMessage.Content, encrypted.Content);
        Assert.NotNull(encrypted.SecurityMetadata);
        Assert.Equal("AES-256-GCM", encrypted.SecurityMetadata.Algorithm);
        Assert.Equal(originalMessage.Type, decrypted.Type);
        Assert.Equal(originalMessage.Content, decrypted.Content);
        Assert.Equal(originalMessage.SenderId, decrypted.SenderId);
    }
    [Fact]
    public async Task EncryptMessage_BeforeKeyExchange_ThrowsException()
    {
        // Arrange
        using var session = new SecureSession();
        await session.InitializeAsync();
        var message = Message.CreateTextMessage("user", "User", "Hello");
        // Act and Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => session.EncryptMessageAsync(message));
    }
    [Fact]
    public async Task IsEstablished_BeforeKeyExchange_ReturnsFalse()
    {
        // Arrange
        using var session = new SecureSession();
        await session.InitializeAsync();
        // Assert
        Assert.False(session.IsEstablished);
    }
    [Fact]
    public async Task GetKeyExchangeMessage_ReturnsValidMessage()
    {
        // Arrange
        using var session = new SecureSession();
        await session.InitializeAsync();       
        // Act
        var keyMsg = session.GetKeyExchangeMessage("user1", "TestUser");       
        // Assert
        Assert.Equal(MessageType.KeyExchange, keyMsg.Type);
        Assert.Equal("user1", keyMsg.SenderId);
        Assert.Equal("TestUser", keyMsg.SenderName);
        Assert.NotEmpty(keyMsg.Content);  // Contains public key
        Assert.NotNull(keyMsg.SecurityMetadata);
        Assert.Equal("ECDH-P256", keyMsg.SecurityMetadata.Algorithm);
    }
    [Fact]
    public async Task Client_EncryptsOutgoingMessage_Automatically()
    {
        // Arrange
        using var clientSession = new SecureSession();
        using var serverSession = new SecureSession();
        await clientSession.InitializeAsync();
        await serverSession.InitializeAsync();
        // Key exchange
        var clientKeyMsg = clientSession.GetKeyExchangeMessage("client1", "Client");
        var serverKeyMsg = serverSession.GetKeyExchangeMessage("server", "Server");
        await clientSession.ProcessKeyExchangeMessageAsync(serverKeyMsg);
        await serverSession.ProcessKeyExchangeMessageAsync(clientKeyMsg);
        var plaintextMessage =
            Message.CreateTextMessage("client1", "Client", "THIS IS PLAINTEXT");
        // Act
        var outgoing = await clientSession.EncryptMessageAsync(plaintextMessage);
        // Assert
        Assert.Equal(MessageType.Encrypted, outgoing.Type);
        Assert.NotEqual("THIS IS PLAINTEXT", outgoing.Content);
        Assert.NotNull(outgoing.SecurityMetadata);
        Assert.Equal("AES-256-GCM", outgoing.SecurityMetadata.Algorithm);
    }
}
