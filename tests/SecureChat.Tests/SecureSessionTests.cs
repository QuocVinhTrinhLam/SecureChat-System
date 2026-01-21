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
    [Fact]
    public async Task Server_DecryptsIncomingEncryptedMessage_Correctly()
    {
        // Arrange
        using var clientSession = new SecureSession();
        using var serverSession = new SecureSession();
        await clientSession.InitializeAsync();
        await serverSession.InitializeAsync();
        // Key exchange
        var clientKeyMsg = clientSession.GetKeyExchangeMessage("client", "Client");
        var serverKeyMsg = serverSession.GetKeyExchangeMessage("server", "Server");
        await clientSession.ProcessKeyExchangeMessageAsync(serverKeyMsg);
        await serverSession.ProcessKeyExchangeMessageAsync(clientKeyMsg);
        var original = Message.CreateTextMessage(
            "client", "Client", "Hello from client");
        // Client encrypts outgoing message
        var encrypted = await clientSession.EncryptMessageAsync(original);
        // Act
        var decrypted = await serverSession.DecryptMessageAsync(encrypted);
        // Assert
        Assert.Equal(MessageType.Text, decrypted.Type);
        Assert.Equal(original.Content, decrypted.Content);
        Assert.Equal(original.SenderId, decrypted.SenderId);
        Assert.Equal(original.SenderName, decrypted.SenderName);
    }
    [Fact]
    public async Task Server_ReceivingPlaintextMessage_ThrowsArgumentException()
    {
        // Arrange
        using var serverSession = new SecureSession();
        using var clientSession = new SecureSession();
        await serverSession.InitializeAsync();
        await clientSession.InitializeAsync();
        // Key exchange để session established
        var clientKeyMsg = clientSession.GetKeyExchangeMessage("client", "Client");
        var serverKeyMsg = serverSession.GetKeyExchangeMessage("server", "Server");
        await serverSession.ProcessKeyExchangeMessageAsync(clientKeyMsg);
        await clientSession.ProcessKeyExchangeMessageAsync(serverKeyMsg);
        // Plaintext message
        var plaintextMessage =
            Message.CreateTextMessage("client", "Client", "Hello");
        // Act and Assert
        await Assert.ThrowsAsync<ArgumentException>(
            () => serverSession.DecryptMessageAsync(plaintextMessage));
    }
    // HMAC Message Integrity Tests
    [Fact]
    public async Task EncryptMessage_IncludesHmacInSecurityMetadata()
    {
        // Arrange
        using var clientSession = new SecureSession();
        using var serverSession = new SecureSession();
        await clientSession.InitializeAsync();
        await serverSession.InitializeAsync();    
        // Key exchange
        var clientKeyMsg = clientSession.GetKeyExchangeMessage("client", "Client");
        var serverKeyMsg = serverSession.GetKeyExchangeMessage("server", "Server");
        await clientSession.ProcessKeyExchangeMessageAsync(serverKeyMsg);
        await serverSession.ProcessKeyExchangeMessageAsync(clientKeyMsg);   
        var message = Message.CreateTextMessage("client", "Client", "Test message");    
        // Act
        var encrypted = await clientSession.EncryptMessageAsync(message);     
        // Assert
        Assert.NotNull(encrypted.SecurityMetadata);
        Assert.NotNull(encrypted.SecurityMetadata.Hmac);
        Assert.NotEmpty(encrypted.SecurityMetadata.Hmac);
    }
    [Fact]
    public async Task DecryptMessage_WithValidHmac_Succeeds()
    {
        // Arrange
        using var clientSession = new SecureSession();
        using var serverSession = new SecureSession();
        await clientSession.InitializeAsync();
        await serverSession.InitializeAsync();
        var clientKeyMsg = clientSession.GetKeyExchangeMessage("client", "Client");
        var serverKeyMsg = serverSession.GetKeyExchangeMessage("server", "Server");
        await clientSession.ProcessKeyExchangeMessageAsync(serverKeyMsg);
        await serverSession.ProcessKeyExchangeMessageAsync(clientKeyMsg);    
        var original = Message.CreateTextMessage("client", "Client", "Hello with HMAC!");
        var encrypted = await clientSession.EncryptMessageAsync(original);    
        // Act
        var decrypted = await serverSession.DecryptMessageAsync(encrypted);  
        // Assert
        Assert.Equal(original.Content, decrypted.Content);
        Assert.Equal(original.SenderId, decrypted.SenderId);
    } 
    [Fact]
    public async Task DecryptMessage_WithMissingHmac_ThrowsSecurityException()
    {
        // Arrange
        using var clientSession = new SecureSession();
        using var serverSession = new SecureSession();
        await clientSession.InitializeAsync();
        await serverSession.InitializeAsync();      
        var clientKeyMsg = clientSession.GetKeyExchangeMessage("client", "Client");
        var serverKeyMsg = serverSession.GetKeyExchangeMessage("server", "Server");
        await clientSession.ProcessKeyExchangeMessageAsync(serverKeyMsg);
        await serverSession.ProcessKeyExchangeMessageAsync(clientKeyMsg);      
        var original = Message.CreateTextMessage("client", "Client", "Test");
        var encrypted = await clientSession.EncryptMessageAsync(original);      
        // Remove HMAC to simulate attack or corruption
        encrypted.SecurityMetadata!.Hmac = null;     
        // Act and Assert
        await Assert.ThrowsAsync<SecurityException>(
            () => serverSession.DecryptMessageAsync(encrypted));
    }
    [Fact]
    public async Task DecryptMessage_WithTamperedCiphertext_ThrowsSecurityException()
    {
        // Arrange
        using var clientSession = new SecureSession();
        using var serverSession = new SecureSession();
        await clientSession.InitializeAsync();
        await serverSession.InitializeAsync(); 
        var clientKeyMsg = clientSession.GetKeyExchangeMessage("client", "Client");
        var serverKeyMsg = serverSession.GetKeyExchangeMessage("server", "Server");
        await clientSession.ProcessKeyExchangeMessageAsync(serverKeyMsg);
        await serverSession.ProcessKeyExchangeMessageAsync(clientKeyMsg);
        var original = Message.CreateTextMessage("client", "Client", "Sensitive data");
        var encrypted = await clientSession.EncryptMessageAsync(original);       
        // Tamper with ciphertext
        var tamperedBytes = Convert.FromBase64String(encrypted.Content);
        tamperedBytes[0] ^= 0xFF; // Flip bits in first byte
        encrypted.Content = Convert.ToBase64String(tamperedBytes);   
        // Act and Assert - HMAC verification should fail before decryption
        await Assert.ThrowsAsync<SecurityException>(
            () => serverSession.DecryptMessageAsync(encrypted));
    }
    [Fact]
    public async Task DecryptMessage_WithTamperedHmac_ThrowsSecurityException()
    {
        // Arrange
        using var clientSession = new SecureSession();
        using var serverSession = new SecureSession();
        await clientSession.InitializeAsync();
        await serverSession.InitializeAsync();    
        var clientKeyMsg = clientSession.GetKeyExchangeMessage("client", "Client");
        var serverKeyMsg = serverSession.GetKeyExchangeMessage("server", "Server");
        await clientSession.ProcessKeyExchangeMessageAsync(serverKeyMsg);
        await serverSession.ProcessKeyExchangeMessageAsync(clientKeyMsg);    
        var original = Message.CreateTextMessage("client", "Client", "Important message");
        var encrypted = await clientSession.EncryptMessageAsync(original);       
        // Tamper with HMAC
        var tamperedHmacBytes = Convert.FromBase64String(encrypted.SecurityMetadata!.Hmac!);
        tamperedHmacBytes[0] ^= 0xFF; // Flip bits
        encrypted.SecurityMetadata.Hmac = Convert.ToBase64String(tamperedHmacBytes);       
        // Act and Assert
        await Assert.ThrowsAsync<SecurityException>(
            () => serverSession.DecryptMessageAsync(encrypted));
    }
}
