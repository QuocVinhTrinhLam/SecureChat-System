using SecureChat.Core.Models;
using SecureChat.Core.Security.Implementations;

namespace SecureChat.Tests;

/// <summary>
/// Các test cases cho PeerSessionManager - quản lý phiên E2E giữa clients
/// </summary>
public class PeerSessionManagerTests
{
    [Fact]
    public async Task TwoPeers_ExchangeKeys_CanCommunicateE2E()
    {
        // Arrange
        using var peerA = new PeerSessionManager();
        using var peerB = new PeerSessionManager();
        
        // Act - Peer A khởi tạo trao đổi khóa
        // FIX: Use Name as ID to match SenderName-based resolution
        var keyMsgA = await peerA.InitiatePeerSessionAsync("Bob", "Bob", "Alice", "Alice");
        
        // Assert - Kiểm tra tin nhắn key exchange
        Assert.Equal(MessageType.PeerKeyExchange, keyMsgA.Type);
        Assert.Equal("Alice", keyMsgA.SenderId);
        Assert.Equal("Alice", keyMsgA.SenderName);
        Assert.Equal("Bob", keyMsgA.RecipientId);
        Assert.Equal("Bob", keyMsgA.RecipientName);
        Assert.NotNull(keyMsgA.Content); // Public key
        
        // Act - Peer B xử lý và phản hồi
        var keyMsgB = await peerB.ProcessPeerKeyExchangeAsync(keyMsgA, "Bob", "Bob");
        
        // Assert - Kiểm tra phản hồi
        Assert.NotNull(keyMsgB);
        Assert.Equal(MessageType.PeerKeyExchangeResponse, keyMsgB.Type);
        Assert.Equal("Bob", keyMsgB.SenderId);
        Assert.Equal("Bob", keyMsgB.SenderName);
        Assert.True(peerB.HasSessionWith("Alice"));
        
        // Act - Peer A xử lý phản hồi
        var finalResponse = await peerA.ProcessPeerKeyExchangeAsync(keyMsgB, "Alice", "Alice");
        
        // Assert - Phiên đã thiết lập
        Assert.Null(finalResponse); // Không cần phản hồi thêm
        Assert.True(peerA.HasSessionWith("Bob"));
    }
    
    [Fact]
    public async Task TwoPeers_SendE2EMessage_Success()
    {
        // Arrange - Thiết lập phiên E2E
        using var peerA = new PeerSessionManager();
        using var peerB = new PeerSessionManager();
        
        var keyMsgA = await peerA.InitiatePeerSessionAsync("Bob", "Bob", "Alice", "Alice");
        var keyMsgB = await peerB.ProcessPeerKeyExchangeAsync(keyMsgA, "Bob", "Bob");
        await peerA.ProcessPeerKeyExchangeAsync(keyMsgB!, "Alice", "Alice");
        
        // Act - Peer A gửi tin nhắn mã hóa E2E
        // Note: RecipientId in direct message is still checked by Message logic, but for encryption metadata it uses "Bob"
        var originalMessage = Message.CreateDirectMessage("Alice", "Alice", "Bob", "Bob", "Hello E2E!");
        var encrypted = await peerA.EncryptForPeerAsync(originalMessage, "Bob");
        
        // Assert - Tin nhắn được mã hóa
        Assert.Equal(MessageType.Encrypted, encrypted.Type);
        Assert.NotEqual(originalMessage.Content, encrypted.Content);
        
        // Act - Peer B giải mã
        var decrypted = await peerB.DecryptFromPeerAsync(encrypted, "Alice");
        
        // Assert - Nội dung khớp
        Assert.Equal("Hello E2E!", decrypted.Content);
        Assert.Equal("Alice", decrypted.SenderId);
        Assert.Equal("Alice", decrypted.SenderName);
    }
    
    [Fact]
    public async Task Peer_EncryptWithoutSession_ThrowsException()
    {
        // Arrange
        using var peerA = new PeerSessionManager();
        var message = Message.CreateDirectMessage("Alice", "Alice", "Bob", "Bob", "Hello!");
        
        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => peerA.EncryptForPeerAsync(message, "Bob"));
    }
    
    [Fact]
    public void HasSessionWith_NoSession_ReturnsFalse()
    {
        // Arrange
        using var peer = new PeerSessionManager();
        
        // Act & Assert
        Assert.False(peer.HasSessionWith("unknown"));
    }
    
    [Fact]
    public async Task GetEstablishedPeers_ReturnsCorrectList()
    {
        // Arrange
        using var peerA = new PeerSessionManager();
        using var peerB = new PeerSessionManager();
        using var peerC = new PeerSessionManager();
        
        // Thiết lập session với peerB (Bob)
        var keyMsgAB = await peerA.InitiatePeerSessionAsync("Bob", "Bob", "Alice", "Alice");
        var keyMsgBA = await peerB.ProcessPeerKeyExchangeAsync(keyMsgAB, "Bob", "Bob");
        await peerA.ProcessPeerKeyExchangeAsync(keyMsgBA!, "Alice", "Alice");
        
        // Thiết lập session với peerC (Charlie)
        var keyMsgAC = await peerA.InitiatePeerSessionAsync("Charlie", "Charlie", "Alice", "Alice");
        var keyMsgCA = await peerC.ProcessPeerKeyExchangeAsync(keyMsgAC, "Charlie", "Charlie");
        await peerA.ProcessPeerKeyExchangeAsync(keyMsgCA!, "Alice", "Alice");
        
        // Act
        var establishedPeers = peerA.GetEstablishedPeers().ToList();
        
        // Assert
        Assert.Equal(2, establishedPeers.Count);
        Assert.Contains("Bob", establishedPeers);
        Assert.Contains("Charlie", establishedPeers);
    }
    
    [Fact]
    public async Task TwoPeers_BidirectionalE2E_Success()
    {
        // Arrange - Thiết lập phiên E2E
        using var peerA = new PeerSessionManager();
        using var peerB = new PeerSessionManager();
        
        var keyMsgA = await peerA.InitiatePeerSessionAsync("Bob", "Bob", "Alice", "Alice");
        var keyMsgB = await peerB.ProcessPeerKeyExchangeAsync(keyMsgA, "Bob", "Bob");
        await peerA.ProcessPeerKeyExchangeAsync(keyMsgB!, "Alice", "Alice");
        
        // Act - A gửi cho B
        var msgAtoB = Message.CreateDirectMessage("Alice", "Alice", "Bob", "Bob", "Hello Bob!");
        var encryptedAtoB = await peerA.EncryptForPeerAsync(msgAtoB, "Bob");
        var decryptedAtoB = await peerB.DecryptFromPeerAsync(encryptedAtoB, "Alice");
        
        // Assert
        Assert.Equal("Hello Bob!", decryptedAtoB.Content);
        
        // Act - B gửi cho A
        var msgBtoA = Message.CreateDirectMessage("Bob", "Bob", "Alice", "Alice", "Hello Alice!");
        var encryptedBtoA = await peerB.EncryptForPeerAsync(msgBtoA, "Alice");
        var decryptedBtoA = await peerA.DecryptFromPeerAsync(encryptedBtoA, "Bob");
        
        // Assert
        Assert.Equal("Hello Alice!", decryptedBtoA.Content);
    }
}
