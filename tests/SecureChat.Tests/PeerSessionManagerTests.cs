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
        var keyMsgA = await peerA.InitiatePeerSessionAsync("peerB", "Bob", "peerA", "Alice");
        
        // Assert - Kiểm tra tin nhắn key exchange
        Assert.Equal(MessageType.PeerKeyExchange, keyMsgA.Type);
        Assert.Equal("peerA", keyMsgA.SenderId);
        Assert.Equal("Alice", keyMsgA.SenderName);
        Assert.Equal("peerB", keyMsgA.RecipientId);
        Assert.Equal("Bob", keyMsgA.RecipientName);
        Assert.NotNull(keyMsgA.Content); // Public key
        
        // Act - Peer B xử lý và phản hồi
        var keyMsgB = await peerB.ProcessPeerKeyExchangeAsync(keyMsgA, "peerB", "Bob");
        
        // Assert - Kiểm tra phản hồi
        Assert.NotNull(keyMsgB);
        Assert.Equal(MessageType.PeerKeyExchangeResponse, keyMsgB.Type);
        Assert.Equal("peerB", keyMsgB.SenderId);
        Assert.Equal("Bob", keyMsgB.SenderName);
        Assert.True(peerB.HasSessionWith("peerA"));
        
        // Act - Peer A xử lý phản hồi
        var finalResponse = await peerA.ProcessPeerKeyExchangeAsync(keyMsgB, "peerA", "Alice");
        
        // Assert - Phiên đã thiết lập
        Assert.Null(finalResponse); // Không cần phản hồi thêm
        Assert.True(peerA.HasSessionWith("peerB"));
    }
    
    [Fact]
    public async Task TwoPeers_SendE2EMessage_Success()
    {
        // Arrange - Thiết lập phiên E2E
        using var peerA = new PeerSessionManager();
        using var peerB = new PeerSessionManager();
        
        var keyMsgA = await peerA.InitiatePeerSessionAsync("peerB", "Bob", "peerA", "Alice");
        var keyMsgB = await peerB.ProcessPeerKeyExchangeAsync(keyMsgA, "peerB", "Bob");
        await peerA.ProcessPeerKeyExchangeAsync(keyMsgB!, "peerA", "Alice");
        
        // Act - Peer A gửi tin nhắn mã hóa E2E
        var originalMessage = Message.CreateDirectMessage("peerA", "Alice", "peerB", "Bob", "Hello E2E!");
        var encrypted = await peerA.EncryptForPeerAsync(originalMessage, "peerB");
        
        // Assert - Tin nhắn được mã hóa
        Assert.Equal(MessageType.Encrypted, encrypted.Type);
        Assert.NotEqual(originalMessage.Content, encrypted.Content);
        
        // Act - Peer B giải mã
        var decrypted = await peerB.DecryptFromPeerAsync(encrypted, "peerA");
        
        // Assert - Nội dung khớp
        Assert.Equal("Hello E2E!", decrypted.Content);
        Assert.Equal("peerA", decrypted.SenderId);
        Assert.Equal("Alice", decrypted.SenderName);
    }
    
    [Fact]
    public async Task Peer_EncryptWithoutSession_ThrowsException()
    {
        // Arrange
        using var peerA = new PeerSessionManager();
        var message = Message.CreateDirectMessage("peerA", "Alice", "peerB", "Bob", "Hello!");
        
        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => peerA.EncryptForPeerAsync(message, "peerB"));
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
        
        // Thiết lập session với peerB
        var keyMsgAB = await peerA.InitiatePeerSessionAsync("peerB", "Bob", "peerA", "Alice");
        var keyMsgBA = await peerB.ProcessPeerKeyExchangeAsync(keyMsgAB, "peerB", "Bob");
        await peerA.ProcessPeerKeyExchangeAsync(keyMsgBA!, "peerA", "Alice");
        
        // Thiết lập session với peerC
        var keyMsgAC = await peerA.InitiatePeerSessionAsync("peerC", "Charlie", "peerA", "Alice");
        var keyMsgCA = await peerC.ProcessPeerKeyExchangeAsync(keyMsgAC, "peerC", "Charlie");
        await peerA.ProcessPeerKeyExchangeAsync(keyMsgCA!, "peerA", "Alice");
        
        // Act
        var establishedPeers = peerA.GetEstablishedPeers().ToList();
        
        // Assert
        Assert.Equal(2, establishedPeers.Count);
        Assert.Contains("peerB", establishedPeers);
        Assert.Contains("peerC", establishedPeers);
    }
    
    [Fact]
    public async Task TwoPeers_BidirectionalE2E_Success()
    {
        // Arrange - Thiết lập phiên E2E
        using var peerA = new PeerSessionManager();
        using var peerB = new PeerSessionManager();
        
        var keyMsgA = await peerA.InitiatePeerSessionAsync("peerB", "Bob", "peerA", "Alice");
        var keyMsgB = await peerB.ProcessPeerKeyExchangeAsync(keyMsgA, "peerB", "Bob");
        await peerA.ProcessPeerKeyExchangeAsync(keyMsgB!, "peerA", "Alice");
        
        // Act - A gửi cho B
        var msgAtoB = Message.CreateDirectMessage("peerA", "Alice", "peerB", "Bob", "Hello Bob!");
        var encryptedAtoB = await peerA.EncryptForPeerAsync(msgAtoB, "peerB");
        var decryptedAtoB = await peerB.DecryptFromPeerAsync(encryptedAtoB, "peerA");
        
        // Assert
        Assert.Equal("Hello Bob!", decryptedAtoB.Content);
        
        // Act - B gửi cho A
        var msgBtoA = Message.CreateDirectMessage("peerB", "Bob", "peerA", "Alice", "Hello Alice!");
        var encryptedBtoA = await peerB.EncryptForPeerAsync(msgBtoA, "peerA");
        var decryptedBtoA = await peerA.DecryptFromPeerAsync(encryptedBtoA, "peerB");
        
        // Assert
        Assert.Equal("Hello Alice!", decryptedBtoA.Content);
    }
}
