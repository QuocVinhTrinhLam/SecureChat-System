using SecureChat.Core.Models;
using SecureChat.Core.Security.Interfaces;

namespace SecureChat.Core.Security.Implementations;

/// <summary>
/// Quản lý nhiều phiên E2E với các peer clients khác
/// 
/// Thiết kế bảo mật:
/// - Mỗi peer có một SecureSession riêng biệt
/// - Server KHÔNG THỂ giải mã tin nhắn giữa các clients
/// - Sử dụng ECDH để thiết lập shared secret trực tiếp giữa clients
/// 
/// Cách sử dụng:
/// 1. Client A gọi InitiatePeerSessionAsync() để bắt đầu trao đổi khóa với Client B
/// 2. Server chuyển tiếp PeerKeyExchange message đến Client B
/// 3. Client B gọi ProcessPeerKeyExchangeAsync() để xử lý và phản hồi
/// 4. Server chuyển tiếp PeerKeyExchangeResponse về Client A
/// 5. Cả hai clients đã có shared secret, có thể gửi tin nhắn E2E
/// </summary>
public sealed class PeerSessionManager : IDisposable
{
    private readonly Dictionary<string, SecureSession> _peerSessions = new();
    private readonly Dictionary<string, TaskCompletionSource<bool>> _pendingKeyExchanges = new();
    private readonly object _lock = new();
    private bool _disposed;

    /// <summary>
    /// Kiểm tra đã có phiên E2E với peer chưa
    /// </summary>
    public bool HasSessionWith(string peerId)
    {
        lock (_lock)
        {
            return _peerSessions.TryGetValue(peerId, out var session) && session.IsEstablished;
        }
    }

    /// <summary>
    /// Lấy hoặc tạo SecureSession cho peer
    /// </summary>
    private SecureSession GetOrCreateSession(string peerId)
    {
        lock (_lock)
        {
            if (!_peerSessions.TryGetValue(peerId, out var session))
            {
                session = new SecureSession();
                _peerSessions[peerId] = session;
            }
            return session;
        }
    }

    /// <summary>
    /// Khởi tạo phiên E2E với peer - gửi public key và chờ phản hồi
    /// </summary>
    /// <param name="peerId">ID của peer cần kết nối</param>
    /// <param name="peerName">Tên hiển thị của peer</param>
    /// <param name="selfId">ID của bản thân</param>
    /// <param name="selfName">Tên hiển thị của bản thân</param>
    /// <returns>Message PeerKeyExchange để gửi đến peer qua server</returns>
    public async Task<Message> InitiatePeerSessionAsync(string peerId, string peerName, string selfId, string selfName)
    {
        ThrowIfDisposed();

        var session = GetOrCreateSession(peerId);
        await session.InitializeAsync();

        // Tạo TaskCompletionSource để chờ phản hồi
        var tcs = new TaskCompletionSource<bool>();
        lock (_lock)
        {
            _pendingKeyExchanges[peerId] = tcs;
        }

        // Tạo tin nhắn trao đổi khóa
        var keyExchangeMsg = session.GetKeyExchangeMessage(selfId, selfName);
        
        return new Message
        {
            Type = MessageType.PeerKeyExchange,
            SenderId = selfId,
            SenderName = selfName,
            RecipientId = peerId,
            RecipientName = peerName,
            Content = keyExchangeMsg.Content, // Public key
            SecurityMetadata = keyExchangeMsg.SecurityMetadata
        };
    }

    /// <summary>
    /// Chờ hoàn tất trao đổi khóa với peer
    /// </summary>
    public async Task WaitForKeyExchangeAsync(string peerId, int timeoutMs = 30000)
    {
        TaskCompletionSource<bool>? tcs;
        lock (_lock)
        {
            if (!_pendingKeyExchanges.TryGetValue(peerId, out tcs))
            {
                // Không có pending, có thể đã hoàn tất
                if (HasSessionWith(peerId))
                    return;
                throw new InvalidOperationException($"Không có yêu cầu trao đổi khóa với {peerId}");
            }
        }

        using var cts = new CancellationTokenSource(timeoutMs);
        try
        {
            await tcs.Task.WaitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            throw new TimeoutException($"Trao đổi khóa với {peerId} timeout sau {timeoutMs}ms");
        }
    }

    /// <summary>
    /// Xử lý tin nhắn trao đổi khóa từ peer
    /// Nếu đây là yêu cầu mới (PeerKeyExchange), trả về phản hồi (PeerKeyExchangeResponse)
    /// Nếu đây là phản hồi (PeerKeyExchangeResponse), hoàn tất phiên và trả về null
    /// </summary>
    public async Task<Message?> ProcessPeerKeyExchangeAsync(Message keyExchange, string selfId, string selfName)
    {
        ThrowIfDisposed();

        // FIX: Sử dụng SenderName làm peerId vì hệ thống sử dụng Username để định danh peer trong UI và ServerConnection
        // SenderId là GUID nhưng ServerConnection khởi tạo session bằng Username
        var peerId = keyExchange.SenderName;
        // var peerId = keyExchange.SenderId; // OLD code causing mismatch
        var peerName = keyExchange.SenderName;

        if (string.IsNullOrEmpty(peerId))
        {
            throw new ArgumentException("SenderName không được để trống trong KeyExchange");
        }

        if (keyExchange.Type == MessageType.PeerKeyExchange)
        {
            // Nhận yêu cầu mới từ peer - tạo session và phản hồi
            var session = GetOrCreateSession(peerId);
            
            // Khởi tạo session nếu chưa có
            if (session.SessionId == null)
            {
                await session.InitializeAsync();
            }

            // Tạo tin nhắn KeyExchange nội bộ để xử lý
            var internalKeyMsg = new Message
            {
                Type = MessageType.KeyExchange,
                SenderId = peerId,
                SenderName = peerName,
                Content = keyExchange.Content,
                SecurityMetadata = keyExchange.SecurityMetadata
            };

            // Xử lý public key của peer
            await session.ProcessKeyExchangeMessageAsync(internalKeyMsg);

            // Tạo phản hồi với public key của mình
            var responseKeyMsg = session.GetKeyExchangeMessage(selfId, selfName);
            
            return new Message
            {
                Type = MessageType.PeerKeyExchangeResponse,
                SenderId = selfId,
                SenderName = selfName,
                RecipientId = peerId,
                RecipientName = peerName,
                Content = responseKeyMsg.Content, // Public key của mình
                SecurityMetadata = responseKeyMsg.SecurityMetadata
            };
        }
        else if (keyExchange.Type == MessageType.PeerKeyExchangeResponse)
        {
            // Nhận phản hồi từ peer - hoàn tất session
            var session = GetOrCreateSession(peerId);

            // Tạo tin nhắn KeyExchange nội bộ để xử lý
            var internalKeyMsg = new Message
            {
                Type = MessageType.KeyExchange,
                SenderId = peerId,
                SenderName = peerName,
                Content = keyExchange.Content,
                SecurityMetadata = keyExchange.SecurityMetadata
            };

            await session.ProcessKeyExchangeMessageAsync(internalKeyMsg);

            // Thông báo hoàn tất cho ai đang chờ
            lock (_lock)
            {
                if (_pendingKeyExchanges.TryGetValue(peerId, out var tcs))
                {
                    tcs.TrySetResult(true);
                    _pendingKeyExchanges.Remove(peerId);
                }
            }

            return null; // Không cần phản hồi thêm
        }

        throw new ArgumentException($"Loại tin nhắn không hợp lệ: {keyExchange.Type}");
    }

    /// <summary>
    /// Mã hóa tin nhắn để gửi đến peer (E2E)
    /// </summary>
    public async Task<Message> EncryptForPeerAsync(Message message, string peerId)
    {
        ThrowIfDisposed();

        SecureSession session;
        lock (_lock)
        {
            if (!_peerSessions.TryGetValue(peerId, out session!))
            {
                throw new InvalidOperationException($"Chưa có phiên E2E với {peerId}. Gọi InitiatePeerSessionAsync trước.");
            }
        }

        if (!session.IsEstablished)
        {
            throw new InvalidOperationException($"Phiên E2E với {peerId} chưa được thiết lập.");
        }

        return await session.EncryptMessageAsync(message);
    }

    /// <summary>
    /// Giải mã tin nhắn nhận từ peer (E2E)
    /// </summary>
    public async Task<Message> DecryptFromPeerAsync(Message encryptedMessage, string peerId)
    {
        ThrowIfDisposed();

        SecureSession session;
        lock (_lock)
        {
            if (!_peerSessions.TryGetValue(peerId, out session!))
            {
                throw new InvalidOperationException($"Chưa có phiên E2E với {peerId}.");
            }
        }

        if (!session.IsEstablished)
        {
            throw new InvalidOperationException($"Phiên E2E với {peerId} chưa được thiết lập.");
        }

        return await session.DecryptMessageAsync(encryptedMessage);
    }

    /// <summary>
    /// Lấy danh sách các peer đã có phiên E2E
    /// </summary>
    public IEnumerable<string> GetEstablishedPeers()
    {
        lock (_lock)
        {
            return _peerSessions
                .Where(kv => kv.Value.IsEstablished)
                .Select(kv => kv.Key)
                .ToList();
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(PeerSessionManager));
    }

    /// <summary>
    /// Giải phóng tất cả phiên E2E và hủy các pending key exchanges
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        lock (_lock)
        {
            foreach (var session in _peerSessions.Values)
            {
                session.Dispose();
            }
            _peerSessions.Clear();

            foreach (var tcs in _pendingKeyExchanges.Values)
            {
                tcs.TrySetCanceled();
            }
            _pendingKeyExchanges.Clear();
        }
    }
}
