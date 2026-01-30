using SecureChat.Core.Models;
using SecureChat.Core.Security.Interfaces;

namespace SecureChat.Core.Security.Implementations;

public sealed class PeerSessionManager : IDisposable
{
    private readonly Dictionary<string, SecureSession> _peerSessions = new();
    private readonly Dictionary<string, TaskCompletionSource<bool>> _pendingKeyExchanges = new();
    private readonly object _lock = new();
    private bool _disposed;

    public bool HasSessionWith(string peerId)
    {
        lock (_lock)
        {
            return _peerSessions.TryGetValue(peerId, out var session) && session.IsEstablished;
        }
    }

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
