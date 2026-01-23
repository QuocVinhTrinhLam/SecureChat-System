using System.Security.Cryptography;

namespace SecureChat.Core.Security.Implementations;

/// <summary>
/// Implementation trao đổi khóa ECDH sử dụng đường cong P-256
/// 
/// Thiết kế bảo mật:
/// - Sử dụng đường cong NIST P-256
/// - Keys được export ở định dạng SPKI để tương thích
/// - Xác thực peer public keys trước khi tính shared secret
/// 
/// Cách sử dụng:
/// 1. Gọi GenerateKeyPairAsync() để tạo cặp khóa cục bộ
/// 2. Gửi GetPublicKey() đến peer
/// 3. Nhận public key của peer
/// 4. Gọi DeriveSharedSecretAsync(peerKey) để lấy shared secret
/// 5. Sử dụng HKDF để tính encryption keys từ shared secret
/// </summary>
public sealed class EcdhKeyExchange : Interfaces.IKeyExchange, IDisposable
{
    private ECDiffieHellman? _ecdh;
    private byte[]? _publicKey;
    private bool _disposed;

    /// <inheritdoc />
    public string AlgorithmIdentifier => "ECDH-P256";

    /// <inheritdoc />
    public Task GenerateKeyPairAsync()
    {
        ThrowIfDisposed();
        
        // Dispose cặp khóa trước đó nếu tồn tại
        _ecdh?.Dispose();
        
        // Tạo instance ECDH mới với đường cong P-256
        _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        
        // Export public key ở định dạng SPKI để tương thích
        _publicKey = _ecdh.ExportSubjectPublicKeyInfo();
        
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public string GetPublicKey()
    {
        ThrowIfDisposed();
        
        if (_publicKey is null)
        {
            throw new InvalidOperationException(
                "Cặp khóa chưa được tạo. Gọi GenerateKeyPairAsync trước.");
        }
        
        return Convert.ToBase64String(_publicKey);
    }

    /// <inheritdoc />
    public Task<string> DeriveSharedSecretAsync(string peerPublicKey)
    {
        ThrowIfDisposed();
        
        if (_ecdh is null)
        {
            throw new InvalidOperationException(
                "Cặp khóa chưa được tạo. Gọi GenerateKeyPairAsync trước.");
        }

        if (!ValidatePublicKey(peerPublicKey))
        {
            throw new ArgumentException(
                "Định dạng hoặc tham số peer public key không hợp lệ", nameof(peerPublicKey));
        }

        // Import public key của peer
        var peerKeyBytes = Convert.FromBase64String(peerPublicKey);
        using var peerEcdh = ECDiffieHellman.Create();
        peerEcdh.ImportSubjectPublicKeyInfo(peerKeyBytes, out _);

        // Tính shared secret sử dụng ECDH
        // Lưu ý bảo mật: Raw shared secret này cần được đưa qua HKDF
        // trước khi sử dụng làm encryption key
        var sharedSecret = _ecdh.DeriveKeyMaterial(peerEcdh.PublicKey);

        return Task.FromResult(Convert.ToBase64String(sharedSecret));
    }

    /// <inheritdoc />
    public bool ValidatePublicKey(string publicKey)
    {
        if (string.IsNullOrWhiteSpace(publicKey))
        {
            return false;
        }

        try
        {
            // Thử decode và parse key
            var keyBytes = Convert.FromBase64String(publicKey);
            
            // Xác thực bằng cách thử import
            using var testEcdh = ECDiffieHellman.Create();
            testEcdh.ImportSubjectPublicKeyInfo(keyBytes, out int bytesRead);
            
            // Đảm bảo tất cả bytes đã được tiêu thụ
            if (bytesRead != keyBytes.Length)
            {
                return false;
            }

            // Xác minh key trên đường cong P-256
            var parameters = testEcdh.ExportParameters(includePrivateParameters: false);
            if (parameters.Curve.Oid?.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
            {
                // Cho phép nếu curve khớp theo tên
                if (parameters.Curve.Oid?.FriendlyName != "nistP256" &&
                    parameters.Curve.Oid?.FriendlyName != "ECDSA_P256")
                {
                    return false;
                }
            }

            return true;
        }
        catch (FormatException)
        {
            // Base64 không hợp lệ
            return false;
        }
        catch (CryptographicException)
        {
            // Định dạng key không hợp lệ hoặc weak key
            return false;
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(EcdhKeyExchange));
        }
    }

    /// <summary>
    /// Giải phóng tài nguyên mật mã một cách an toàn
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        
        _ecdh?.Dispose();
        _ecdh = null;
        
        // Xóa public key khỏi bộ nhớ
        if (_publicKey is not null)
        {
            CryptographicOperations.ZeroMemory(_publicKey);
            _publicKey = null;
        }
        
        _disposed = true;
    }
}
