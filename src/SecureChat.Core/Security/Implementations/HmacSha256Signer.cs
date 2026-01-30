using System.Security.Cryptography;
using System.Text;

namespace SecureChat.Core.Security.Implementations;

public sealed class HmacSha256Signer : Interfaces.IMessageSigner
{
    private const int KeySizeBytes = 32;

    /// <inheritdoc />
    public string AlgorithmIdentifier => "HMAC-SHA256";

    /// <inheritdoc />
    public Task<string> SignAsync(string data, string key)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(key);

        var keyBytes = Convert.FromBase64String(key);
        var dataBytes = Encoding.Unicode.GetBytes(data);

        byte[] signature;
        using (var hmac = new HMACSHA256(keyBytes))
        {
            signature = hmac.ComputeHash(dataBytes);
        }

        return Task.FromResult(Convert.ToBase64String(signature));
    }

    /// <inheritdoc />
    public Task<bool> VerifyAsync(string data, string signature, string key)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(key);

        try
        {
            var keyBytes = Convert.FromBase64String(key);
            var dataBytes = Encoding.Unicode.GetBytes(data);
            var expectedSignature = Convert.FromBase64String(signature);

            byte[] computedSignature;
            using (var hmac = new HMACSHA256(keyBytes))
            {
                computedSignature = hmac.ComputeHash(dataBytes);
            }

            // QUAN TRỌNG: Sử dụng so sánh constant-time để ngăn chặn timing attacks
            // Không bao giờ sử dụng == hoặc SequenceEqual cho so sánh mật mã
            return Task.FromResult(
                CryptographicOperations.FixedTimeEquals(computedSignature, expectedSignature));
        }
        catch (FormatException)
        {
            // Base64 không hợp lệ - trả về false, không throw
            // Điều này ngăn chặn phân biệt giữa lỗi định dạng và signature không khớp
            return Task.FromResult(false);
        }
    }

    /// <inheritdoc />
    public string GenerateKey()
    {
        var keyBytes = new byte[KeySizeBytes];
        RandomNumberGenerator.Fill(keyBytes);
        return Convert.ToBase64String(keyBytes);
    }
}
