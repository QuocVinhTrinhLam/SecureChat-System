using System.Security.Cryptography;
using System.Text;

namespace SecureChat.Core.Security.Implementations;

/// <summary>
/// HMAC-SHA256 message signing implementation.
/// 
/// Security Design:
/// - Uses 256-bit keys for HMAC
/// - SHA-256 provides 256-bit security strength
/// - Constant-time signature verification to prevent timing attacks
/// 
/// Usage:
/// - For message authentication when using encrypt-then-MAC pattern
/// - Can be used with the MAC key derived via HKDF from shared secret
/// </summary>
public sealed class HmacSha256Signer : Interfaces.IMessageSigner
{
    /// <summary>
    /// Recommended key size in bytes (256 bits).
    /// </summary>
    private const int KeySizeBytes = 32;

    /// <inheritdoc />
    public string AlgorithmIdentifier => "HMAC-SHA256";

    /// <inheritdoc />
    public Task<string> SignAsync(string data, string key)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(key);

        var keyBytes = Convert.FromBase64String(key);
        var dataBytes = Encoding.UTF8.GetBytes(data);

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
            var dataBytes = Encoding.UTF8.GetBytes(data);
            var expectedSignature = Convert.FromBase64String(signature);

            byte[] computedSignature;
            using (var hmac = new HMACSHA256(keyBytes))
            {
                computedSignature = hmac.ComputeHash(dataBytes);
            }

            // CRITICAL: Use constant-time comparison to prevent timing attacks
            // Never use == or SequenceEqual for cryptographic comparisons
            return Task.FromResult(
                CryptographicOperations.FixedTimeEquals(computedSignature, expectedSignature));
        }
        catch (FormatException)
        {
            // Invalid Base64 - return false, don't throw
            // This prevents distinguishing between format errors and signature mismatches
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
