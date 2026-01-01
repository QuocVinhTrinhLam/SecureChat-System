using System.Security.Cryptography;

namespace SecureChat.Core.Utilities;

/// <summary>
/// Wrapper around System.Security.Cryptography.RandomNumberGenerator
/// for generating cryptographically secure random values.
/// 
/// Security Design:
/// - Centralizes all random number generation for easy auditing
/// - Uses only cryptographically secure sources
/// - Provides convenient methods for common use cases
/// 
/// NEVER use System.Random for security-sensitive operations!
/// System.Random is predictable and NOT suitable for:
/// - Key generation
/// - Nonce/IV generation
/// - Session tokens
/// - Any security-related randomness
/// </summary>
public static class SecureRandom
{
    /// <summary>
    /// Generates random bytes using a cryptographically secure RNG.
    /// </summary>
    /// <param name="length">Number of bytes to generate.</param>
    /// <returns>Array of random bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If length is negative.</exception>
    public static byte[] GetBytes(int length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "Length must be non-negative");
        }
        
        if (length == 0)
        {
            return Array.Empty<byte>();
        }
        
        var bytes = new byte[length];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }
    
    /// <summary>
    /// Generates a random Base64-encoded string.
    /// Useful for tokens, session IDs, etc.
    /// </summary>
    /// <param name="byteLength">Number of random bytes (Base64 output will be longer).</param>
    /// <returns>Base64-encoded random string.</returns>
    public static string GetBase64String(int byteLength)
    {
        var bytes = GetBytes(byteLength);
        return Convert.ToBase64String(bytes);
    }
    
    /// <summary>
    /// Generates a random URL-safe Base64 string.
    /// Uses - and _ instead of + and / for URL compatibility.
    /// </summary>
    /// <param name="byteLength">Number of random bytes.</param>
    /// <returns>URL-safe Base64-encoded string.</returns>
    public static string GetUrlSafeBase64String(int byteLength)
    {
        var bytes = GetBytes(byteLength);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
    
    /// <summary>
    /// Generates a random hexadecimal string.
    /// </summary>
    /// <param name="byteLength">Number of random bytes (hex output is 2x this length).</param>
    /// <returns>Lowercase hexadecimal string.</returns>
    public static string GetHexString(int byteLength)
    {
        var bytes = GetBytes(byteLength);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
    
    /// <summary>
    /// Generates a random 32-bit integer.
    /// Security: Uses cryptographic RNG, not System.Random.
    /// </summary>
    /// <returns>Random 32-bit integer.</returns>
    public static int GetInt32()
    {
        var bytes = GetBytes(4);
        return BitConverter.ToInt32(bytes, 0);
    }
    
    /// <summary>
    /// Generates a random non-negative 32-bit integer.
    /// </summary>
    /// <returns>Random non-negative integer.</returns>
    public static int GetNonNegativeInt32()
    {
        return GetInt32() & int.MaxValue;
    }
    
    /// <summary>
    /// Generates a random integer within the specified range.
    /// Security: Uses rejection sampling to avoid modulo bias.
    /// </summary>
    /// <param name="minValue">Inclusive minimum value.</param>
    /// <param name="maxValue">Exclusive maximum value.</param>
    /// <returns>Random integer in [minValue, maxValue).</returns>
    public static int GetInt32(int minValue, int maxValue)
    {
        if (minValue >= maxValue)
        {
            throw new ArgumentException("minValue must be less than maxValue");
        }
        
        // Use the built-in unbiased method from .NET 6+
        return RandomNumberGenerator.GetInt32(minValue, maxValue);
    }
    
    /// <summary>
    /// Generates a new GUID using cryptographic randomness.
    /// Note: Standard Guid.NewGuid() already uses crypto RNG on modern .NET.
    /// </summary>
    /// <returns>A new random GUID.</returns>
    public static Guid NewGuid()
    {
        return Guid.NewGuid();
    }
}
