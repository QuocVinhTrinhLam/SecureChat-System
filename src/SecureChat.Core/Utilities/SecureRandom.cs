using System.Security.Cryptography;

namespace SecureChat.Core.Utilities;

public static class SecureRandom
{
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
    
    public static string GetBase64String(int byteLength)
    {
        var bytes = GetBytes(byteLength);
        return Convert.ToBase64String(bytes);
    }
    
    public static string GetUrlSafeBase64String(int byteLength)
    {
        var bytes = GetBytes(byteLength);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
    
    public static string GetHexString(int byteLength)
    {
        var bytes = GetBytes(byteLength);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
    
    public static int GetInt32()
    {
        var bytes = GetBytes(4);
        return BitConverter.ToInt32(bytes, 0);
    }
    
    public static int GetNonNegativeInt32()
    {
        return GetInt32() & int.MaxValue;
    }
    
    public static int GetInt32(int minValue, int maxValue)
    {
        if (minValue >= maxValue)
        {
            throw new ArgumentException("minValue must be less than maxValue");
        }
        
        // Use the built-in unbiased method from .NET 6+
        return RandomNumberGenerator.GetInt32(minValue, maxValue);
    }
    
    public static Guid NewGuid()
    {
        return Guid.NewGuid();
    }
}
