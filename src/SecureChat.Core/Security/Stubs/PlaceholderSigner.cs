namespace SecureChat.Core.Security.Stubs;

using SecureChat.Core.Security.Interfaces;

/// <summary>
/// Placeholder implementation of IMessageSigner for foundation phase.
/// 
/// WARNING: This provides NO cryptographic signing!
/// This stub exists to allow the system architecture to be tested
/// before cryptographic primitives are implemented.
/// 
/// TODO (Phase 2): Replace with HMAC-SHA256 implementation using:
/// - System.Security.Cryptography.HMACSHA256
/// - Constant-time comparison for verification
/// - Alternatively, consider ECDSA for non-repudiation
/// </summary>
public sealed class PlaceholderSigner : IMessageSigner
{
    /// <inheritdoc />
    public string AlgorithmIdentifier => "PLACEHOLDER-NONE";
    
    /// <inheritdoc />
    public Task<string> SignAsync(string data, string key)
    {
        Console.WriteLine("[SECURITY WARNING] Using placeholder signer - NOT SECURE!");
        
        // STUB: Just return a fake signature based on data hash
        // Real implementation: HMACSHA256.ComputeHash() or ECDSA.SignData()
        var dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
        var hashCode = data.GetHashCode(); // NOT cryptographically secure!
        
        var fakeSignature = Convert.ToBase64String(
            BitConverter.GetBytes(hashCode)
        );
        
        return Task.FromResult(fakeSignature);
    }
    
    /// <inheritdoc />
    public Task<bool> VerifyAsync(string data, string signature, string key)
    {
        Console.WriteLine("[SECURITY WARNING] Using placeholder verification - NOT SECURE!");
        
        // STUB: Recompute fake signature and compare
        // Real implementation MUST use constant-time comparison:
        // CryptographicOperations.FixedTimeEquals()
        
        try
        {
            var expectedSignature = SignAsync(data, key).Result;
            
            // WARNING: String comparison is NOT constant-time!
            // This is vulnerable to timing attacks.
            // Real impl: Convert both to bytes and use FixedTimeEquals
            return Task.FromResult(signature == expectedSignature);
        }
        catch
        {
            // Security: Don't expose verification failure reasons
            return Task.FromResult(false);
        }
    }
    
    /// <inheritdoc />
    public string GenerateKey()
    {
        // Generate a random key suitable for HMAC
        // This part uses proper cryptographic RNG
        var keyBytes = new byte[32]; // 256 bits
        System.Security.Cryptography.RandomNumberGenerator.Fill(keyBytes);
        return Convert.ToBase64String(keyBytes);
    }
}
