namespace SecureChat.Core.Security.Stubs;

using SecureChat.Core.Security.Interfaces;

public sealed class PlaceholderEncryption : ISymmetricEncryption
{
    /// <inheritdoc />
    public int KeySizeBits => 256;
    
    /// <inheritdoc />
    public string AlgorithmIdentifier => "PLACEHOLDER-NONE";
    
    /// <inheritdoc />
    public Task<(string ciphertext, string iv, string tag)> EncryptAsync(string plaintext, string key)
    {
        Console.WriteLine("[SECURITY WARNING] Using placeholder encryption - NOT SECURE!");
        
        // STUB: Just Base64 encode
        // Real implementation: AesGcm.Encrypt() with random nonce
        var fakeCiphertext = Convert.ToBase64String(
            System.Text.Encoding.Unicode.GetBytes(plaintext)
        );
        
        // Generate fake IV (real impl: RandomNumberGenerator.GetBytes(12))
        var fakeIv = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
        
        // Generate fake auth tag (real impl: output from AesGcm.Encrypt)
        var fakeTag = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
        
        return Task.FromResult((fakeCiphertext, fakeIv, fakeTag));
    }
    
    /// <inheritdoc />
    public Task<string> DecryptAsync(string ciphertext, string key, string iv, string tag)
    {
        Console.WriteLine("[SECURITY WARNING] Using placeholder decryption - NOT SECURE!");
        
        try
        {
            // STUB: Just Base64 decode
            // Real implementation: 
            // 1. Validate tag length
            // 2. AesGcm.Decrypt() - this verifies the auth tag
            // 3. Return plaintext only if tag verification succeeds
            var plaintext = System.Text.Encoding.Unicode.GetString(
                Convert.FromBase64String(ciphertext)
            );
            
            return Task.FromResult(plaintext);
        }
        catch (FormatException)
        {
            // Security: Don't reveal why decryption failed
            throw new System.Security.Cryptography.CryptographicException("Decryption failed");
        }
    }
    
    /// <inheritdoc />
    public string GenerateKey()
    {
        // STUB: Generate random bytes
        // Real implementation should also use RandomNumberGenerator
        var keyBytes = new byte[KeySizeBits / 8];
        System.Security.Cryptography.RandomNumberGenerator.Fill(keyBytes);
        return Convert.ToBase64String(keyBytes);
    }
}
