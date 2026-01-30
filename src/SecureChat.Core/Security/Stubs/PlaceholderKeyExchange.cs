namespace SecureChat.Core.Security.Stubs;
using SecureChat.Core.Security.Interfaces;

public sealed class PlaceholderKeyExchange : IKeyExchange
{
    private string? _publicKey;
    private string? _privateKey;
    
    /// <inheritdoc />
    public string AlgorithmIdentifier => "PLACEHOLDER-NONE";
    
    /// <inheritdoc />
    public Task GenerateKeyPairAsync()
    {
        // STUB: Generate fake keys for testing protocol flow
        // Security Note: Real implementation must use ECDiffieHellman.Create()
        _privateKey = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
        _publicKey = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
        
        Console.WriteLine("[SECURITY WARNING] Using placeholder key exchange - NOT SECURE!");
        
        return Task.CompletedTask;
    }
    
    /// <inheritdoc />
    public string GetPublicKey()
    {
        if (_publicKey is null)
        {
            throw new InvalidOperationException("Key pair not generated. Call GenerateKeyPairAsync first.");
        }
        return _publicKey;
    }
    
    /// <inheritdoc />
    public Task<string> DeriveSharedSecretAsync(string peerPublicKey)
    {
        if (_privateKey is null)
        {
            throw new InvalidOperationException("Key pair not generated. Call GenerateKeyPairAsync first.");
        }
        
        if (!ValidatePublicKey(peerPublicKey))
        {
            throw new ArgumentException("Invalid peer public key", nameof(peerPublicKey));
        }
        
        // STUB: Return a deterministic fake shared secret
        // Real implementation: ECDiffieHellman.DeriveKeyMaterial()
        var fakeSecret = Convert.ToBase64String(
            System.Text.Encoding.Unicode.GetBytes("PLACEHOLDER_SHARED_SECRET_32CHR!")
        );
        
        return Task.FromResult(fakeSecret);
    }
    
    /// <inheritdoc />
    public bool ValidatePublicKey(string publicKey)
    {
        // STUB: Basic non-empty check
        // Real implementation must:
        // - Validate key format
        // - Check for weak/invalid curve points
        // - Verify key is on the expected curve
        return !string.IsNullOrWhiteSpace(publicKey);
    }
}
