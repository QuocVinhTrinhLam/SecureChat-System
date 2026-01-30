namespace SecureChat.Core.Security.Interfaces;

public interface ISymmetricEncryption
{
    Task<(string ciphertext, string iv, string tag)> EncryptAsync(string plaintext, string key);
    
    Task<string> DecryptAsync(string ciphertext, string key, string iv, string tag);
    
    string GenerateKey();
    
    int KeySizeBits { get; }
    
    string AlgorithmIdentifier { get; }
}
