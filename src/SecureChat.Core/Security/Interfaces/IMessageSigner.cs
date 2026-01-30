namespace SecureChat.Core.Security.Interfaces;

public interface IMessageSigner
{
    Task<string> SignAsync(string data, string key);
    
    Task<bool> VerifyAsync(string data, string signature, string key);
    
    string GenerateKey();
    
    string AlgorithmIdentifier { get; }
}
