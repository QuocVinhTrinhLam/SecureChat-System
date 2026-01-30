namespace SecureChat.Core.Security.Interfaces;
public interface IKeyExchange
{
    string AlgorithmIdentifier { get; }
    Task GenerateKeyPairAsync();
    string GetPublicKey();
    Task<string> DeriveSharedSecretAsync(string peerPublicKey);
    bool ValidatePublicKey(string publicKey);
}
