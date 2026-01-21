namespace SecureChat.Core.Security.Interfaces;
/// <summary>
/// Defines key exchange contract for secure session establishment
/// </summary>
public interface IKeyExchange
{
    /// <summary>
    /// Identifier of the key exchange algorithm
    /// </summary>
    string AlgorithmIdentifier { get; }
    /// <summary>
    /// Generate public/private key pair
    /// </summary>
    Task GenerateKeyPairAsync();
    /// <summary>
    /// Get public key to send to peer
    /// </summary>
    string GetPublicKey();
    /// <summary>
    /// Derive shared secret from peer public key
    /// </summary>
    Task<string> DeriveSharedSecretAsync(string peerPublicKey);
    /// <summary>
    /// Validate received public key
    /// </summary>
    bool ValidatePublicKey(string publicKey);
}
