namespace SecureChat.Core.Security.Interfaces;

/// <summary>
/// Abstraction for asymmetric key exchange operations.
/// 
/// Security Design:
/// - Enables pluggable key exchange algorithms (RSA, ECDH, etc.)
/// - Session keys derived from key exchange are used for symmetric encryption
/// - Implementations must validate peer public keys to prevent MITM attacks
/// 
/// Future Implementation Notes:
/// - Prefer ECDH over RSA for key exchange (better performance, smaller keys)
/// - Use X25519 for modern, secure key agreement
/// - Consider adding key derivation function (HKDF) for session key generation
/// </summary>
public interface IKeyExchange
{
    /// <summary>
    /// Generates a new key pair for this session.
    /// Security: Private key must never leave the local process.
    /// </summary>
    /// <returns>Task representing the async operation.</returns>
    Task GenerateKeyPairAsync();
    
    /// <summary>
    /// Gets the public key to share with the peer.
    /// Security: Safe to transmit over insecure channel.
    /// </summary>
    /// <returns>Base64-encoded public key.</returns>
    string GetPublicKey();
    
    /// <summary>
    /// Derives a shared secret using peer's public key.
    /// Security Critical: The shared secret is sensitive! 
    /// Use key derivation (HKDF) before using as encryption key.
    /// </summary>
    /// <param name="peerPublicKey">Base64-encoded public key from peer.</param>
    /// <returns>Base64-encoded shared secret.</returns>
    /// <exception cref="ArgumentException">If peer key is invalid.</exception>
    /// <exception cref="InvalidOperationException">If local key pair not generated.</exception>
    Task<string> DeriveSharedSecretAsync(string peerPublicKey);
    
    /// <summary>
    /// Validates a peer's public key.
    /// Security: Must check for weak keys, invalid points (ECDH), etc.
    /// </summary>
    /// <param name="publicKey">Base64-encoded public key to validate.</param>
    /// <returns>True if key is valid and safe to use.</returns>
    bool ValidatePublicKey(string publicKey);
    
    /// <summary>
    /// Gets the algorithm identifier for this key exchange.
    /// Used in message SecurityMetadata.
    /// </summary>
    string AlgorithmIdentifier { get; }
}
