namespace SecureChat.Core.Security.Interfaces;

/// <summary>
/// Abstraction for message integrity and authenticity verification
/// 
/// Security Purpose:
/// - Ensures messages haven't been tampered with in transit
/// - Provides sender authenticity
/// - Prevents message forgery attacks
/// 
/// Implementation Options:
/// - HMAC-SHA256: Fast, symmetric, requires shared key
/// - RSA-PSS: Asymmetric, provides non-repudiation
/// - ECDSA: Asymmetric, smaller signatures than RSA
/// 
/// Security Notes:
/// - Sign-then-encrypt is generally preferred over encrypt-then-sign
/// - Include message ID and timestamp in signed data to prevent replay
/// - Use constant-time comparison for signature verification
/// </summary>
public interface IMessageSigner
{
    /// <summary>
    /// Signs the provided data.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="key">
    /// For HMAC: Base64-encoded shared secret key
    /// For asymmetric: Base64-encoded private key
    /// </param>
    /// <returns>Base64-encoded signature.</returns>
    /// <remarks>
    /// Security: The key parameter must be kept secret
    /// For asymmetric signing, this should be the sender's private key
    /// </remarks>
    Task<string> SignAsync(string data, string key);
    
    /// <summary>
    /// Verifies a signature against the provided data
    /// </summary>
    /// <param name="data">The original signed data.</param>
    /// <param name="signature">Base64-encoded signature to verify.</param>
    /// <param name="key">
    /// For HMAC: Base64-encoded shared secret key
    /// For asymmetric: Base64-encoded public key
    /// </param>
    /// <returns>True if signature is valid, false otherwise.</returns>
    /// <remarks>
    /// Security Critical: Must use constant-time comparison to prevent timing attacks
    /// Never throw exceptions for invalid signatures - return false instead
    /// </remarks>
    Task<bool> VerifyAsync(string data, string signature, string key);
    
    /// <summary>
    /// Generates a key suitable for this signing algorithm
    /// For HMAC, generates a random key
    /// For asymmetric, generates a key pair
    /// </summary>
    /// <returns>Base64-encoded key material.</returns>
    string GenerateKey();
    
    /// <summary>
    /// Gets the algorithm identifier for message metadata
    /// </summary>
    string AlgorithmIdentifier { get; }
}
