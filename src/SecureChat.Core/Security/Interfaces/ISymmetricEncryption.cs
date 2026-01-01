namespace SecureChat.Core.Security.Interfaces;

/// <summary>
/// Abstraction for symmetric encryption operations.
/// 
/// Security Design:
/// - Used for encrypting message content after key exchange
/// - Must use authenticated encryption (AEAD) to prevent tampering
/// - IV/nonce management is critical - NEVER reuse!
/// 
/// Recommended Implementations:
/// - AES-256-GCM (NIST standard, widely supported)
/// - ChaCha20-Poly1305 (excellent for software implementations)
/// 
/// Security Requirements for Implementations:
/// - Use 256-bit keys minimum
/// - Generate cryptographically random IVs for each message
/// - Verify authentication tag before returning plaintext
/// - Zeroize sensitive key material after use
/// </summary>
public interface ISymmetricEncryption
{
    /// <summary>
    /// Encrypts plaintext using the provided key.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="key">Base64-encoded encryption key.</param>
    /// <returns>
    /// Tuple containing:
    /// - ciphertext: Base64-encoded encrypted data
    /// - iv: Base64-encoded initialization vector (unique per message!)
    /// - tag: Base64-encoded authentication tag (for AEAD modes)
    /// </returns>
    /// <remarks>
    /// Security: The IV is generated internally and must be cryptographically random.
    /// Never accept an IV from external input for encryption operations.
    /// </remarks>
    Task<(string ciphertext, string iv, string tag)> EncryptAsync(string plaintext, string key);
    
    /// <summary>
    /// Decrypts ciphertext using the provided key.
    /// </summary>
    /// <param name="ciphertext">Base64-encoded encrypted data.</param>
    /// <param name="key">Base64-encoded encryption key.</param>
    /// <param name="iv">Base64-encoded initialization vector.</param>
    /// <param name="tag">Base64-encoded authentication tag.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Thrown if decryption fails or authentication tag is invalid.
    /// Security: Do not distinguish between padding errors and auth failures!
    /// </exception>
    Task<string> DecryptAsync(string ciphertext, string key, string iv, string tag);
    
    /// <summary>
    /// Generates a cryptographically secure random key.
    /// </summary>
    /// <returns>Base64-encoded key of appropriate length for the algorithm.</returns>
    string GenerateKey();
    
    /// <summary>
    /// Gets the key size in bits for this algorithm.
    /// </summary>
    int KeySizeBits { get; }
    
    /// <summary>
    /// Gets the algorithm identifier for message metadata.
    /// </summary>
    string AlgorithmIdentifier { get; }
}
