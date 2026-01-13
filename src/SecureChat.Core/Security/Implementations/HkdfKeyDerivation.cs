using System.Security.Cryptography;
using System.Text;

namespace SecureChat.Core.Security.Implementations;

/// <summary>
/// HKDF (HMAC-based Key Derivation Function) utility for deriving session keys.
/// 
/// Security Design:
/// - Derives separate keys for encryption and MAC from a single shared secret
/// - Uses SHA-256 as the underlying hash function
/// - Context-specific "info" parameters ensure key separation
/// - Follows RFC 5869 for HKDF implementation
/// 
/// Usage:
/// 1. Obtain shared secret from ECDH key exchange
/// 2. Call DeriveSessionKeys() to get encryption and MAC keys
/// 3. Use encryption key for AES-256-GCM
/// 4. Use MAC key for additional HMAC if needed
/// </summary>
public static class HkdfKeyDerivation
{
    /// <summary>
    /// Derived key length in bytes (256 bits).
    /// </summary>
    private const int KeyLength = 32;

    /// <summary>
    /// Protocol version identifier for key derivation context.
    /// </summary>
    private const string ProtocolVersion = "SecureChat-v1";

    /// <summary>
    /// Derives encryption and MAC keys from a shared secret.
    /// </summary>
    /// <param name="sharedSecret">Base64-encoded shared secret from ECDH.</param>
    /// <param name="salt">Optional salt (32 bytes recommended). Uses zeros if null.</param>
    /// <returns>Tuple of (encryptionKey, macKey) as Base64-encoded strings.</returns>
    /// <remarks>
    /// Security: The shared secret should come from a secure key exchange (ECDH).
    /// Using different "info" parameters ensures the derived keys are cryptographically
    /// independent even though they come from the same shared secret.
    /// </remarks>
    public static (string encryptionKey, string macKey) DeriveSessionKeys(
        string sharedSecret, byte[]? salt = null)
    {
        ArgumentNullException.ThrowIfNull(sharedSecret);

        var sharedSecretBytes = Convert.FromBase64String(sharedSecret);
        
        // Use 32 zero bytes as default salt if not provided
        salt ??= new byte[32];

        // Derive encryption key with encryption-specific context
        var encKey = HKDF.DeriveKey(
            hashAlgorithmName: HashAlgorithmName.SHA256,
            ikm: sharedSecretBytes,
            outputLength: KeyLength,
            salt: salt,
            info: Encoding.UTF8.GetBytes($"{ProtocolVersion}-encryption-key"));

        // Derive MAC key with MAC-specific context
        var macKey = HKDF.DeriveKey(
            hashAlgorithmName: HashAlgorithmName.SHA256,
            ikm: sharedSecretBytes,
            outputLength: KeyLength,
            salt: salt,
            info: Encoding.UTF8.GetBytes($"{ProtocolVersion}-mac-key"));

        // Clear shared secret from memory
        CryptographicOperations.ZeroMemory(sharedSecretBytes);

        return (
            encryptionKey: Convert.ToBase64String(encKey),
            macKey: Convert.ToBase64String(macKey)
        );
    }

    /// <summary>
    /// Derives a single key for a specific purpose.
    /// </summary>
    /// <param name="sharedSecret">Base64-encoded shared secret from ECDH.</param>
    /// <param name="purpose">Key purpose identifier (e.g., "client-to-server").</param>
    /// <param name="salt">Optional salt. Uses zeros if null.</param>
    /// <returns>Base64-encoded derived key.</returns>
    public static string DeriveKey(string sharedSecret, string purpose, byte[]? salt = null)
    {
        ArgumentNullException.ThrowIfNull(sharedSecret);
        ArgumentNullException.ThrowIfNull(purpose);

        var sharedSecretBytes = Convert.FromBase64String(sharedSecret);
        salt ??= new byte[32];

        var derivedKey = HKDF.DeriveKey(
            hashAlgorithmName: HashAlgorithmName.SHA256,
            ikm: sharedSecretBytes,
            outputLength: KeyLength,
            salt: salt,
            info: Encoding.UTF8.GetBytes($"{ProtocolVersion}-{purpose}"));

        // Clear shared secret from memory
        CryptographicOperations.ZeroMemory(sharedSecretBytes);

        return Convert.ToBase64String(derivedKey);
    }

    /// <summary>
    /// Derives session keys with a unique session ID incorporated into the salt.
    /// This provides additional domain separation between sessions.
    /// </summary>
    /// <param name="sharedSecret">Base64-encoded shared secret from ECDH.</param>
    /// <param name="sessionId">Unique session identifier.</param>
    /// <returns>Tuple of (encryptionKey, macKey) as Base64-encoded strings.</returns>
    public static (string encryptionKey, string macKey) DeriveSessionKeysWithId(
        string sharedSecret, string sessionId)
    {
        ArgumentNullException.ThrowIfNull(sharedSecret);
        ArgumentNullException.ThrowIfNull(sessionId);

        // Use session ID as part of salt for domain separation
        var sessionIdBytes = Encoding.UTF8.GetBytes(sessionId);
        var salt = new byte[32];
        
        // Copy session ID bytes into salt (truncate or pad as needed)
        var copyLength = Math.Min(sessionIdBytes.Length, salt.Length);
        Array.Copy(sessionIdBytes, salt, copyLength);

        return DeriveSessionKeys(sharedSecret, salt);
    }
}
