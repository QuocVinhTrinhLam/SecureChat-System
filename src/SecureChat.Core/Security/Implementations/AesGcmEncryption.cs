using System.Security.Cryptography;
using System.Text;

namespace SecureChat.Core.Security.Implementations;

/// <summary>
/// AES-256-GCM authenticated encryption implementation.
/// 
/// Security Design:
/// - Uses 256-bit keys for maximum security
/// - 96-bit (12-byte) nonces as recommended by NIST SP 800-38D
/// - 128-bit (16-byte) authentication tags
/// - Cryptographically random nonces generated for each encryption
/// 
/// Security Notes:
/// - NEVER reuse a nonce with the same key
/// - Authentication tag verification happens during decryption
/// - Decryption fails atomically if tag doesn't match (no partial plaintext)
/// </summary>
public sealed class AesGcmEncryption : Interfaces.ISymmetricEncryption
{
    /// <summary>
    /// Nonce size in bytes (96 bits as per NIST recommendation).
    /// </summary>
    private const int NonceSize = 12;
    
    /// <summary>
    /// Authentication tag size in bytes (128 bits for maximum security).
    /// </summary>
    private const int TagSize = 16;

    /// <inheritdoc />
    public int KeySizeBits => 256;

    /// <inheritdoc />
    public string AlgorithmIdentifier => "AES-256-GCM";

    /// <inheritdoc />
    public Task<(string ciphertext, string iv, string tag)> EncryptAsync(
        string plaintext, string key)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(key);

        var keyBytes = Convert.FromBase64String(key);
        ValidateKeySize(keyBytes);

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

        // Generate cryptographically random nonce
        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        // Prepare output buffers
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagSize];

        // Encrypt using AES-GCM
        using var aesGcm = new AesGcm(keyBytes, TagSize);
        aesGcm.Encrypt(
            nonce: nonce,
            plaintext: plaintextBytes,
            ciphertext: ciphertext,
            tag: tag,
            associatedData: null);

        // Clear sensitive data from memory
        CryptographicOperations.ZeroMemory(plaintextBytes);

        return Task.FromResult((
            ciphertext: Convert.ToBase64String(ciphertext),
            iv: Convert.ToBase64String(nonce),
            tag: Convert.ToBase64String(tag)
        ));
    }

    /// <inheritdoc />
    public Task<string> DecryptAsync(
        string ciphertext, string key, string iv, string tag)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(iv);
        ArgumentNullException.ThrowIfNull(tag);

        byte[]? plaintextBytes = null;
        
        try
        {
            var keyBytes = Convert.FromBase64String(key);
            ValidateKeySize(keyBytes);

            var ciphertextBytes = Convert.FromBase64String(ciphertext);
            var nonceBytes = Convert.FromBase64String(iv);
            var tagBytes = Convert.FromBase64String(tag);

            // Validate nonce and tag sizes
            if (nonceBytes.Length != NonceSize)
            {
                throw new CryptographicException("Invalid nonce size");
            }
            if (tagBytes.Length != TagSize)
            {
                throw new CryptographicException("Invalid tag size");
            }

            plaintextBytes = new byte[ciphertextBytes.Length];

            // Decrypt and verify authentication tag
            using var aesGcm = new AesGcm(keyBytes, TagSize);
            aesGcm.Decrypt(
                nonce: nonceBytes,
                ciphertext: ciphertextBytes,
                tag: tagBytes,
                plaintext: plaintextBytes,
                associatedData: null);

            return Task.FromResult(Encoding.UTF8.GetString(plaintextBytes));
        }
        catch (FormatException)
        {
            // Invalid Base64 - don't reveal which parameter
            throw new CryptographicException("Decryption failed");
        }
        catch (AuthenticationTagMismatchException)
        {
            // Tag verification failed - possible tampering
            throw new CryptographicException("Decryption failed - authentication failed");
        }
        finally
        {
            // Clear plaintext from memory on any path
            if (plaintextBytes is not null)
            {
                CryptographicOperations.ZeroMemory(plaintextBytes);
            }
        }
    }

    /// <inheritdoc />
    public string GenerateKey()
    {
        var keyBytes = new byte[KeySizeBits / 8];
        RandomNumberGenerator.Fill(keyBytes);
        return Convert.ToBase64String(keyBytes);
    }

    /// <summary>
    /// Validates that the key is the correct size.
    /// </summary>
    private void ValidateKeySize(byte[] key)
    {
        if (key.Length != KeySizeBits / 8)
        {
            throw new ArgumentException(
                $"Key must be exactly {KeySizeBits / 8} bytes ({KeySizeBits} bits)",
                nameof(key));
        }
    }
}
