using SecureChat.Core.Security.Implementations;
using System.Security.Cryptography;
using Xunit;

namespace SecureChat.Tests;

/// <summary>
/// Tests for AES-256-GCM encryption implementation.
/// </summary>
public class AesGcmEncryptionTests
{
    private readonly AesGcmEncryption _encryption = new();

    [Fact]
    public async Task EncryptDecrypt_RoundTrip_ReturnsOriginalPlaintext()
    {
        // Arrange
        var plaintext = "Hello, Secure World! 🔐";
        var key = _encryption.GenerateKey();
        
        // Act
        var (ciphertext, iv, tag) = await _encryption.EncryptAsync(plaintext, key);
        var decrypted = await _encryption.DecryptAsync(ciphertext, key, iv, tag);
        
        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task Encrypt_SamePlaintext_ProducesDifferentCiphertext()
    {
        // Arrange - Same plaintext should produce different ciphertext due to random IV
        var plaintext = "Same message";
        var key = _encryption.GenerateKey();
        
        // Act
        var result1 = await _encryption.EncryptAsync(plaintext, key);
        var result2 = await _encryption.EncryptAsync(plaintext, key);
        
        // Assert
        Assert.NotEqual(result1.ciphertext, result2.ciphertext);
        Assert.NotEqual(result1.iv, result2.iv);
    }

    [Fact]
    public async Task Decrypt_TamperedCiphertext_ThrowsCryptographicException()
    {
        // Arrange
        var plaintext = "Original message";
        var key = _encryption.GenerateKey();
        var (ciphertext, iv, tag) = await _encryption.EncryptAsync(plaintext, key);
        
        // Tamper with ciphertext
        var bytes = Convert.FromBase64String(ciphertext);
        bytes[0] ^= 0xFF;  // Flip bits
        var tamperedCiphertext = Convert.ToBase64String(bytes);
        
        // Act & Assert
        await Assert.ThrowsAsync<CryptographicException>(
            () => _encryption.DecryptAsync(tamperedCiphertext, key, iv, tag));
    }

    [Fact]
    public async Task Decrypt_WrongKey_ThrowsCryptographicException()
    {
        // Arrange
        var plaintext = "Secret message";
        var correctKey = _encryption.GenerateKey();
        var wrongKey = _encryption.GenerateKey();
        
        var (ciphertext, iv, tag) = await _encryption.EncryptAsync(plaintext, correctKey);
        
        // Act & Assert
        await Assert.ThrowsAsync<CryptographicException>(
            () => _encryption.DecryptAsync(ciphertext, wrongKey, iv, tag));
    }

    [Fact]
    public void GenerateKey_ProducesCorrectKeySize()
    {
        // Act
        var key = _encryption.GenerateKey();
        var keyBytes = Convert.FromBase64String(key);
        
        // Assert - 256 bits = 32 bytes
        Assert.Equal(32, keyBytes.Length);
    }

    [Fact]
    public void GenerateKey_ProducesUniqueKeys()
    {
        // Act
        var key1 = _encryption.GenerateKey();
        var key2 = _encryption.GenerateKey();
        
        // Assert
        Assert.NotEqual(key1, key2);
    }

    [Fact]
    public void AlgorithmIdentifier_ReturnsExpectedValue()
    {
        // Assert
        Assert.Equal("AES-256-GCM", _encryption.AlgorithmIdentifier);
        Assert.Equal(256, _encryption.KeySizeBits);
    }

    [Fact]
    public async Task Encrypt_LargeMessage_Succeeds()
    {
        // Arrange - Test with a larger message
        var plaintext = new string('A', 100000);  // 100KB
        var key = _encryption.GenerateKey();
        
        // Act
        var (ciphertext, iv, tag) = await _encryption.EncryptAsync(plaintext, key);
        var decrypted = await _encryption.DecryptAsync(ciphertext, key, iv, tag);
        
        // Assert
        Assert.Equal(plaintext, decrypted);
    }
}
