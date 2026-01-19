using SecureChat.Core.Security.Implementations;
using Xunit;

namespace SecureChat.Tests.Security;
/// <summary>
/// Unit tests for AES-256-GCM encryption/decryption.
/// Verify decrypt utility works correctly.
/// </summary>
public class AesGcmEncryptionTests
{
    [Fact]
    public async Task AesGcm_Decrypt_AfterEncrypt_ReturnsOriginalPlaintext()
    {
        // Arrange
        var encryption = new AesGcmEncryption();
        string key = encryption.GenerateKey();
        string plaintext = "Hello SecureChat";
        // Act
        var encrypted = await encryption.EncryptAsync(plaintext, key);
        string decrypted = await encryption.DecryptAsync(
            encrypted.ciphertext,
            key,
            encrypted.iv,
            encrypted.tag
        );
        // Assert
        Assert.NotEqual(plaintext, encrypted.ciphertext);
        Assert.Equal(plaintext, decrypted);
    }
}