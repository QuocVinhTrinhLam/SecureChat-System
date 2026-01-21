using System.Security.Cryptography;
using SecureChat.Core.Security.Implementations;
using Xunit;

namespace SecureChat.Tests.Security
{
    /// <summary>
    /// Negative tests for AES-GCM encryption/decryption
    /// These tests ensure tampering or misuse is correctly detected
    /// </summary>
    public class AesGcmEncryptionNegativeTests
    {
        [Fact]
        public async Task Decrypt_WithWrongKey_ThrowsCryptographicException()
        {
            // Arrange
            var encryption = new AesGcmEncryption();
            string correctKey = encryption.GenerateKey();
            string wrongKey = encryption.GenerateKey(); // khác key
            string plaintext = "Hello SecureChat";
            var encrypted = await encryption.EncryptAsync(plaintext, correctKey);
            // Act and Assert
            await Assert.ThrowsAsync<CryptographicException>(async () =>
            {
                await encryption.DecryptAsync(
                    encrypted.ciphertext,
                    wrongKey,
                    encrypted.iv,
                    encrypted.tag
                );
            });
        }
        [Fact]
        public async Task Decrypt_WithTamperedCiphertext_ThrowsCryptographicException()
        {
            // Arrange
            var encryption = new AesGcmEncryption();
            string key = encryption.GenerateKey();
            string plaintext = "Hello SecureChat";
            var encrypted = await encryption.EncryptAsync(plaintext, key);
            // Giả mạo ciphertext
            byte[] tamperedCiphertext = encrypted.ciphertext.ToCharArray()
                .Select(c => (byte)(c ^ 0xFF))
                .ToArray();
            // Act and Assert
            await Assert.ThrowsAsync<CryptographicException>(async () =>
            {
                await encryption.DecryptAsync(
                    System.Text.Encoding.Unicode.GetString(tamperedCiphertext),
                    key,
                    encrypted.iv,
                    encrypted.tag
                );
            });
        }
        [Fact]
        public async Task Decrypt_WithTamperedAuthTag_ThrowsCryptographicException()
        {
            // Arrange
            var encryption = new AesGcmEncryption();

            string key = encryption.GenerateKey();
            string plaintext = "Hello SecureChat";
            var encrypted = await encryption.EncryptAsync(plaintext, key);
            // Giả mạo authentication tag
            byte[] tamperedTag = encrypted.tag.ToCharArray()
                .Select(c => (byte)(c ^ 0xAA))
                .ToArray();
            // Act and Assert
            await Assert.ThrowsAsync<CryptographicException>(async () =>
            {
                await encryption.DecryptAsync(
                    encrypted.ciphertext,
                    key,
                    encrypted.iv,
                    System.Text.Encoding.Unicode.GetString(tamperedTag)
                );
            });
        }
        [Fact]
        public async Task Decrypt_WithInvalidIv_ThrowsCryptographicException()
        {
            // Arrange
            var encryption = new AesGcmEncryption();
            string key = encryption.GenerateKey();
            string plaintext = "Hello SecureChat";
            var encrypted = await encryption.EncryptAsync(plaintext, key);
            // IV không hợp lệ
            string invalidIv = "invalid_iv";
            // Act and Assert
            await Assert.ThrowsAsync<CryptographicException>(async () =>
            {
                await encryption.DecryptAsync(
                    encrypted.ciphertext,
                    key,
                    invalidIv,
                    encrypted.tag
                );
            });
        }
    }
}
