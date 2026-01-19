using SecureChat.Core.Security.Implementations;
using Xunit;

namespace SecureChat.Tests;
    public class AesGcmEncryptionTests
    {
        [Fact]
        public async Task EncryptAndDecrypt_ShouldReturnOriginalPlaintext()
        {
            // Arrange
            var encryption = new AesGcmEncryption();
            string key = encryption.GenerateKey();
            string plaintext = "Hello Secure Chat!";
            // Act
            var (ciphertext, iv, tag) =
                await encryption.EncryptAsync(plaintext, key);

            string decrypted =
                await encryption.DecryptAsync(ciphertext, key, iv, tag);
            // Assert
            Assert.Equal(plaintext, decrypted);
        }
    }
