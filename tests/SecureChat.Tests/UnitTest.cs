using SecureChat.Core.Security.Implementations;
using Xunit;

namespace SecureChat.Tests.Security
{
    public class AesGcmEncryptionTests
    {
        [Fact]
        public async Task EncryptAndDecrypt_ReturnsOriginalPlaintext()
        {
            // Arrange
            var encryption = new AesGcmEncryption();
            string key = encryption.GenerateKey();
            string plaintext = "Hello SecureChat";
            // Act
            var result = await encryption.EncryptAsync(plaintext, key);
            string decrypted = await encryption.DecryptAsync(
                result.ciphertext,
                key,
                result.iv,
                result.tag
            );
            // Assert
            Assert.Equal(plaintext, decrypted);
        }
    }
}
