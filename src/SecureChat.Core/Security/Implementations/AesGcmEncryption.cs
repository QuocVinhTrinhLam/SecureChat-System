using System.Security.Cryptography;
using System.Text;
using SecureChat.Core.Security.Interfaces;

namespace SecureChat.Core.Security.Implementations
{
    /// <summary>
    /// Provides AES-256-GCM authenticated encryption implementation.
    /// </summary>
    public sealed class AesGcmEncryption : ISymmetricEncryption
    {
        private const int KeySize = 32;   // 256-bit
        private const int NonceSize = 12; // 96-bit
        private const int TagSize = 16;   // 128-bit
        /// <summary>
        /// Gets the symmetric key size in bits.
        /// </summary>
        public int KeySizeBits => 256;
        /// <summary>
        /// Gets the algorithm identifier used in message metadata.
        /// </summary>
        public string AlgorithmIdentifier => "AES-256-GCM";
        /// <summary>
        /// Generates a cryptographically secure random 256-bit AES key.
        /// </summary>
        /// <returns>Base64-encoded AES key.</returns>
        public string GenerateKey()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeySize));
        }
        /// <summary>
        /// Encrypts plaintext using AES-256-GCM.
        /// </summary>
        /// <param name="plaintext">Plaintext string to encrypt.</param>
        /// <param name="key">Base64-encoded 256-bit encryption key.</param>
        /// <returns>
        /// Tuple containing:
        /// - ciphertext: Base64-encoded encrypted data
        /// - iv: Base64-encoded nonce
        /// - tag: Base64-encoded authentication tag
        /// </returns>
        public async Task<(string ciphertext, string iv, string tag)>
            EncryptAsync(string plaintext, string key)
        {
            byte[] keyBytes = Convert.FromBase64String(key);
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] tag = new byte[TagSize];
            using var aes = new AesGcm(keyBytes, TagSize);
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
            return (
                Convert.ToBase64String(ciphertext),
                Convert.ToBase64String(nonce),
                Convert.ToBase64String(tag)
            );
        }
        /// <summary>
        /// Decrypts AES-256-GCM encrypted data.
        /// </summary>
        /// <param name="ciphertext">Base64-encoded ciphertext.</param>
        /// <param name="key">Base64-encoded 256-bit encryption key.</param>
        /// <param name="iv">Base64-encoded nonce.</param>
        /// <param name="tag">Base64-encoded authentication tag.</param>
        /// <returns>Decrypted plaintext string.</returns>
        /// <exception cref="CryptographicException">
        /// Thrown if authentication fails, ciphertext is tampered,
        /// or input data is invalid.
        /// </exception>
        public async Task<string> DecryptAsync(
            string ciphertext,
            string key,
            string iv,
            string tag)
        {
            try
            {
                byte[] keyBytes = Convert.FromBase64String(key);
                byte[] nonce = Convert.FromBase64String(iv);
                byte[] cipherBytes = Convert.FromBase64String(ciphertext);
                byte[] tagBytes = Convert.FromBase64String(tag);
                byte[] plaintext = new byte[cipherBytes.Length];
                using var aes = new AesGcm(keyBytes, TagSize);
                aes.Decrypt(nonce, cipherBytes, tagBytes, plaintext);
                return Encoding.UTF8.GetString(plaintext);
            }
            catch (Exception ex) when (
                ex is FormatException ||
                ex is CryptographicException ||
                ex is AuthenticationTagMismatchException)
            {
                // Normalize all failures to CryptographicException
                throw new CryptographicException(
                    "AES-256-GCM decryption failed.", ex);
            }
        }
    }
}
