using System.Security.Cryptography;
using System.Text;
using SecureChat.Core.Security.Interfaces;

namespace SecureChat.Core.Security.Implementations
{
    /// <summary>
    /// Triển khai mã hóa xác thực AES-256-GCM.
    /// </summary>
    public sealed class AesGcmEncryption : ISymmetricEncryption
    {
        private const int KeySize = 32;   // 256-bit
        private const int NonceSize = 12; // 96-bit
        private const int TagSize = 16;   // 128-bit
        /// <inheritdoc />
        public int KeySizeBits => 256;
        /// <inheritdoc />
        public string AlgorithmIdentifier => "AES-256-GCM";
        /// <summary>
        /// Tạo khóa AES 256-bit an toàn (Base64).
        /// </summary>
        public string GenerateKey()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeySize));
        }
        /// <summary>
        /// Mã hóa plaintext sử dụng AES-256-GCM.
        /// Trả về (ciphertext, iv, tag) dưới dạng chuỗi Base64.
        /// </summary>
        public Task<(string ciphertext, string iv, string tag)>
            EncryptAsync(string plaintext, string key)
        {
            byte[] keyBytes = Convert.FromBase64String(key);
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] tag = new byte[TagSize];
            using var aes = new AesGcm(keyBytes, TagSize);
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
            return Task.FromResult((
                Convert.ToBase64String(ciphertext),
                Convert.ToBase64String(nonce),
                Convert.ToBase64String(tag)
            ));
        }
        /// <summary>
        /// Giải mã ciphertext AES-256-GCM.
        /// Ném ngoại lệ CryptographicException nếu thất bại.
        /// </summary>
        public Task<string> DecryptAsync(
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
                return Task.FromResult(Encoding.UTF8.GetString(plaintext));
            }
            catch (Exception ex) when (
                ex is FormatException ||
                ex is CryptographicException ||
                ex is AuthenticationTagMismatchException)
            {
                // Normalize exceptions
                throw new CryptographicException(
                    "AES-256-GCM decryption failed.", ex);
            }
        }
    }
}
