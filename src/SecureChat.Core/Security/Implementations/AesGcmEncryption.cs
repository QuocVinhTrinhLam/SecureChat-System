using System.Security.Cryptography;
using System.Text;
using SecureChat.Core.Security.Interfaces;

namespace SecureChat.Core.Security.Implementations
{
    /// <summary>
    /// Cung cấp implementation mã hóa authenticated AES-256-GCM
    /// </summary>
    public sealed class AesGcmEncryption : ISymmetricEncryption
    {
        private const int KeySize = 32;   // 256-bit
        private const int NonceSize = 12; // 96-bit
        private const int TagSize = 16;   // 128-bit
        /// <summary>
        /// Lấy kích thước khóa đối xứng tính bằng bits.
        /// </summary>
        public int KeySizeBits => 256;
        /// <summary>
        /// Lấy định danh thuật toán sử dụng trong message metadata
        /// </summary>
        public string AlgorithmIdentifier => "AES-256-GCM";
        /// <summary>
        /// Tạo khóa AES 256-bit ngẫu nhiên an toàn về mặt mật mã
        /// </summary>
        /// <returns>Khóa AES được mã hóa Base64.</returns>
        public string GenerateKey()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeySize));
        }
        /// <summary>
        /// Mã hóa plaintext sử dụng AES-256-GCM
        /// </summary>
        /// <param name="plaintext">Chuỗi plaintext cần mã hóa.</param>
        /// <param name="key">Khóa mã hóa 256-bit được mã hóa Base64.</param>
        /// <returns>
        /// Tuple chứa:
        /// - ciphertext: Dữ liệu đã mã hóa ở Base64
        /// - iv: Nonce ở Base64
        /// - tag: Authentication tag ở Base64
        /// </returns>
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
        /// Giải mã dữ liệu đã mã hóa AES-256-GCM
        /// </summary>
        /// <param name="ciphertext">Ciphertext được mã hóa Base64.</param>
        /// <param name="key">Khóa mã hóa 256-bit được mã hóa Base64.</param>
        /// <param name="iv">Nonce được mã hóa Base64.</param>
        /// <param name="tag">Authentication tag được mã hóa Base64.</param>
        /// <returns>Chuỗi plaintext đã giải mã.</returns>
        /// <exception cref="CryptographicException">
        /// Thrown nếu xác thực thất bại, ciphertext bị giả mạo,
        /// hoặc dữ liệu đầu vào không hợp lệ
        /// </exception>
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
                // Chuẩn hóa tất cả lỗi thành CryptographicException
                throw new CryptographicException(
                    "Giải mã AES-256-GCM thất bại.", ex);
            }
        }
    }
}
