namespace SecureChat.Core.Security.Interfaces;

/// <summary>
/// Abstraction cho các thao tác mã hóa đối xứng
/// 
/// Thiết kế bảo mật:
/// - Sử dụng để mã hóa nội dung tin nhắn sau trao đổi khóa
/// - Phải sử dụng authenticated encryption để ngăn chặn giả mạo
/// - Quản lý IV/nonce là quan trọng - KHÔNG BAO GIỜ tái sử dụng
/// 
/// Implementation khuyến nghị:
/// - AES-256-GCM
/// - ChaCha20-Poly1305
/// 
/// Yêu cầu bảo mật cho implementations:
/// - Sử dụng khóa tối thiểu 256-bit
/// - Tạo IV ngẫu nhiên an toàn về mặt mật mã cho mỗi tin nhắn
/// - Xác minh authentication tag trước khi trả về plaintext
/// - Xóa key material nhạy cảm sau khi sử dụng
/// </summary>
public interface ISymmetricEncryption
{
    /// <summary>
    /// Mã hóa plaintext sử dụng khóa được cung cấp
    /// </summary>
    /// <param name="plaintext">Dữ liệu cần mã hóa.</param>
    /// <param name="key">Khóa mã hóa được mã hóa Base64.</param>
    /// <returns>
    /// Tuple chứa:
    /// - ciphertext: Dữ liệu đã mã hóa dạng Base64
    /// - iv: Vector khởi tạo dạng Base64
    /// - tag: Authentication tag dạng Base64
    /// </returns>
    /// <remarks>
    /// Bảo mật: IV được tạo nội bộ và phải ngẫu nhiên an toàn về mặt mật mã
    /// Không bao giờ chấp nhận IV từ input bên ngoài cho thao tác mã hóa
    /// </remarks>
    Task<(string ciphertext, string iv, string tag)> EncryptAsync(string plaintext, string key);
    
    /// <summary>
    /// Giải mã ciphertext sử dụng khóa được cung cấp
    /// </summary>
    /// <param name="ciphertext">Dữ liệu đã mã hóa dạng Base64.</param>
    /// <param name="key">Khóa mã hóa dạng Base64.</param>
    /// <param name="iv">Vector khởi tạo dạng Base64.</param>
    /// <param name="tag">Authentication tag dạng Base64.</param>
    /// <returns>Plaintext đã giải mã.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Thrown nếu giải mã thất bại hoặc authentication tag không hợp lệ
    /// Bảo mật: Không phân biệt giữa lỗi padding và lỗi xác thực
    /// </exception>
    Task<string> DecryptAsync(string ciphertext, string key, string iv, string tag);
    
    /// <summary>
    /// Tạo khóa ngẫu nhiên an toàn về mặt mật mã
    /// </summary>
    /// <returns>Khóa dạng Base64 với độ dài phù hợp cho thuật toán.</returns>
    string GenerateKey();
    
    /// <summary>
    /// Lấy kích thước khóa tính bằng bits cho thuật toán này
    /// </summary>
    int KeySizeBits { get; }
    
    /// <summary>
    /// Lấy định danh thuật toán cho message metadata
    /// </summary>
    string AlgorithmIdentifier { get; }
}
