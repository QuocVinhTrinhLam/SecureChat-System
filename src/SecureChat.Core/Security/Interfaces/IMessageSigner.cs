namespace SecureChat.Core.Security.Interfaces;

/// <summary>
/// Abstraction cho xác minh tính toàn vẹn và tính xác thực của tin nhắn
/// 
/// Mục đích bảo mật:
/// - Đảm bảo tin nhắn không bị giả mạo trong quá trình truyền
/// - Cung cấp tính xác thực của người gửi
/// - Ngăn chặn tấn công giả mạo tin nhắn
/// 
/// Tùy chọn implementation:
/// - HMAC-SHA256: Nhanh, đối xứng, yêu cầu shared key
/// - RSA-PSS: Bất đối xứng, cung cấp non-repudiation
/// - ECDSA: Bất đối xứng, chữ ký nhỏ hơn RSA
/// 
/// Lưu ý bảo mật:
/// - Sign-then-encrypt thường được ưa chuộng hơn encrypt-then-sign
/// - Bao gồm message ID và timestamp trong dữ liệu ký để ngăn chặn replay
/// - Sử dụng so sánh constant-time cho xác minh chữ ký
/// </summary>
public interface IMessageSigner
{
    /// <summary>
    /// Ký dữ liệu được cung cấp.
    /// </summary>
    /// <param name="data">Dữ liệu cần ký.</param>
    /// <param name="key">
    /// Với HMAC: Khóa bí mật shared dạng Base64
    /// Với bất đối xứng: Private key dạng Base64
    /// </param>
    /// <returns>Chữ ký dạng Base64.</returns>
    /// <remarks>
    /// Bảo mật: Tham số key phải được giữ bí mật
    /// Với ký bất đối xứng, đây nên là private key của người gửi
    /// </remarks>
    Task<string> SignAsync(string data, string key);
    
    /// <summary>
    /// Xác minh chữ ký với dữ liệu được cung cấp
    /// </summary>
    /// <param name="data">Dữ liệu gốc đã ký.</param>
    /// <param name="signature">Chữ ký dạng Base64 cần xác minh.</param>
    /// <param name="key">
    /// Với HMAC: Khóa bí mật shared dạng Base64
    /// Với bất đối xứng: Public key dạng Base64
    /// </param>
    /// <returns>True nếu chữ ký hợp lệ, false nếu không.</returns>
    /// <remarks>
    /// Bảo mật quan trọng: Phải sử dụng so sánh constant-time để ngăn chặn timing attacks
    /// Không bao giờ throw exception cho chữ ký không hợp lệ - trả về false thay vào đó
    /// </remarks>
    Task<bool> VerifyAsync(string data, string signature, string key);
    
    /// <summary>
    /// Tạo khóa phù hợp cho thuật toán ký này
    /// Với HMAC, tạo khóa ngẫu nhiên
    /// Với bất đối xứng, tạo cặp khóa
    /// </summary>
    /// <returns>Key material dạng Base64.</returns>
    string GenerateKey();
    
    /// <summary>
    /// Lấy định danh thuật toán cho message metadata
    /// </summary>
    string AlgorithmIdentifier { get; }
}
