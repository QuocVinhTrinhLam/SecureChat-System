using System.Security.Cryptography;
using System.Text;

namespace SecureChat.Core.Security.Implementations;

/// <summary>
/// Tiện ích HKDF (HMAC-based Key Derivation Function) để tính session keys
/// 
/// Thiết kế bảo mật:
/// - Tính các khóa riêng biệt cho encryption và MAC từ một shared secret
/// - Sử dụng SHA-256 làm hàm hash cơ sở
/// - Tham số "info" theo ngữ cảnh đảm bảo phân tách khóa
/// - Tuân theo RFC 5869 cho implementation HKDF
/// 
/// Cách sử dụng:
/// 1. Lấy shared secret từ trao đổi khóa ECDH
/// 2. Gọi DeriveSessionKeys() để lấy encryption và MAC keys
/// 3. Sử dụng encryption key cho AES-256-GCM
/// 4. Sử dụng MAC key cho HMAC bổ sung nếu cần
/// </summary>
public static class HkdfKeyDerivation
{
    /// <summary>
    /// Độ dài khóa được tính theo bytes - 256 bits
    /// </summary>
    private const int KeyLength = 32;

    /// <summary>
    /// Định danh phiên bản giao thức cho ngữ cảnh tính khóa
    /// </summary>
    private const string ProtocolVersion = "SecureChat-v1";

    /// <summary>
    /// Tính encryption và MAC keys từ shared secret
    /// </summary>
    /// <param name="sharedSecret">Shared secret được mã hóa Base64 từ ECDH.</param>
    /// <param name="salt">Salt tùy chọn. Sử dụng zeros nếu null.</param>
    /// <returns>Tuple của (encryptionKey, macKey) dạng chuỗi Base64.</returns>
    /// <remarks>
    /// Bảo mật: Shared secret cần đến từ trao đổi khóa an toàn (ECDH)
    /// Sử dụng các tham số "info" khác nhau đảm bảo các khóa được tính
    /// độc lập về mặt mật mã mặc dù chúng đến từ cùng shared secret.
    /// </remarks>
    public static (string encryptionKey, string macKey) DeriveSessionKeys(
        string sharedSecret, byte[]? salt = null)
    {
        ArgumentNullException.ThrowIfNull(sharedSecret);

        var sharedSecretBytes = Convert.FromBase64String(sharedSecret);
        
        // Sử dụng 32 zero bytes làm salt mặc định nếu không cung cấp
        salt ??= new byte[32];

        // Tính encryption key với ngữ cảnh dành riêng cho encryption
        var encKey = HKDF.DeriveKey(
            hashAlgorithmName: HashAlgorithmName.SHA256,
            ikm: sharedSecretBytes,
            outputLength: KeyLength,
            salt: salt,
            info: Encoding.Unicode.GetBytes($"{ProtocolVersion}-encryption-key"));

        // Tính MAC key với ngữ cảnh dành riêng cho MAC
        var macKey = HKDF.DeriveKey(
            hashAlgorithmName: HashAlgorithmName.SHA256,
            ikm: sharedSecretBytes,
            outputLength: KeyLength,
            salt: salt,
            info: Encoding.Unicode.GetBytes($"{ProtocolVersion}-mac-key"));

        // Xóa shared secret khỏi bộ nhớ
        CryptographicOperations.ZeroMemory(sharedSecretBytes);

        return (
            encryptionKey: Convert.ToBase64String(encKey),
            macKey: Convert.ToBase64String(macKey)
        );
    }

    /// <summary>
    /// Tính một khóa đơn cho mục đích cụ thể.
    /// </summary>
    /// <param name="sharedSecret">Shared secret được mã hóa Base64 từ ECDH.</param>
    /// <param name="purpose">Định danh mục đích của khóa.</param>
    /// <param name="salt">Salt tùy chọn. Sử dụng zeros nếu null.</param>
    /// <returns>Khóa được tính dạng Base64.</returns>
    public static string DeriveKey(string sharedSecret, string purpose, byte[]? salt = null)
    {
        ArgumentNullException.ThrowIfNull(sharedSecret);
        ArgumentNullException.ThrowIfNull(purpose);

        var sharedSecretBytes = Convert.FromBase64String(sharedSecret);
        salt ??= new byte[32];

        var derivedKey = HKDF.DeriveKey(
            hashAlgorithmName: HashAlgorithmName.SHA256,
            ikm: sharedSecretBytes,
            outputLength: KeyLength,
            salt: salt,
            info: Encoding.Unicode.GetBytes($"{ProtocolVersion}-{purpose}"));

        // Xóa shared secret khỏi bộ nhớ
        CryptographicOperations.ZeroMemory(sharedSecretBytes);

        return Convert.ToBase64String(derivedKey);
    }

    /// <summary>
    /// Tính session keys với session ID duy nhất được tích hợp vào salt
    /// Điều này cung cấp phân tách domain bổ sung giữa các phiên
    /// </summary>
    /// <param name="sharedSecret">Shared secret được mã hóa Base64 từ ECDH.</param>
    /// <param name="sessionId">Định danh phiên duy nhất.</param>
    /// <returns>Tuple của (encryptionKey, macKey) dạng chuỗi Base64.</returns>
    public static (string encryptionKey, string macKey) DeriveSessionKeysWithId(
        string sharedSecret, string sessionId)
    {
        ArgumentNullException.ThrowIfNull(sharedSecret);
        ArgumentNullException.ThrowIfNull(sessionId);

        // Sử dụng session ID như một phần của salt để phân tách domain
        var sessionIdBytes = Encoding.Unicode.GetBytes(sessionId);
        var salt = new byte[32];
        
        // Copy session ID bytes vào salt
        var copyLength = Math.Min(sessionIdBytes.Length, salt.Length);
        Array.Copy(sessionIdBytes, salt, copyLength);

        return DeriveSessionKeys(sharedSecret, salt);
    }
}
