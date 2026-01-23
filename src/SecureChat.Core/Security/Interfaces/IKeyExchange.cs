namespace SecureChat.Core.Security.Interfaces;
/// <summary>
/// Định nghĩa contract trao đổi khóa để thiết lập phiên bảo mật
/// </summary>
public interface IKeyExchange
{
    /// <summary>
    /// Định danh thuật toán trao đổi khóa
    /// </summary>
    string AlgorithmIdentifier { get; }
    /// <summary>
    /// Tạo cặp khóa public/private
    /// </summary>
    Task GenerateKeyPairAsync();
    /// <summary>
    /// Lấy public key để gửi cho peer
    /// </summary>
    string GetPublicKey();
    /// <summary>
    /// Tính shared secret từ public key của peer
    /// </summary>
    Task<string> DeriveSharedSecretAsync(string peerPublicKey);
    /// <summary>
    /// Xác thực public key nhận được
    /// </summary>
    bool ValidatePublicKey(string publicKey);
}
