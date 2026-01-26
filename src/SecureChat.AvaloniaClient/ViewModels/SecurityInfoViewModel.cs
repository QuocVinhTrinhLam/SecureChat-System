using CommunityToolkit.Mvvm.ComponentModel;

namespace SecureChat.AvaloniaClient.ViewModels;

/// <summary>
/// ViewModel hiển thị thông tin bảo mật/mã hóa
/// Phục vụ demo và thuyết trình
/// </summary>
public partial class SecurityInfoViewModel : ViewModelBase
{
    [ObservableProperty]
    private string _algorithm = "Chưa kết nối";
    
    [ObservableProperty]
    private string _plaintextMessage = "";
    
    [ObservableProperty]
    private string _encryptedMessage = "";
    
    [ObservableProperty]
    private string _iv = "";
    
    [ObservableProperty]
    private string _hmac = "";
    
    [ObservableProperty]
    private string _keyExchangeInfo = "ECDH P-256";
    
    /// <summary>
    /// Cập nhật thông tin từ tin nhắn đã mã hóa
    /// </summary>
    public void UpdateFromEncryptedMessage(string plaintext, string encrypted, string? iv, string? hmac)
    {
        PlaintextMessage = plaintext;
        EncryptedMessage = encrypted.Length > 100 ? encrypted[..100] + "..." : encrypted;
        Iv = iv ?? "N/A";
        Hmac = hmac?.Length > 32 ? hmac[..32] + "..." : hmac ?? "N/A";
    }
    
    /// <summary>
    /// Cập nhật khi kết nối thành công
    /// </summary>
    public void UpdateOnConnected()
    {
        Algorithm = "AES-256-GCM + HMAC-SHA256";
        KeyExchangeInfo = "ECDH P-256 (Established)";
    }
    
    /// <summary>
    /// Reset khi ngắt kết nối
    /// </summary>
    public void Reset()
    {
        Algorithm = "Chưa kết nối";
        PlaintextMessage = "";
        EncryptedMessage = "";
        Iv = "";
        Hmac = "";
        KeyExchangeInfo = "ECDH P-256";
    }
}
