using CommunityToolkit.Mvvm.ComponentModel;

namespace SecureChat.AvaloniaClient.ViewModels;


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
    
    
    public void UpdateFromEncryptedMessage(string plaintext, string encrypted, string? iv, string? hmac)
    {
        PlaintextMessage = plaintext;
        EncryptedMessage = encrypted.Length > 100 ? encrypted[..100] + "..." : encrypted;
        Iv = iv ?? "N/A";
        Hmac = hmac?.Length > 32 ? hmac[..32] + "..." : hmac ?? "N/A";
    }
    
        public void UpdateOnConnected()
    {
        Algorithm = "AES-256-GCM + HMAC-SHA256";
        KeyExchangeInfo = "ECDH P-256 (Established)";
    }
    
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
