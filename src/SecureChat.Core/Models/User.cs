namespace SecureChat.Core.Models;

public sealed class User
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    
    public string Username { get; set; } = string.Empty;
    
    public string? PublicKey { get; set; }
    
    public DateTime ConnectedAt { get; set; } = DateTime.UtcNow;
    
    public bool IsKeyExchangeComplete { get; set; } = false;
    
    public static User Create(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            throw new ArgumentException("Username không được để trống", nameof(username));
        }
        
        // Bảo mật: Xác thực username cơ bản
        // Trong môi trường production, thêm xác thực đầy đủ hơn
        const int MaxUsernameLength = 32;
        if (username.Length > MaxUsernameLength)
        {
            throw new ArgumentException($"Username không được vượt quá {MaxUsernameLength} ký tự", nameof(username));
        }
        
        return new User
        {
            Username = username.Trim()
        };
    }
}
