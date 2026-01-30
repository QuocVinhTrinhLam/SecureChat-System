using System.Security.Cryptography;
using System.Text;

namespace SecureChat.Core.Security.Implementations;

public static class HkdfKeyDerivation
{
    private const int KeyLength = 32;

    private const string ProtocolVersion = "SecureChat-v1";

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
