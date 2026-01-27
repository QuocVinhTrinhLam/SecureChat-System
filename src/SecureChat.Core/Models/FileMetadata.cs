using System.Text.Json.Serialization;

namespace SecureChat.Core.Models;

/// <summary>
/// Chứa metadata của file được truyền qua hệ thống chat
/// Được gửi trước khi bắt đầu transfer để người nhận chuẩn bị
/// </summary>
public sealed class FileMetadata
{
    /// <summary>
    /// ID duy nhất của file transfer session
    /// Dùng để liên kết các chunks với file gốc
    /// </summary>
    [JsonPropertyName("fileId")]
    public string FileId { get; set; } = Guid.NewGuid().ToString();
    
    /// <summary>
    /// Tên file gốc (bao gồm extension)
    /// Bảo mật: Cần sanitize khi save để tránh path traversal
    /// </summary>
    [JsonPropertyName("fileName")]
    public string FileName { get; set; } = string.Empty;
    
    /// <summary>
    /// Kích thước file tính bằng bytes
    /// </summary>
    [JsonPropertyName("fileSize")]
    public long FileSize { get; set; }
    
    /// <summary>
    /// Tổng số chunks sẽ được gửi
    /// ChunkSize mặc định 64KB (65536 bytes)
    /// </summary>
    [JsonPropertyName("totalChunks")]
    public int TotalChunks { get; set; }
    
    /// <summary>
    /// SHA-256 hash của file gốc (Base64)
    /// Dùng để verify integrity sau khi nhận đủ chunks
    /// </summary>
    [JsonPropertyName("fileHash")]
    public string FileHash { get; set; } = string.Empty;
    
    /// <summary>
    /// MIME type của file (ví dụ: "application/pdf", "image/png")
    /// </summary>
    [JsonPropertyName("contentType")]
    public string ContentType { get; set; } = "application/octet-stream";
}

/// <summary>
/// Chứa dữ liệu của một chunk file
/// Mỗi chunk được mã hóa riêng với IV độc lập
/// </summary>
public sealed class FileChunkData
{
    /// <summary>
    /// ID của file transfer session (liên kết với FileMetadata)
    /// </summary>
    [JsonPropertyName("fileId")]
    public string FileId { get; set; } = string.Empty;
    
    /// <summary>
    /// Index của chunk (0-based)
    /// </summary>
    [JsonPropertyName("chunkIndex")]
    public int ChunkIndex { get; set; }
    
    /// <summary>
    /// Dữ liệu chunk đã mã hóa (Base64)
    /// </summary>
    [JsonPropertyName("data")]
    public string Data { get; set; } = string.Empty;
    
    /// <summary>
    /// Tổng số chunks (để hiển thị progress)
    /// </summary>
    [JsonPropertyName("totalChunks")]
    public int TotalChunks { get; set; }
}
