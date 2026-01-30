using System.Text.Json.Serialization;

namespace SecureChat.Core.Models;

public sealed class FileMetadata
{
    [JsonPropertyName("fileId")]
    public string FileId { get; set; } = Guid.NewGuid().ToString();
    
    [JsonPropertyName("fileName")]
    public string FileName { get; set; } = string.Empty;
    
    [JsonPropertyName("fileSize")]
    public long FileSize { get; set; }
    
    [JsonPropertyName("totalChunks")]
    public int TotalChunks { get; set; }
    
    [JsonPropertyName("fileHash")]
    public string FileHash { get; set; } = string.Empty;
    
    [JsonPropertyName("contentType")]
    public string ContentType { get; set; } = "application/octet-stream";
}

public sealed class FileChunkData
{
    [JsonPropertyName("fileId")]
    public string FileId { get; set; } = string.Empty;
    
    [JsonPropertyName("chunkIndex")]
    public int ChunkIndex { get; set; }
    
    [JsonPropertyName("data")]
    public string Data { get; set; } = string.Empty;
    
    [JsonPropertyName("totalChunks")]
    public int TotalChunks { get; set; }
}
