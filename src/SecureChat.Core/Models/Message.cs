using System.Text.Json.Serialization;

namespace SecureChat.Core.Models;

public sealed class SecurityMetadata
{
    [JsonPropertyName("algorithm")]
    public string? Algorithm { get; set; }
    
    [JsonPropertyName("iv")]
    public string? InitializationVector { get; set; }
    
    [JsonPropertyName("signature")]
    public string? Signature { get; set; }
    
    [JsonPropertyName("hmac")]
    public string? Hmac { get; set; }
    
    [JsonPropertyName("keyId")]
    public string? KeyId { get; set; }
}

public sealed class Message
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = Guid.NewGuid().ToString();
    
    [JsonPropertyName("type")]
    public MessageType Type { get; set; } = MessageType.Text;
    
    [JsonPropertyName("senderId")]
    public string SenderId { get; set; } = string.Empty;
    
    [JsonPropertyName("senderName")]
    public string SenderName { get; set; } = string.Empty;
    
    [JsonPropertyName("content")]
    public string Content { get; set; } = string.Empty;
    
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    
    [JsonPropertyName("securityMetadata")]
    public SecurityMetadata? SecurityMetadata { get; set; }
    
    [JsonPropertyName("recipientId")]
    public string? RecipientId { get; set; }
    
    [JsonPropertyName("recipientName")]
    public string? RecipientName { get; set; }
    
    [JsonPropertyName("fileMetadata")]
    public FileMetadata? FileMetadata { get; set; }
    
    [JsonPropertyName("fileChunkData")]
    public FileChunkData? FileChunkData { get; set; }
    
    public static Message CreateTextMessage(string senderId, string senderName, string content)
    {
        return new Message
        {
            Type = MessageType.Text,
            SenderId = senderId,
            SenderName = senderName,
            Content = content
        };
    }
    
    public static Message CreateDirectMessage(
        string senderId, string senderName,
        string recipientId, string recipientName,
        string content)
    {
        return new Message
        {
            Type = MessageType.Text,
            SenderId = senderId,
            SenderName = senderName,
            RecipientId = recipientId,
            RecipientName = recipientName,
            Content = content
        };
    }
    
    public static Message CreateSystemMessage(string content)
    {
        return new Message
        {
            Type = MessageType.System,
            SenderId = "SYSTEM",
            SenderName = "Hệ thống",
            Content = content
        };
    }
    
    public static Message CreateJoinMessage(string userId, string userName)
    {
        return new Message
        {
            Type = MessageType.Join,
            SenderId = userId,
            SenderName = userName,
            Content = $"{userName} đã tham gia chat"
        };
    }
    
    public static Message CreateLeaveMessage(string userId, string userName)
    {
        return new Message
        {
            Type = MessageType.Leave,
            SenderId = userId,
            SenderName = userName,
            Content = $"{userName} đã rời khỏi chat"
        };
    }
    
    public static Message CreateUserListMessage(IEnumerable<string> usernames)
    {
        return new Message
        {
            Type = MessageType.UserList,
            SenderId = "SYSTEM",
            SenderName = "Hệ thống",
            Content = string.Join(",", usernames)
        };
    }
    
    public static Message CreateFileMessage(
        string senderId, string senderName,
        string recipientId, string recipientName,
        FileMetadata fileMetadata)
    {
        return new Message
        {
            Type = MessageType.File,
            SenderId = senderId,
            SenderName = senderName,
            RecipientId = recipientId,
            RecipientName = recipientName,
            FileMetadata = fileMetadata,
            Content = $"[FILE] {fileMetadata.FileName} ({FormatFileSize(fileMetadata.FileSize)})"
        };
    }
    
    public static Message CreateFileChunkMessage(
        string senderId, string senderName,
        string recipientId, string recipientName,
        FileChunkData chunkData)
    {
        return new Message
        {
            Type = MessageType.FileChunk,
            SenderId = senderId,
            SenderName = senderName,
            RecipientId = recipientId,
            RecipientName = recipientName,
            FileChunkData = chunkData,
            Content = $"Chunk {chunkData.ChunkIndex + 1}/{chunkData.TotalChunks}"
        };
    }
    
    public static Message CreateFileCompleteMessage(
        string senderId, string senderName,
        string recipientId, string recipientName,
        string fileId, string fileName)
    {
        return new Message
        {
            Type = MessageType.FileComplete,
            SenderId = senderId,
            SenderName = senderName,
            RecipientId = recipientId,
            RecipientName = recipientName,
            Content = $"File {fileName} đã được nhận hoàn tất",
            FileMetadata = new FileMetadata { FileId = fileId, FileName = fileName }
        };
    }
    
    private static string FormatFileSize(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB" };
        int order = 0;
        double size = bytes;
        while (size >= 1024 && order < sizes.Length - 1)
        {
            order++;
            size /= 1024;
        }
        return $"{size:0.##} {sizes[order]}";
    }
}
