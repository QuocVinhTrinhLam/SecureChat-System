using System.Security.Cryptography;
using SecureChat.Core.Models;

namespace SecureChat.Core.Services;

public class FileTransferService
{
    public const int ChunkSize = 65536;
    
    public event EventHandler<FileTransferProgressEventArgs>? ProgressChanged;
    
    public event EventHandler<FileTransferCompleteEventArgs>? TransferCompleted;
    
    public event EventHandler<FileTransferErrorEventArgs>? TransferFailed;
    
    // Lưu trữ các file đang nhận (chờ ghép chunks)
    private readonly Dictionary<string, IncomingFileTransfer> _incomingTransfers = new();
    
    public async Task<FileMetadata> PrepareFileForSendingAsync(string filePath)
    {
        var fileInfo = new FileInfo(filePath);
        if (!fileInfo.Exists)
            throw new FileNotFoundException("File không tồn tại", filePath);
        
        var totalChunks = (int)Math.Ceiling((double)fileInfo.Length / ChunkSize);
        var fileHash = await ComputeFileHashAsync(filePath);
        var contentType = GetContentType(filePath);
        
        return new FileMetadata
        {
            FileId = Guid.NewGuid().ToString(),
            FileName = fileInfo.Name,
            FileSize = fileInfo.Length,
            TotalChunks = totalChunks,
            FileHash = fileHash,
            ContentType = contentType
        };
    }
    
    public async IAsyncEnumerable<FileChunkData> ReadFileChunksAsync(string filePath, string fileId)
    {
        var fileInfo = new FileInfo(filePath);
        var totalChunks = (int)Math.Ceiling((double)fileInfo.Length / ChunkSize);
        
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkSize, true);
        var buffer = new byte[ChunkSize];
        var chunkIndex = 0;
        
        int bytesRead;
        while ((bytesRead = await stream.ReadAsync(buffer, 0, ChunkSize)) > 0)
        {
            var chunkData = new byte[bytesRead];
            Array.Copy(buffer, chunkData, bytesRead);
            
            yield return new FileChunkData
            {
                FileId = fileId,
                ChunkIndex = chunkIndex,
                Data = Convert.ToBase64String(chunkData),
                TotalChunks = totalChunks
            };
            
            ProgressChanged?.Invoke(this, new FileTransferProgressEventArgs
            {
                FileId = fileId,
                CurrentChunk = chunkIndex + 1,
                TotalChunks = totalChunks,
                BytesTransferred = stream.Position,
                TotalBytes = fileInfo.Length,
                IsUpload = true
            });
            
            chunkIndex++;
        }
    }
    
    public void StartReceiving(FileMetadata metadata, string senderName)
    {
        var transfer = new IncomingFileTransfer
        {
            Metadata = metadata,
            SenderName = senderName,
            Chunks = new byte[metadata.TotalChunks][],
            ReceivedChunks = 0,
            StartTime = DateTime.UtcNow
        };
        
        _incomingTransfers[metadata.FileId] = transfer;
    }
    
    public bool ReceiveChunk(FileChunkData chunkData)
    {
        if (!_incomingTransfers.TryGetValue(chunkData.FileId, out var transfer))
        {
            TransferFailed?.Invoke(this, new FileTransferErrorEventArgs
            {
                FileId = chunkData.FileId,
                Error = "Không tìm thấy file transfer session"
            });
            return false;
        }
        
        // Decode và lưu chunk
        var data = Convert.FromBase64String(chunkData.Data);
        transfer.Chunks[chunkData.ChunkIndex] = data;
        transfer.ReceivedChunks++;
        
        ProgressChanged?.Invoke(this, new FileTransferProgressEventArgs
        {
            FileId = chunkData.FileId,
            FileName = transfer.Metadata.FileName,
            CurrentChunk = transfer.ReceivedChunks,
            TotalChunks = transfer.Metadata.TotalChunks,
            BytesTransferred = transfer.ReceivedChunks * ChunkSize,
            TotalBytes = transfer.Metadata.FileSize,
            IsUpload = false
        });
        
        // Kiểm tra đã nhận đủ chưa
        return transfer.ReceivedChunks >= transfer.Metadata.TotalChunks;
    }
    
    public async Task<string> SaveReceivedFileAsync(string fileId, string saveDirectory)
    {
        if (!_incomingTransfers.TryGetValue(fileId, out var transfer))
            throw new InvalidOperationException("Không tìm thấy file transfer session");
        
        // Đảm bảo thư mục tồn tại
        Directory.CreateDirectory(saveDirectory);
        
        // Sanitize filename để tránh path traversal
        var safeFileName = SanitizeFileName(transfer.Metadata.FileName);
        var savePath = Path.Combine(saveDirectory, safeFileName);
        
        // Nếu file đã tồn tại, thêm suffix
        savePath = GetUniqueFilePath(savePath);
        
        // Ghép tất cả chunks và ghi ra file
        // Sử dụng block riêng để đảm bảo stream được đóng trước khi verify hash
        {
            await using var stream = new FileStream(savePath, FileMode.Create, FileAccess.Write, FileShare.None, ChunkSize, true);
            foreach (var chunk in transfer.Chunks)
            {
                if (chunk != null)
                    await stream.WriteAsync(chunk, 0, chunk.Length);
            }
            // Stream được đóng tự động khi ra khỏi block
        }
        
        // Verify hash (sau khi stream đã được đóng)
        var savedHash = await ComputeFileHashAsync(savePath);
        if (savedHash != transfer.Metadata.FileHash)
        {
            File.Delete(savePath);
            TransferFailed?.Invoke(this, new FileTransferErrorEventArgs
            {
                FileId = fileId,
                FileName = transfer.Metadata.FileName,
                Error = "File bị hỏng - hash không khớp"
            });
            throw new InvalidDataException("File hash không khớp sau khi nhận");
        }
        
        // Cleanup
        _incomingTransfers.Remove(fileId);
        
        TransferCompleted?.Invoke(this, new FileTransferCompleteEventArgs
        {
            FileId = fileId,
            FileName = transfer.Metadata.FileName,
            SavePath = savePath,
            FileSize = transfer.Metadata.FileSize
        });
        
        return savePath;
    }
    
    private static async Task<string> ComputeFileHashAsync(string filePath)
    {
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkSize, true);
        var hash = await SHA256.HashDataAsync(stream);
        return Convert.ToBase64String(hash);
    }
    
    private static string SanitizeFileName(string fileName)
    {
        var invalidChars = Path.GetInvalidFileNameChars();
        var sanitized = new string(fileName.Where(c => !invalidChars.Contains(c)).ToArray());
        
        // Loại bỏ các pattern nguy hiểm
        sanitized = sanitized.Replace("..", "");
        
        return string.IsNullOrWhiteSpace(sanitized) ? "unnamed_file" : sanitized;
    }
    
    private static string GetUniqueFilePath(string filePath)
    {
        if (!File.Exists(filePath))
            return filePath;
        
        var directory = Path.GetDirectoryName(filePath) ?? ".";
        var fileName = Path.GetFileNameWithoutExtension(filePath);
        var extension = Path.GetExtension(filePath);
        var counter = 1;
        
        string newPath;
        do
        {
            newPath = Path.Combine(directory, $"{fileName}_{counter}{extension}");
            counter++;
        } while (File.Exists(newPath));
        
        return newPath;
    }
    
    private static string GetContentType(string filePath)
    {
        var extension = Path.GetExtension(filePath).ToLowerInvariant();
        return extension switch
        {
            ".pdf" => "application/pdf",
            ".doc" or ".docx" => "application/msword",
            ".xls" or ".xlsx" => "application/vnd.ms-excel",
            ".ppt" or ".pptx" => "application/vnd.ms-powerpoint",
            ".txt" => "text/plain",
            ".html" or ".htm" => "text/html",
            ".css" => "text/css",
            ".js" => "application/javascript",
            ".json" => "application/json",
            ".xml" => "application/xml",
            ".zip" => "application/zip",
            ".rar" => "application/x-rar-compressed",
            ".7z" => "application/x-7z-compressed",
            ".tar" or ".gz" => "application/x-tar",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".png" => "image/png",
            ".gif" => "image/gif",
            ".bmp" => "image/bmp",
            ".svg" => "image/svg+xml",
            ".mp3" => "audio/mpeg",
            ".wav" => "audio/wav",
            ".mp4" => "video/mp4",
            ".avi" => "video/x-msvideo",
            ".mov" => "video/quicktime",
            _ => "application/octet-stream"
        };
    }
    
    private class IncomingFileTransfer
    {
        public required FileMetadata Metadata { get; init; }
        public required string SenderName { get; init; }
        public required byte[][] Chunks { get; init; }
        public int ReceivedChunks { get; set; }
        public DateTime StartTime { get; init; }
    }
}

public class FileTransferProgressEventArgs : EventArgs
{
    public string FileId { get; init; } = string.Empty;
    public string FileName { get; init; } = string.Empty;
    public int CurrentChunk { get; init; }
    public int TotalChunks { get; init; }
    public long BytesTransferred { get; init; }
    public long TotalBytes { get; init; }
    public bool IsUpload { get; init; }
    
    public double ProgressPercent => TotalBytes > 0 ? (double)BytesTransferred / TotalBytes * 100 : 0;
}

public class FileTransferCompleteEventArgs : EventArgs
{
    public string FileId { get; init; } = string.Empty;
    public string FileName { get; init; } = string.Empty;
    public string SavePath { get; init; } = string.Empty;
    public long FileSize { get; init; }
}

public class FileTransferErrorEventArgs : EventArgs
{
    public string FileId { get; init; } = string.Empty;
    public string FileName { get; init; } = string.Empty;
    public string Error { get; init; } = string.Empty;
}

