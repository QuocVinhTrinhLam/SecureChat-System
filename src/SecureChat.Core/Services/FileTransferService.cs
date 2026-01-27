using System.Security.Cryptography;
using SecureChat.Core.Models;

namespace SecureChat.Core.Services;

/// <summary>
/// Service xử lý gửi và nhận file qua hệ thống chat
/// File được chia thành chunks 64KB và mã hóa riêng từng chunk
/// </summary>
public class FileTransferService
{
    /// <summary>
    /// Kích thước mỗi chunk (64KB)
    /// </summary>
    public const int ChunkSize = 65536;
    
    /// <summary>
    /// Event khi có thay đổi tiến trình transfer
    /// </summary>
    public event EventHandler<FileTransferProgressEventArgs>? ProgressChanged;
    
    /// <summary>
    /// Event khi transfer hoàn tất
    /// </summary>
    public event EventHandler<FileTransferCompleteEventArgs>? TransferCompleted;
    
    /// <summary>
    /// Event khi có lỗi trong quá trình transfer
    /// </summary>
    public event EventHandler<FileTransferErrorEventArgs>? TransferFailed;
    
    // Lưu trữ các file đang nhận (chờ ghép chunks)
    private readonly Dictionary<string, IncomingFileTransfer> _incomingTransfers = new();
    
    /// <summary>
    /// Chuẩn bị file để gửi - tính toán metadata
    /// </summary>
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
    
    /// <summary>
    /// Đọc file và trả về các chunks dưới dạng IAsyncEnumerable
    /// </summary>
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
    
    /// <summary>
    /// Bắt đầu nhận file mới
    /// </summary>
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
    
    /// <summary>
    /// Nhận một chunk của file
    /// Trả về true nếu đã nhận đủ tất cả chunks
    /// </summary>
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
    
    /// <summary>
    /// Lưu file đã nhận hoàn tất vào thư mục chỉ định
    /// </summary>
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
    
    /// <summary>
    /// Tính SHA-256 hash của file
    /// </summary>
    private static async Task<string> ComputeFileHashAsync(string filePath)
    {
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkSize, true);
        var hash = await SHA256.HashDataAsync(stream);
        return Convert.ToBase64String(hash);
    }
    
    /// <summary>
    /// Sanitize tên file để tránh path traversal attacks
    /// </summary>
    private static string SanitizeFileName(string fileName)
    {
        var invalidChars = Path.GetInvalidFileNameChars();
        var sanitized = new string(fileName.Where(c => !invalidChars.Contains(c)).ToArray());
        
        // Loại bỏ các pattern nguy hiểm
        sanitized = sanitized.Replace("..", "");
        
        return string.IsNullOrWhiteSpace(sanitized) ? "unnamed_file" : sanitized;
    }
    
    /// <summary>
    /// Tạo đường dẫn file unique nếu file đã tồn tại
    /// </summary>
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
    
    /// <summary>
    /// Xác định MIME type dựa trên extension
    /// </summary>
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
    
    /// <summary>
    /// Lớp nội bộ để theo dõi file đang nhận
    /// </summary>
    private class IncomingFileTransfer
    {
        public required FileMetadata Metadata { get; init; }
        public required string SenderName { get; init; }
        public required byte[][] Chunks { get; init; }
        public int ReceivedChunks { get; set; }
        public DateTime StartTime { get; init; }
    }
}

/// <summary>
/// Event args cho progress update
/// </summary>
public class FileTransferProgressEventArgs : EventArgs
{
    /// <summary>ID của file đang transfer</summary>
    public string FileId { get; init; } = string.Empty;
    /// <summary>Tên file đang transfer</summary>
    public string FileName { get; init; } = string.Empty;
    /// <summary>Số chunk hiện tại</summary>
    public int CurrentChunk { get; init; }
    /// <summary>Tổng số chunks</summary>
    public int TotalChunks { get; init; }
    /// <summary>Số bytes đã transfer</summary>
    public long BytesTransferred { get; init; }
    /// <summary>Tổng số bytes</summary>
    public long TotalBytes { get; init; }
    /// <summary>True nếu đang upload, false nếu đang download</summary>
    public bool IsUpload { get; init; }
    
    /// <summary>Phần trăm tiến trình (0-100)</summary>
    public double ProgressPercent => TotalBytes > 0 ? (double)BytesTransferred / TotalBytes * 100 : 0;
}

/// <summary>
/// Event args khi transfer hoàn tất
/// </summary>
public class FileTransferCompleteEventArgs : EventArgs
{
    /// <summary>ID của file đã transfer xong</summary>
    public string FileId { get; init; } = string.Empty;
    /// <summary>Tên file</summary>
    public string FileName { get; init; } = string.Empty;
    /// <summary>Đường dẫn file đã lưu</summary>
    public string SavePath { get; init; } = string.Empty;
    /// <summary>Kích thước file (bytes)</summary>
    public long FileSize { get; init; }
}

/// <summary>
/// Event args khi có lỗi
/// </summary>
public class FileTransferErrorEventArgs : EventArgs
{
    /// <summary>ID của file bị lỗi</summary>
    public string FileId { get; init; } = string.Empty;
    /// <summary>Tên file bị lỗi</summary>
    public string FileName { get; init; } = string.Empty;
    /// <summary>Thông báo lỗi</summary>
    public string Error { get; init; } = string.Empty;
}

