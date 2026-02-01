using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureChat.AvaloniaClient.Models;
using SecureChat.AvaloniaClient.Services;
using SecureChat.Core.Models;
using SecureChat.Core.Services;

namespace SecureChat.AvaloniaClient.ViewModels;


public partial class MainViewModel : ViewModelBase
{
    private readonly ChatService _chatService;
    private readonly FileTransferService _fileTransferService;
    private string _currentUserId = string.Empty;
    
    // Storage provider for file dialogs (set from View)
    public IStorageProvider? StorageProvider { get; set; }
    
    [ObservableProperty]
    private string _serverIp = "127.0.0.1";
    
    [ObservableProperty]
    private string _port = "9000";
    
    [ObservableProperty]
    private string _username = "";
    
    [ObservableProperty]
    private string _statusText = "Chưa kết nối";
    
    [ObservableProperty]
    private bool _isConnected = false;
    
    [ObservableProperty]
    private string _messageInput = "";
    
    // File transfer properties
    [ObservableProperty]
    private bool _isTransferring = false;
    
    [ObservableProperty]
    private double _transferProgress = 0;
    
    [ObservableProperty]
    private string _transferStatusText = "";
    
    private ObservableCollection<MessageViewModel> _messages;
    public ObservableCollection<MessageViewModel> Messages
    {
        get => _messages;
        set => SetProperty(ref _messages, value);
    }
    
    [ObservableProperty]
    private SecurityInfoViewModel _securityInfo = new();
    
    public MainViewModel() : this(new ChatService())
    {
    }
    
    public MainViewModel(ChatService chatService)
    {
        _chatService = chatService;
        _fileTransferService = new FileTransferService();
        
        // Initialize Messages collection
        _messages = new ObservableCollection<MessageViewModel>();
        Console.WriteLine($"[MainViewModel] Constructor: Messages collection initialized. Count={_messages.Count}");
        
        // Subscribe to chat events
        _chatService.MessageReceived += OnMessageReceived;
        _chatService.ConnectionStateChanged += OnConnectionStateChanged;
        _chatService.ErrorOccurred += OnErrorOccurred;
        
        // Subscribe to file transfer events
        _fileTransferService.ProgressChanged += OnFileTransferProgress;
        _fileTransferService.TransferCompleted += OnFileTransferCompleted;
        _fileTransferService.TransferFailed += OnFileTransferFailed;
        
        Console.WriteLine("[MainViewModel] Constructor: Event subscriptions completed");
    }
    
    
    [RelayCommand(CanExecute = nameof(CanConnect))]
    private async Task ConnectAsync()
    {
        if (string.IsNullOrWhiteSpace(Username))
        {
            AddSystemMessage("Vui lòng nhập username");
            return;
        }
        
        if (!int.TryParse(Port, out var portNumber))
        {
            AddSystemMessage("Port không hợp lệ");
            return;
        }
        
        try
        {
            _currentUserId = Guid.NewGuid().ToString();
            await _chatService.ConnectAsync(ServerIp, portNumber, Username);
            
            // Cập nhật security info
            SecurityInfo.UpdateOnConnected();
        }
        catch (Exception ex)
        {
            AddSystemMessage($"Lỗi kết nối: {ex.Message}");
        }
    }
    
    private bool CanConnect() => !IsConnected;
    
    
    [RelayCommand(CanExecute = nameof(CanDisconnect))]
    private async Task DisconnectAsync()
    {
        try
        {
            await _chatService.DisconnectAsync();
            SecurityInfo.Reset();
        }
        catch (Exception ex)
        {
            AddSystemMessage($"Lỗi ngắt kết nối: {ex.Message}");
        }
    }
    
    private bool CanDisconnect() => IsConnected;
    
    
    [RelayCommand(CanExecute = nameof(CanSendMessage))]
    private async Task SendMessageAsync()
    {
        Console.WriteLine($"[MainViewModel] SendMessageAsync called. MessageInput='{MessageInput}', IsConnected={IsConnected}");
        
        if (string.IsNullOrWhiteSpace(MessageInput))
        {
            Console.WriteLine("[MainViewModel] MessageInput is empty, returning");
            return;
        }
        
        try
        {
            var content = MessageInput;
            MessageInput = ""; // Clear input immediately
            
            Console.WriteLine($"[MainViewModel] Cleared input, sending: '{content}'");
            
            // Parse direct message: @username message
            string? recipientName = null;
            if (content.StartsWith("@"))
            {
                var spaceIndex = content.IndexOf(' ');
                if (spaceIndex > 1)
                {
                    recipientName = content[1..spaceIndex];
                    content = content[(spaceIndex + 1)..];
                }
            }
            

            
            Console.WriteLine($"[MainViewModel.SendMessageAsync] Sending: '{content}', Recipient: '{recipientName ?? "null"}'");
            
            // Gửi tin nhắn - server sẽ echo lại để hiển thị (với broadcast) hoặc không (với direct)
            var sentMessage = await _chatService.SendMessageAsync(content, recipientName);
            
            // Luôn thêm tin nhắn vào UI ngay lập tức
            // Duplicate check trong AddMessage sẽ xử lý trường hợp server echo lại broadcast
            AddMessage(sentMessage);
            
            // Cập nhật security info nếu là tin nhắn mã hóa
            if (!string.IsNullOrEmpty(recipientName) && sentMessage.SecurityMetadata != null)
            {
                SecurityInfo.UpdateFromEncryptedMessage(
                    sentMessage.Content,
                    sentMessage.Content, // Encrypted version (would need original)
                    sentMessage.SecurityMetadata.InitializationVector,
                    sentMessage.SecurityMetadata.Hmac
                );
            }
            
            Console.WriteLine("[MainViewModel] SendMessageAsync completed");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MainViewModel] Exception in SendMessageAsync: {ex}");
            AddSystemMessage($"Lỗi gửi tin nhắn: {ex.Message}");
        }
    }
    
    private bool CanSendMessage() => IsConnected && !string.IsNullOrWhiteSpace(MessageInput);
    
    
    [RelayCommand(CanExecute = nameof(CanAttachFile))]
    private async Task AttachFileAsync()
    {
        if (StorageProvider == null)
        {
            AddSystemMessage("Không thể mở file picker");
            return;
        }
        
        try
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Chọn file để gửi",
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("All Files") { Patterns = new[] { "*.*" } }
                }
            });
            
            if (files.Count == 0)
                return;
            
            var file = files[0];
            var filePath = file.Path.LocalPath;
            
            // Lấy recipient từ message input nếu có @username
            string? recipientName = null;
            if (MessageInput.StartsWith("@"))
            {
                var spaceIndex = MessageInput.IndexOf(' ');
                if (spaceIndex > 1)
                    recipientName = MessageInput[1..spaceIndex];
                else if (spaceIndex == -1)
                    recipientName = MessageInput[1..];
            }
            
            if (string.IsNullOrEmpty(recipientName))
            {
                AddSystemMessage("Vui lòng nhập @username để chọn người nhận file");
                return;
            }
            
            await SendFileAsync(filePath, recipientName);
        }
        catch (Exception ex)
        {
            AddSystemMessage($"Lỗi chọn file: {ex.Message}");
        }
    }
    
    private bool CanAttachFile() => IsConnected && !IsTransferring;
    
    
    private async Task SendFileAsync(string filePath, string recipientName)
    {
        try
        {
            Console.WriteLine($"[SendFileAsync] Starting file transfer: {filePath} to {recipientName}");
            IsTransferring = true;
            TransferStatusText = $"Đang chuẩn bị gửi {Path.GetFileName(filePath)}...";
            TransferProgress = 0;
            
            // Chuẩn bị metadata
            var metadata = await _fileTransferService.PrepareFileForSendingAsync(filePath);
            Console.WriteLine($"[SendFileAsync] Metadata prepared: FileId={metadata.FileId}, FileName={metadata.FileName}, TotalChunks={metadata.TotalChunks}");
            
            // Gửi file metadata message
            await _chatService.SendFileMetadataAsync(metadata, recipientName);
            Console.WriteLine($"[SendFileAsync] Metadata sent successfully");
            TransferStatusText = $"Đang gửi {metadata.FileName}...";
            
            // Gửi từng chunk
            int chunkCount = 0;
            await foreach (var chunk in _fileTransferService.ReadFileChunksAsync(filePath, metadata.FileId))
            {
                Console.WriteLine($"[SendFileAsync] Sending chunk {chunk.ChunkIndex + 1}/{chunk.TotalChunks}");
                await _chatService.SendFileChunkAsync(chunk, recipientName);
                Console.WriteLine($"[SendFileAsync] Chunk {chunk.ChunkIndex + 1} sent successfully");
                chunkCount++;
            }
            Console.WriteLine($"[SendFileAsync] All {chunkCount} chunks sent");
            
            // Gửi complete message
            await _chatService.SendFileCompleteAsync(metadata.FileId, metadata.FileName, recipientName);
            Console.WriteLine($"[SendFileAsync] Complete message sent");
            
            AddSystemMessage($"Đã gửi file {metadata.FileName} đến {recipientName}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SendFileAsync] ERROR: {ex}");
            AddSystemMessage($"Lỗi gửi file: {ex.Message}");
        }
        finally
        {
            IsTransferring = false;
            TransferProgress = 0;
            TransferStatusText = "";
        }
    }
    
    
    private void OnMessageReceived(object? sender, Message message)
    {
        Console.WriteLine($"[MainViewModel] OnMessageReceived: Type={message.Type}, Sender={message.SenderName}");
        
        Dispatcher.UIThread.Post(() =>
        {
            Console.WriteLine($"[MainViewModel] Adding message to UI: Type={message.Type}");
            
            // Xử lý file transfer messages - chỉ người nhận mới cần xử lý
            // Người gửi đã có file, không cần lưu lại
            var isRecipient = !string.Equals(message.SenderName, _chatService.UserName, StringComparison.OrdinalIgnoreCase);
            
            if (message.Type == MessageType.File && message.FileMetadata != null && isRecipient)
            {
                Console.WriteLine($"[MainViewModel] Received FILE metadata: {message.FileMetadata.FileName}, TotalChunks={message.FileMetadata.TotalChunks}");
                _fileTransferService.StartReceiving(message.FileMetadata, message.SenderName);
                IsTransferring = true;
                TransferStatusText = $"Đang nhận {message.FileMetadata.FileName}...";
            }
            else if (message.Type == MessageType.FileChunk && message.FileChunkData != null && isRecipient)
            {
                Console.WriteLine($"[MainViewModel] Received CHUNK: FileId={message.FileChunkData.FileId}, Index={message.FileChunkData.ChunkIndex}/{message.FileChunkData.TotalChunks}");
                var isComplete = _fileTransferService.ReceiveChunk(message.FileChunkData);
                Console.WriteLine($"[MainViewModel] Chunk processed, isComplete={isComplete}");
                if (isComplete)
                {
                    Console.WriteLine($"[MainViewModel] All chunks received, saving file...");
                    // Auto-save to Downloads folder
                    var downloadsPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                        "Downloads"
                    );
                    _ = SaveReceivedFileAsync(message.FileChunkData.FileId, downloadsPath);
                }
                return; // Don't show chunk messages in chat
            }
            else if (message.Type == MessageType.FileChunk)
            {
                Console.WriteLine($"[MainViewModel] Ignoring FileChunk for sender");
                return; // Don't show chunk messages for sender either
            }
            else if (message.Type == MessageType.FileComplete && isRecipient)
            {
                Console.WriteLine($"[MainViewModel] Received FILE COMPLETE");
                IsTransferring = false;
                TransferProgress = 0;
                TransferStatusText = "";
            }
            
            AddMessage(message);
            
            // Cập nhật security info nếu là tin nhắn mã hóa
            if (message.SecurityMetadata != null)
            {
                SecurityInfo.UpdateFromEncryptedMessage(
                    message.Content,
                    message.Content, // Encrypted version (would need original)
                    message.SecurityMetadata.InitializationVector,
                    message.SecurityMetadata.Hmac
                );
            }
        });
    }
    
    private async Task SaveReceivedFileAsync(string fileId, string saveDirectory)
    {
        try
        {
            var savePath = await _fileTransferService.SaveReceivedFileAsync(fileId, saveDirectory);
            Dispatcher.UIThread.Post(() =>
            {
                AddSystemMessage($"File đã lưu tại: {savePath}");
            });
        }
        catch (Exception ex)
        {
            Dispatcher.UIThread.Post(() =>
            {
                AddSystemMessage($"Lỗi lưu file: {ex.Message}");
            });
        }
    }
    
    private void OnFileTransferProgress(object? sender, FileTransferProgressEventArgs e)
    {
        Dispatcher.UIThread.Post(() =>
        {
            TransferProgress = e.ProgressPercent;
            var action = e.IsUpload ? "Đang gửi" : "Đang nhận";
            TransferStatusText = $"{action} {e.FileName}: {e.CurrentChunk}/{e.TotalChunks}";
        });
    }
    
    private void OnFileTransferCompleted(object? sender, FileTransferCompleteEventArgs e)
    {
        Dispatcher.UIThread.Post(() =>
        {
            IsTransferring = false;
            TransferProgress = 0;
            TransferStatusText = "";
        });
    }
    
    private void OnFileTransferFailed(object? sender, FileTransferErrorEventArgs e)
    {
        Dispatcher.UIThread.Post(() =>
        {
            IsTransferring = false;
            TransferProgress = 0;
            TransferStatusText = "";
            AddSystemMessage($"File transfer thất bại: {e.Error}");
        });
    }
    
    
    private void OnConnectionStateChanged(object? sender, ConnectionState state)
    {
        Dispatcher.UIThread.Post(() =>
        {
            IsConnected = state == ConnectionState.Connected;
            StatusText = state switch
            {
                ConnectionState.Disconnected => "Chưa kết nối",
                ConnectionState.Connecting => "Đang kết nối...",
                ConnectionState.Connected => "Đã kết nối",
                ConnectionState.Disconnecting => "Đang ngắt kết nối...",
                ConnectionState.Error => "Lỗi kết nối",
                _ => "Không xác định"
            };
            
            // Update command can execute
            ConnectCommand.NotifyCanExecuteChanged();
            DisconnectCommand.NotifyCanExecuteChanged();
            SendMessageCommand.NotifyCanExecuteChanged();
            AttachFileCommand.NotifyCanExecuteChanged();
        });
    }
    
    
    private void OnErrorOccurred(object? sender, string error)
    {
        Dispatcher.UIThread.Post(() =>
        {
            AddSystemMessage($"Lỗi: {error}");
        });
    }
    
    
    private void AddMessage(Message message)
    {
        Console.WriteLine($"[MainViewModel.AddMessage] Type={message.Type}, Sender={message.SenderName}, Content={message.Content}");
        Console.WriteLine($"[MainViewModel.AddMessage] Messages.Count before add: {Messages.Count}");
        Console.WriteLine($"[MainViewModel.AddMessage] Thread ID: {System.Threading.Thread.CurrentThread.ManagedThreadId}");
        
        // Prevent duplicates (e.g. from server echo vs local add)
        foreach (var msg in Messages)
        {
            if (msg.Id == message.Id)
            {
                Console.WriteLine($"[MainViewModel.AddMessage] Ignoring duplicate message Id={message.Id}");
                return;
            }
        }

        var messageVm = new MessageViewModel(message, Username);
        Console.WriteLine($"[MainViewModel.AddMessage] Created MessageViewModel: DisplayText='{messageVm.DisplayText}'");
        
        Messages.Add(messageVm);
        Console.WriteLine($"[MainViewModel.AddMessage] Messages.Count after add: {Messages.Count}");
        
        // Giới hạn số tin nhắn hiển thị
        while (Messages.Count > 200)
        {
            Messages.RemoveAt(0);
        }
    }
    
    
    private void AddSystemMessage(string content)
    {
        var message = Message.CreateSystemMessage(content);
        AddMessage(message);
    }
    
    partial void OnMessageInputChanged(string value)
    {
        SendMessageCommand.NotifyCanExecuteChanged();
    }
}
