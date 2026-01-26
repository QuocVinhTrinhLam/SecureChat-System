using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureChat.AvaloniaClient.Models;
using SecureChat.AvaloniaClient.Services;
using SecureChat.Core.Models;

namespace SecureChat.AvaloniaClient.ViewModels;

/// <summary>
/// ViewModel chính cho MainWindow
/// </summary>
public partial class MainViewModel : ViewModelBase
{
    private readonly ChatService _chatService;
    private string _currentUserId = string.Empty;
    
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
        
        // Initialize Messages collection
        _messages = new ObservableCollection<MessageViewModel>();
        Console.WriteLine($"[MainViewModel] Constructor: Messages collection initialized. Count={_messages.Count}");
        
        // Subscribe to events
        _chatService.MessageReceived += OnMessageReceived;
        _chatService.ConnectionStateChanged += OnConnectionStateChanged;
        _chatService.ErrorOccurred += OnErrorOccurred;
        
        Console.WriteLine("[MainViewModel] Constructor: Event subscriptions completed");
    }
    
    /// <summary>
    /// Command kết nối đến server
    /// </summary>
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
    
    /// <summary>
    /// Command ngắt kết nối
    /// </summary>
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
    
    /// <summary>
    /// Command gửi tin nhắn
    /// </summary>
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
            
            // Gửi tin nhắn - server sẽ echo lại để hiển thị
            await _chatService.SendMessageAsync(content, recipientName);
            Console.WriteLine("[MainViewModel] SendMessageAsync completed");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MainViewModel] Exception in SendMessageAsync: {ex}");
            AddSystemMessage($"Lỗi gửi tin nhắn: {ex.Message}");
        }
    }
    
    private bool CanSendMessage() => IsConnected && !string.IsNullOrWhiteSpace(MessageInput);
    
    /// <summary>
    /// Xử lý tin nhắn nhận được
    /// </summary>
    private void OnMessageReceived(object? sender, Message message)
    {
        Console.WriteLine($"[MainViewModel] OnMessageReceived: Type={message.Type}, Sender={message.SenderName}");
        
        Dispatcher.UIThread.Post(() =>
        {
            Console.WriteLine($"[MainViewModel] Adding message to UI: Type={message.Type}");
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
    
    /// <summary>
    /// Xử lý thay đổi trạng thái kết nối
    /// </summary>
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
        });
    }
    
    /// <summary>
    /// Xử lý lỗi
    /// </summary>
    private void OnErrorOccurred(object? sender, string error)
    {
        Dispatcher.UIThread.Post(() =>
        {
            AddSystemMessage($"Lỗi: {error}");
        });
    }
    
    /// <summary>
    /// Thêm tin nhắn vào danh sách
    /// </summary>
    private void AddMessage(Message message)
    {
        Console.WriteLine($"[MainViewModel.AddMessage] Type={message.Type}, Sender={message.SenderName}, Content={message.Content}");
        Console.WriteLine($"[MainViewModel.AddMessage] Messages.Count before add: {Messages.Count}");
        Console.WriteLine($"[MainViewModel.AddMessage] Thread ID: {System.Threading.Thread.CurrentThread.ManagedThreadId}");
        
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
    
    /// <summary>
    /// Thêm tin nhắn hệ thống
    /// </summary>
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
