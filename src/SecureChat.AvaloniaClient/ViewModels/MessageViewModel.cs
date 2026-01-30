using System;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using SecureChat.Core.Models;

namespace SecureChat.AvaloniaClient.ViewModels;


public partial class MessageViewModel : ViewModelBase
{
    private readonly Message _message;
    
    [ObservableProperty]
    private string _displayText;
    
    [ObservableProperty]
    private IBrush _messageColor;
    
    public string Id => _message.Id;
    public MessageType Type => _message.Type;
    
    public MessageViewModel(Message message, string currentUserId)
    {
        _message = message;
        _displayText = FormatMessage(message, currentUserId);
        _messageColor = GetMessageColor(message, currentUserId);
    }
    
    
    private static string FormatMessage(Message message, string currentUserId)
    {
        return message.Type switch
        {
            MessageType.Text => FormatTextMessage(message, currentUserId),
            MessageType.Join => $">>> {message.SenderName} đã tham gia chat",
            MessageType.Leave => $"<<< {message.SenderName} đã rời khỏi chat",
            MessageType.System => $"[Hệ thống]: {message.Content}",
            MessageType.Error => $"[Lỗi]: {message.Content}",
            MessageType.UserList => $"[Users online]: {message.Content}",
            MessageType.File => FormatFileMessage(message, currentUserId),
            MessageType.FileComplete => $"[Hệ thống]: {message.Content}",
            _ => message.Content
        };
    }
    
    private static string FormatTextMessage(Message message, string currentUserName)
    {
        // Tin nhắn trực tiếp
        if (!string.IsNullOrEmpty(message.RecipientId) || !string.IsNullOrEmpty(message.RecipientName))
        {
            if (string.Equals(message.SenderName, currentUserName, StringComparison.OrdinalIgnoreCase))
            {
                // Tin nhắn gửi đi
                return $"[Bạn → {message.RecipientName}]: {message.Content}";
            }
            else
            {
                // Tin nhắn nhận vào
                return $"[{message.SenderName} → Bạn]: {message.Content}";
            }
        }
        
        // Tin nhắn broadcast
        if (string.Equals(message.SenderName, currentUserName, StringComparison.OrdinalIgnoreCase))
        {
            return $"[Bạn]: {message.Content}";
        }
        else
        {
            return $"[{message.SenderName}]: {message.Content}";
        }
    }
    
    
    private static string FormatFileMessage(Message message, string currentUserName)
    {
        var fileName = message.FileMetadata?.FileName ?? "unknown";
        var fileSize = message.FileMetadata?.FileSize ?? 0;
        var sizeStr = FormatFileSize(fileSize);
        
        if (string.Equals(message.SenderName, currentUserName, StringComparison.OrdinalIgnoreCase))
        {
            return $"[Bạn → {message.RecipientName}]: [FILE] {fileName} ({sizeStr})";
        }
        else
        {
            return $"[{message.SenderName} → Bạn]: [FILE] {fileName} ({sizeStr})";
        }
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
    
    
    private static IBrush GetMessageColor(Message message, string currentUserId)
    {
        return message.Type switch
        {
            MessageType.Text when !string.IsNullOrEmpty(message.RecipientId) => Brushes.Magenta, // Direct message
            MessageType.Text when message.SenderId == currentUserId => Brushes.Cyan, // Sent broadcast
            MessageType.Text => Brushes.LimeGreen, // Received broadcast
            MessageType.Join or MessageType.Leave => Brushes.Yellow,
            MessageType.System => Brushes.DodgerBlue,
            MessageType.Error => Brushes.Red,
            MessageType.UserList => Brushes.Cyan,
            MessageType.File => Brushes.Orange, // File message
            MessageType.FileComplete => Brushes.LightGreen, // File complete
            _ => Brushes.White
        };
    }
}
