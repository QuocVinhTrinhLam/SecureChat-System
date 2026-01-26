using System;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using SecureChat.Core.Models;

namespace SecureChat.AvaloniaClient.ViewModels;

/// <summary>
/// ViewModel cho một tin nhắn trong chat
/// </summary>
public partial class MessageViewModel : ViewModelBase
{
    private readonly Message _message;
    
    [ObservableProperty]
    private string _displayText;
    
    [ObservableProperty]
    private IBrush _messageColor;
    
    public MessageType Type => _message.Type;
    
    public MessageViewModel(Message message, string currentUserId)
    {
        _message = message;
        _displayText = FormatMessage(message, currentUserId);
        _messageColor = GetMessageColor(message, currentUserId);
    }
    
    /// <summary>
    /// Format tin nhắn để hiển thị
    /// </summary>
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
    
    /// <summary>
    /// Lấy màu cho tin nhắn
    /// </summary>
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
            _ => Brushes.White
        };
    }
}
